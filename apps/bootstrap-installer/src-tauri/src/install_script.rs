//! Resolves and downloads `scripts/install.ps1` (and `install.sh`).
//!
//! Resolution order:
//!   1. Dev shortcut: a sibling repo checkout via $HERMES_SETUP_DEV_REPO_ROOT
//!      env var. Lets devs iterate without re-publishing the script.
//!   2. Bundled fallback: if the installer was bundled with a script (e.g.
//!      tauri's `resource` mechanism), serve from there. Not used today.
//!   3. Network: download from GitHub raw at a pinned commit or branch.
//!      Commit pins are immutable; branch pins are HEAD-tracking.
//!
//! Mirrors `apps/desktop/electron/bootstrap-runner.ts`'s `resolveInstallScript`,
//! but the dev-checkout resolution is driven by an env var rather than the
//! Electron app's APP_ROOT/../.. trick, because Hermes-Setup.exe is meant
//! to live OUTSIDE any repo checkout.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

use crate::paths;

/// Identity of the install.ps1 we'll execute. Used by both the manifest
/// fetch and the per-stage runs.
#[derive(Debug, Clone)]
pub struct ResolvedScript {
    pub path: PathBuf,
    pub source: ScriptSource,
    /// Commit pin (40-char SHA) if known. install.ps1's `-Commit` arg is
    /// what makes the repo stage clone the exact tested SHA.
    pub commit: Option<String>,
    pub branch: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptSource {
    DevCheckout,
    Bundled,
    Cached,
    Downloaded,
}

/// What flavor of script (Windows .ps1 vs Unix .sh).
#[derive(Debug, Clone, Copy)]
pub enum ScriptKind {
    Ps1,
    Sh,
}

impl ScriptKind {
    pub fn for_current_os() -> Self {
        if cfg!(target_os = "windows") {
            Self::Ps1
        } else {
            Self::Sh
        }
    }

    fn filename(&self) -> &'static str {
        match self {
            Self::Ps1 => "install.ps1",
            Self::Sh => "install.sh",
        }
    }
}

/// Validates a string looks like a git SHA (7+ hex chars). Mirrors
/// `STAMP_COMMIT_RE` from bootstrap-runner.ts.
fn is_valid_commit(s: &str) -> bool {
    let len = s.len();
    (7..=40).contains(&len) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// A full, exact 40-char commit SHA — the only identity an ATTESTED
/// (production) installer will accept (A10).
fn is_full_commit(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// A10: a production (RELEASE-profile) installer requires an exact full-commit
/// installer identity UNCONDITIONALLY — there is NO optional environment gate.
/// `attested_required` is the pure policy: attestation is required whenever the
/// binary is a release build, OR (in a debug build) when the operator explicitly
/// opts in. Only an explicit debug build may run in dev/branch mode.
pub(crate) fn attested_required(is_release: bool, env_opt_in: bool) -> bool {
    is_release || env_opt_in
}

/// A10: whether this installer must resolve an exact full-commit identity (no
/// branch raw-script, no dev shortcut, no stale cached-script fallback). Release
/// builds are ALWAYS attested; a debug build may opt in via
/// `HERMES_SETUP_REQUIRE_ATTESTED=1`.
pub fn require_attested() -> bool {
    // `cfg!(debug_assertions)` is false in a release build (`tauri build`) and
    // true in a debug build (`tauri dev` / `tauri build --debug` / `cargo test`).
    attested_required(
        !cfg!(debug_assertions),
        matches!(option_env!("HERMES_SETUP_REQUIRE_ATTESTED"), Some("1")),
    )
}

/// Resolve the (ref, immutable) pair to fetch, enforcing the attested policy.
///
/// Attested mode: the pin MUST be a full 40-char commit SHA. A branch ref, a
/// short SHA, or no pin at all is rejected — there is no branch raw-script
/// fallback, and because the result is always immutable there is no stale
/// cached fallback either. Non-attested mode keeps the dev/CI behavior (a full
/// or short SHA is immutable; a branch is a mutable HEAD-tracking ref).
pub(crate) fn resolve_pin_source(pin: &Pin, require_attested: bool) -> Result<(String, bool)> {
    if require_attested {
        return match &pin.commit {
            Some(c) if is_full_commit(c) => Ok((c.clone(), true)),
            Some(other) => Err(anyhow!(
                "attested installer requires a full 40-char commit SHA; `{other}` is not one — \
                 refusing a branch/short-ref installer identity"
            )),
            None => Err(anyhow!(
                "attested installer requires a pinned commit; no branch raw-script fallback is permitted"
            )),
        };
    }

    match (&pin.commit, &pin.branch) {
        (Some(c), _) if is_valid_commit(c) => Ok((c.clone(), true)),
        (_, Some(b)) if !b.trim().is_empty() => Ok((b.clone(), false)),
        (Some(other), _) => Err(anyhow!(
            "install script pin commit `{other}` is not a valid git SHA"
        )),
        _ => Err(anyhow!(
            "no install-script pin supplied — installer cannot resolve a script source"
        )),
    }
}

/// Resolver cache plan for a pin that already has a local path computed.
///
/// Immutable commit pins reuse cache forever. Mutable branch/tag pins always
/// refresh, and only fall back to a stale cache when the refresh fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CachePlan {
    /// On-disk hit for an immutable pin — skip the network.
    Reuse,
    /// Download (or re-download). `stale_ok` means a failed refresh may return
    /// the existing cache file (mutable pins with a prior download).
    Fetch { stale_ok: bool },
}

pub(crate) fn cache_plan(immutable: bool, cached_exists: bool) -> CachePlan {
    if immutable && cached_exists {
        CachePlan::Reuse
    } else {
        CachePlan::Fetch {
            stale_ok: !immutable && cached_exists,
        }
    }
}

/// Resolves the install script to use for this run.
///
/// `pin` is the commit-or-branch from either Hermes-Setup's build-time
/// constant (compiled into the installer) or a runtime override.
pub async fn resolve(
    kind: ScriptKind,
    pin: &Pin,
    require_attested: bool,
    emit_log: &impl Fn(&str),
) -> Result<ResolvedScript> {
    // 1. Dev shortcut — DISABLED for attested/production installers so a stray
    //    HERMES_SETUP_DEV_REPO_ROOT can never substitute an unattested script.
    if !require_attested {
        if let Ok(repo_root) = std::env::var("HERMES_SETUP_DEV_REPO_ROOT") {
            let candidate = PathBuf::from(repo_root).join("scripts").join(kind.filename());
            if candidate.exists() {
                emit_log(&format!(
                    "[bootstrap] dev mode — using local {} at {}",
                    kind.filename(),
                    candidate.display()
                ));
                return Ok(ResolvedScript {
                    path: candidate,
                    source: ScriptSource::DevCheckout,
                    commit: pin.commit.clone(),
                    branch: pin.branch.clone(),
                });
            }
        }
    }

    // 2. (Not implemented) bundled fallback.

    // 3. Network. Attested installers require an exact full-commit identity and
    //    have no branch/stale fallback; dev/CI keep the immutable-commit /
    //    mutable-branch behavior. See resolve_pin_source.
    let (commit_or_ref, immutable) = resolve_pin_source(pin, require_attested)?;

    let cached = cached_path(kind, &commit_or_ref);
    match cache_plan(immutable, cached.exists()) {
        CachePlan::Reuse => {
            emit_log(&format!(
                "[bootstrap] using cached {} for {}",
                kind.filename(),
                truncate_ref(&commit_or_ref)
            ));
            // Immutable pins are cached forever, so a .ps1 cached by a
            // pre-BOM-fix installer would keep the #67193 encoding bug on
            // every retry. Upgrade it in place before handing it out.
            upgrade_cached_script(kind, &cached, emit_log);
            // A10: a cached script is NOT trusted on its path alone — verify its
            // bytes against the baked pinned-commit digest before reuse. An
            // attested installer fails closed if the cache is tampered or the
            // build shipped no digest.
            verify_cached_script(kind, &cached, require_attested)?;
            return Ok(ResolvedScript {
                path: cached,
                source: ScriptSource::Cached,
                commit: pin.commit.clone(),
                branch: pin.branch.clone(),
            });
        }
        CachePlan::Fetch { stale_ok } => {
            emit_log(&format!(
                "[bootstrap] downloading {} for {} {} from GitHub",
                kind.filename(),
                if immutable {
                    "commit"
                } else {
                    "mutable ref"
                },
                truncate_ref(&commit_or_ref)
            ));

            match download(kind, &commit_or_ref, &cached, require_attested).await {
                Ok(()) => {
                    emit_log(&format!("[bootstrap] cached to {}", cached.display()));
                    Ok(ResolvedScript {
                        path: cached,
                        source: ScriptSource::Downloaded,
                        commit: pin.commit.clone(),
                        branch: pin.branch.clone(),
                    })
                }
                Err(err) if stale_ok => {
                    emit_log(&format!(
                        "[bootstrap] WARNING: refresh failed for mutable ref {}; using stale cached {} at {}: {err:#}",
                        truncate_ref(&commit_or_ref),
                        kind.filename(),
                        cached.display()
                    ));
                    // Stale cache can predate the BOM fix too — upgrade it.
                    upgrade_cached_script(kind, &cached, emit_log);
                    // Still verify the stale cache against any baked digest. In
                    // non-attested mutable-ref mode there is no baked digest, so
                    // this is a no-op; an attested installer never reaches the
                    // stale path (its pins are immutable, stale_ok=false).
                    verify_cached_script(kind, &cached, require_attested)?;
                    Ok(ResolvedScript {
                        path: cached,
                        source: ScriptSource::Cached,
                        commit: pin.commit.clone(),
                        branch: pin.branch.clone(),
                    })
                }
                Err(err) => Err(err),
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Pin {
    pub commit: Option<String>,
    pub branch: Option<String>,
}

fn cached_path(kind: ScriptKind, commit_or_ref: &str) -> PathBuf {
    let safe = sanitize_ref(commit_or_ref);
    let filename = match kind {
        ScriptKind::Ps1 => format!("install-{safe}.ps1"),
        ScriptKind::Sh => format!("install-{safe}.sh"),
    };
    paths::bootstrap_cache_dir().join(filename)
}

/// Replace anything that's not [A-Za-z0-9._-] with `_`. Branch refs can
/// contain `/`, dots, etc.; we want a flat filename.
fn sanitize_ref(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn truncate_ref(s: &str) -> &str {
    if is_valid_commit(s) && s.len() >= 12 {
        &s[..12]
    } else {
        s
    }
}

/// UTF-8 BOM. Windows PowerShell 5.1 reads a BOM-less `.ps1` using the system
/// ANSI code page; a leading BOM is what tells it the file is UTF-8. The
/// `irm | iex` / `[scriptblock]::Create` path strips BOMs on purpose, but the
/// GUI bootstrap runs the *cached file* via `-File`, so we write the opposite
/// (#67193).
const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// A10 — the SHA-256 baked at build time for this script AT THE PINNED COMMIT
/// (build.rs `git cat-file blob <commit>:scripts/<file>`). `None` on a build
/// with no immutable commit pin (branch-follow dev build).
fn attested_script_sha256(kind: ScriptKind) -> Option<String> {
    let raw = match kind {
        ScriptKind::Ps1 => option_env!("BUILD_INSTALL_PS1_SHA256"),
        ScriptKind::Sh => option_env!("BUILD_INSTALL_SH_SHA256"),
    }?;
    normalize_digest(raw)
}

fn normalize_digest(raw: &str) -> Option<String> {
    let s = raw.trim().to_ascii_lowercase();
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(s)
    } else {
        None
    }
}

/// The canonical script body the attested digest is computed over: the raw git
/// blob bytes. A cached `.ps1` carries the UTF-8 BOM our writer prepends, so
/// strip it before hashing to compare against the (BOM-less) attested digest.
fn canonical_script_body(kind: ScriptKind, bytes: &[u8]) -> &[u8] {
    match kind {
        ScriptKind::Ps1 if bytes.starts_with(UTF8_BOM) => &bytes[UTF8_BOM.len()..],
        _ => bytes,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Pure attestation check (unit-testable without a baked env). Verifies
/// `bytes` (a network body or a cached file) against `expected`:
///   * `Some(digest)` — the body's SHA-256 MUST equal it, else fail closed.
///   * `None` + attested build — fail closed (an attested installer must have a
///     baked digest to verify against).
///   * `None` + non-attested build — allowed (dev/branch-follow has no pin).
pub(crate) fn verify_body_against(
    expected: Option<&str>,
    kind: ScriptKind,
    bytes: &[u8],
    require_attested: bool,
) -> Result<()> {
    match expected {
        Some(exp) => {
            let got = sha256_hex(canonical_script_body(kind, bytes));
            if got != exp.trim().to_ascii_lowercase() {
                return Err(anyhow!(
                    "install {} failed attestation: sha256 {} != expected {} — refusing a \
                     tampered or mirror-substituted script at the pinned commit",
                    kind.filename(),
                    got,
                    exp
                ));
            }
            Ok(())
        }
        None if require_attested => Err(anyhow!(
            "attested installer has no baked digest for {} — the build must embed \
             BUILD_INSTALL_*_SHA256 at the pinned commit before an attested installer \
             may execute a downloaded script",
            kind.filename()
        )),
        None => Ok(()),
    }
}

/// Verify script `bytes` against the build-baked digest for `kind`. Applied to
/// both freshly-downloaded bytes and reused cache bytes so a poisoned cache is
/// rejected just like a poisoned download (A10 — "stale cache is insufficient").
pub(crate) fn verify_script_bytes(
    kind: ScriptKind,
    bytes: &[u8],
    require_attested: bool,
) -> Result<()> {
    let baked = attested_script_sha256(kind);
    verify_body_against(baked.as_deref(), kind, bytes, require_attested)
}

/// Read a cached script file and verify it against the baked digest. Used on
/// the cache-reuse paths so an attested installer never executes an unverified
/// on-disk script.
fn verify_cached_script(kind: ScriptKind, cached: &Path, require_attested: bool) -> Result<()> {
    let bytes = std::fs::read(cached)
        .with_context(|| format!("reading cached script {} for attestation", cached.display()))?;
    verify_script_bytes(kind, &bytes, require_attested)
}

/// Prepare bytes for the on-disk bootstrap cache.
///
/// `.ps1` files get a UTF-8 BOM (unless one is already present). `.sh` files
/// are left unchanged — a BOM would break `#!/bin/bash`.
pub(crate) fn prepare_cached_script_bytes(kind: ScriptKind, bytes: &[u8]) -> Vec<u8> {
    match kind {
        ScriptKind::Ps1 => {
            if bytes.starts_with(UTF8_BOM) {
                bytes.to_vec()
            } else {
                let mut out = Vec::with_capacity(UTF8_BOM.len() + bytes.len());
                out.extend_from_slice(UTF8_BOM);
                out.extend_from_slice(bytes);
                out
            }
        }
        ScriptKind::Sh => bytes.to_vec(),
    }
}

/// Upgrade a cached script written by a pre-BOM-fix installer in place.
///
/// `prepare_cached_script_bytes` only runs inside `download()`, but immutable
/// commit pins (and the stale-fallback path) reuse the on-disk file without
/// re-downloading — so a BOM-less `.ps1` cached before the #67193 fix would
/// keep reproducing the ANSI-codepage parse failure on every retry. Rewrites
/// through the same atomic tmp+rename shape as `download()`. Best-effort: a
/// failed upgrade logs a warning and keeps the original file (which is no
/// worse than the pre-existing behavior).
fn upgrade_cached_script(kind: ScriptKind, cached: &Path, emit_log: &impl Fn(&str)) {
    if !matches!(kind, ScriptKind::Ps1) {
        return;
    }
    let bytes = match std::fs::read(cached) {
        Ok(b) => b,
        Err(err) => {
            emit_log(&format!(
                "[bootstrap] WARNING: could not read cached script {} for BOM check: {err}",
                cached.display()
            ));
            return;
        }
    };
    if bytes.starts_with(UTF8_BOM) {
        return;
    }
    let upgraded = prepare_cached_script_bytes(kind, &bytes);
    let tmp = cached.with_extension("ps1.tmp");
    let result = std::fs::write(&tmp, &upgraded).and_then(|()| std::fs::rename(&tmp, cached));
    match result {
        Ok(()) => emit_log(&format!(
            "[bootstrap] upgraded cached {} with UTF-8 BOM (#67193)",
            cached.display()
        )),
        Err(err) => {
            let _ = std::fs::remove_file(&tmp);
            emit_log(&format!(
                "[bootstrap] WARNING: could not upgrade cached {} with UTF-8 BOM: {err}",
                cached.display()
            ));
        }
    }
}

/// Downloads to `dest_path` via reqwest with rustls. Atomically renames
/// `dest_path.tmp` → `dest_path` so partial writes don't poison the cache.
///
/// The client carries explicit timeouts: mutable branch pins call this on
/// EVERY run (#67193 cache-refresh fix), and the stale-cache fallback in
/// `resolve()` only fires when this returns `Err`. Without a timeout, a
/// black-holed connection (captive portal, hung proxy, silently dropped
/// packets) never errors — the whole bootstrap would hang here instead of
/// falling back to the cached script.
async fn download(
    kind: ScriptKind,
    commit_or_ref: &str,
    dest_path: &Path,
    require_attested: bool,
) -> Result<()> {
    let url = format!(
        "https://raw.githubusercontent.com/NousResearch/hermes-agent/{}/scripts/{}",
        commit_or_ref,
        kind.filename()
    );

    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("creating bootstrap-cache parent dir {}", parent.display())
        })?;
    }

    let tmp_path = dest_path.with_extension({
        let ext = dest_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("tmp");
        format!("{ext}.tmp")
    });

    let response = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("building download client")?
        .get(&url)
        .header("User-Agent", "hermes-setup/0.0.1")
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Failed to download {}: HTTP {} from {}",
            kind.filename(),
            response.status(),
            url
        ));
    }

    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("reading body of {url}"))?;
    // A10: byte-verify the freshly downloaded script against the baked
    // pinned-commit digest BEFORE it is written to the cache or executed. A
    // pinned-commit URL is not sufficient — a compromised mirror/CDN or a
    // tampered response must be rejected here.
    verify_script_bytes(kind, &bytes, require_attested)
        .with_context(|| format!("verifying downloaded {} from {url}", kind.filename()))?;
    let bytes = prepare_cached_script_bytes(kind, &bytes);

    let mut file = tokio::fs::File::create(&tmp_path)
        .await
        .with_context(|| format!("creating temp file {}", tmp_path.display()))?;
    file.write_all(&bytes)
        .await
        .with_context(|| format!("writing temp file {}", tmp_path.display()))?;
    file.flush().await.context("flushing temp file")?;
    drop(file);

    tokio::fs::rename(&tmp_path, dest_path)
        .await
        .with_context(|| {
            format!(
                "renaming {} → {}",
                tmp_path.display(),
                dest_path.display()
            )
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_commit_accepts_short_and_full_shas() {
        assert!(is_valid_commit("02d26981d3d4ad50e142399b8476f59ad5953ff0"));
        assert!(is_valid_commit("02d2698"));
        assert!(!is_valid_commit("02d269"));
        assert!(!is_valid_commit("not-a-sha"));
        assert!(!is_valid_commit(""));
    }

    // ── A10: attested (production) installer identity ──────────────────────
    #[test]
    fn is_full_commit_requires_exactly_40_hex() {
        assert!(is_full_commit("02d26981d3d4ad50e142399b8476f59ad5953ff0"));
        assert!(!is_full_commit("02d2698")); // short
        assert!(!is_full_commit("02d26981d3d4ad50e142399b8476f59ad5953ff")); // 39
        assert!(!is_full_commit("02d26981d3d4ad50e142399b8476f59ad5953ff0a")); // 41
        assert!(!is_full_commit("main"));
    }

    // ── A10: install-script BYTE attestation ───────────────────────────────
    fn digest_of(bytes: &[u8]) -> String {
        sha256_hex(bytes)
    }

    #[test]
    fn attested_required_is_unconditional_in_release() {
        // Release profile → attestation required, no env gate.
        assert!(attested_required(true, false));
        assert!(attested_required(true, true));
        // Debug profile → dev/branch mode allowed unless the operator opts in.
        assert!(!attested_required(false, false));
        assert!(attested_required(false, true));
    }

    #[test]
    fn verify_accepts_bytes_matching_the_baked_digest() {
        let body = b"# install.sh\necho hello\n";
        let expected = digest_of(body);
        assert!(verify_body_against(Some(&expected), ScriptKind::Sh, body, true).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_or_mirror_substituted_bytes() {
        let expected = digest_of(b"# the real script\n");
        let tampered = b"# EVIL substituted script\n";
        let err = verify_body_against(Some(&expected), ScriptKind::Sh, tampered, true).unwrap_err();
        assert!(err.to_string().contains("failed attestation"), "{err}");
    }

    #[test]
    fn verify_ps1_matches_after_cache_bom_is_stripped() {
        // The baked digest is over the BOM-less git blob; a cached .ps1 carries
        // the UTF-8 BOM our writer prepends. Verification must still pass.
        let raw = b"Write-Host 'hi'\r\n";
        let expected = digest_of(raw);
        let cached = prepare_cached_script_bytes(ScriptKind::Ps1, raw);
        assert!(cached.starts_with(UTF8_BOM));
        assert!(verify_body_against(Some(&expected), ScriptKind::Ps1, &cached, true).is_ok());
    }

    #[test]
    fn verify_fails_closed_when_attested_but_no_baked_digest() {
        let err = verify_body_against(None, ScriptKind::Ps1, b"anything", true).unwrap_err();
        assert!(err.to_string().contains("no baked digest"), "{err}");
    }

    #[test]
    fn verify_is_a_noop_when_not_attested_and_no_digest() {
        // Dev / mutable branch-follow build ships no digest and does not enforce.
        assert!(verify_body_against(None, ScriptKind::Sh, b"whatever", false).is_ok());
    }

    #[test]
    fn verify_still_enforces_a_present_digest_even_when_not_attested() {
        // If a digest IS baked (immutable commit pin) it is enforced regardless
        // of the attested flag — an immutable pin's content is fixed.
        let expected = digest_of(b"real\n");
        assert!(verify_body_against(Some(&expected), ScriptKind::Sh, b"real\n", false).is_ok());
        assert!(verify_body_against(Some(&expected), ScriptKind::Sh, b"fake\n", false).is_err());
    }

    #[test]
    fn normalize_digest_validates_shape() {
        assert_eq!(normalize_digest(&"A".repeat(64)), Some("a".repeat(64)));
        assert_eq!(normalize_digest("  " ), None);
        assert_eq!(normalize_digest(&"a".repeat(63)), None); // too short
        assert_eq!(normalize_digest("xyz"), None); // non-hex
    }

    #[test]
    fn verify_cached_script_reads_and_checks_bytes() {
        let dir = std::env::temp_dir().join(format!("hermes-attest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("install.sh");
        std::fs::write(&path, b"echo real\n").unwrap();
        let good = digest_of(b"echo real\n");

        // Matching baked digest → the cached file passes.
        assert!(verify_body_against(Some(&good), ScriptKind::Sh, &std::fs::read(&path).unwrap(), true).is_ok());
        // A mutated cache is rejected.
        std::fs::write(&path, b"echo EVIL\n").unwrap();
        assert!(verify_body_against(Some(&good), ScriptKind::Sh, &std::fs::read(&path).unwrap(), true).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attested_requires_an_exact_full_commit_no_branch_or_short() {
        let full = "0".repeat(40);
        // A full commit is accepted and is immutable.
        let (r, immutable) = resolve_pin_source(
            &Pin { commit: Some(full.clone()), branch: Some("main".into()) },
            true,
        )
        .unwrap();
        assert_eq!(r, full);
        assert!(immutable);

        // A branch-only pin is rejected — no branch raw-script fallback.
        assert!(resolve_pin_source(&Pin { commit: None, branch: Some("main".into()) }, true).is_err());
        // A short SHA is rejected.
        assert!(resolve_pin_source(&Pin { commit: Some("02d2698".into()), branch: None }, true).is_err());
        // No pin at all is rejected.
        assert!(resolve_pin_source(&Pin::default(), true).is_err());
    }

    #[test]
    fn non_attested_keeps_branch_and_short_sha_behavior() {
        let (r, imm) =
            resolve_pin_source(&Pin { commit: None, branch: Some("main".into()) }, false).unwrap();
        assert_eq!(r, "main");
        assert!(!imm);

        let (r2, imm2) =
            resolve_pin_source(&Pin { commit: Some("02d2698".into()), branch: None }, false).unwrap();
        assert_eq!(r2, "02d2698");
        assert!(imm2);
    }

    #[test]
    fn attested_pin_is_immutable_so_there_is_no_stale_cache_fallback() {
        // An attested pin is always immutable, so cache_plan never yields a
        // stale-OK fetch — a failed download errors instead of serving stale.
        assert_eq!(cache_plan(/*immutable=*/ true, /*cached_exists=*/ true), CachePlan::Reuse);
        assert_eq!(
            cache_plan(/*immutable=*/ true, /*cached_exists=*/ false),
            CachePlan::Fetch { stale_ok: false }
        );
    }

    #[test]
    fn sanitize_ref_replaces_slashes() {
        assert_eq!(sanitize_ref("bb/gui"), "bb_gui");
        assert_eq!(sanitize_ref("main"), "main");
        assert_eq!(sanitize_ref("release/1.2.3"), "release_1.2.3");
    }

    #[test]
    fn prepare_cached_ps1_prefixes_utf8_bom() {
        let out = prepare_cached_script_bytes(ScriptKind::Ps1, b"Write-Host hi\n");
        assert!(out.starts_with(UTF8_BOM), "cached .ps1 must start with UTF-8 BOM");
        assert_eq!(&out[UTF8_BOM.len()..], b"Write-Host hi\n");
    }

    #[test]
    fn prepare_cached_ps1_does_not_double_bom() {
        let mut already = UTF8_BOM.to_vec();
        already.extend_from_slice(b"x");
        let out = prepare_cached_script_bytes(ScriptKind::Ps1, &already);
        assert_eq!(out, already);
        assert_eq!(out.windows(3).filter(|w| *w == UTF8_BOM).count(), 1);
    }

    #[test]
    fn prepare_cached_sh_stays_bomless() {
        let out = prepare_cached_script_bytes(ScriptKind::Sh, b"#!/bin/bash\n");
        assert!(!out.starts_with(UTF8_BOM));
        assert_eq!(out, b"#!/bin/bash\n");
    }

    #[test]
    fn commit_pins_are_immutable_branch_pins_are_not() {
        // Mirrors the resolve() immutable decision: SHA pins may reuse cache
        // forever; branch pins must refresh so Retry cannot keep a bad script.
        assert!(is_valid_commit("02d26981d3d4ad50e142399b8476f59ad5953ff0"));
        assert!(!is_valid_commit("main"));
        assert!(!is_valid_commit("release/1.2.3"));
    }

    #[test]
    fn existing_branch_cache_plans_refresh_with_stale_fallback() {
        // Resolver-level: a prior install-main.ps1 must not short-circuit
        // Retry — mutable pins refresh, and only fall back if download fails.
        assert_eq!(
            cache_plan(/*immutable=*/ false, /*cached_exists=*/ true),
            CachePlan::Fetch { stale_ok: true }
        );
        assert_eq!(
            cache_plan(/*immutable=*/ true, /*cached_exists=*/ true),
            CachePlan::Reuse
        );
        assert_eq!(
            cache_plan(/*immutable=*/ false, /*cached_exists=*/ false),
            CachePlan::Fetch { stale_ok: false }
        );
        assert_eq!(
            cache_plan(/*immutable=*/ true, /*cached_exists=*/ false),
            CachePlan::Fetch { stale_ok: false }
        );
    }

    #[test]
    fn upgrade_cached_script_adds_bom_to_legacy_ps1() {
        // A .ps1 cached by a pre-#67193 installer has no BOM; the Reuse path
        // must upgrade it in place instead of serving the broken bytes forever.
        let dir = std::env::temp_dir().join(format!("hermes-bom-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cached = dir.join("install-abc1234.ps1");
        std::fs::write(&cached, b"Write-Host legacy\n").unwrap();

        upgrade_cached_script(ScriptKind::Ps1, &cached, &|_| {});
        let bytes = std::fs::read(&cached).unwrap();
        assert!(bytes.starts_with(UTF8_BOM), "legacy cache must gain a BOM");
        assert_eq!(&bytes[UTF8_BOM.len()..], b"Write-Host legacy\n");

        // Idempotent: a second pass must not double the BOM.
        upgrade_cached_script(ScriptKind::Ps1, &cached, &|_| {});
        let again = std::fs::read(&cached).unwrap();
        assert_eq!(again, bytes);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn upgrade_cached_script_leaves_sh_untouched() {
        let dir = std::env::temp_dir().join(format!("hermes-bom-sh-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cached = dir.join("install-main.sh");
        std::fs::write(&cached, b"#!/bin/bash\n").unwrap();

        upgrade_cached_script(ScriptKind::Sh, &cached, &|_| {});
        assert_eq!(std::fs::read(&cached).unwrap(), b"#!/bin/bash\n");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
