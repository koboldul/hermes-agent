use std::process::Command;

fn main() {
    // -----------------------------------------------------------------
    // Bake the install.ps1 pin into the binary at compile time.
    //
    // BUILD_PIN_COMMIT and BUILD_PIN_BRANCH are read by bootstrap.rs's
    // `option_env!()` macro to default the install-script reference.
    // Precedence (matches install.ps1's own arg precedence): commit > branch.
    //
    // The COMMIT pin is opt-in. By default a dev build pins ONLY the branch,
    // so the produced installer follows that branch's HEAD at install time
    // (tolerant of fast-forwards/new commits, and never references a SHA the
    // local checkout hasn't pushed). Set HERMES_BUILD_PIN_COMMIT to bake an
    // immutable commit pin for reproducible/release installers.
    //
    // Commit pin resolution:
    //   - HERMES_BUILD_PIN_COMMIT, if set and non-empty. Accepts a SHA, tag,
    //     or branch name; resolved to an immutable SHA via `git rev-parse`
    //     when possible, else used verbatim if it already looks like a SHA.
    //   - Otherwise: NO commit pin (branch-follow is the default).
    //
    // Branch pin resolution:
    //   1. HERMES_BUILD_PIN_BRANCH, if set and non-empty.
    //   2. `git rev-parse --abbrev-ref HEAD` of the checkout this build.rs
    //      lives in — the current branch. (None on a detached HEAD.)
    //   3. Last-resort fallback handled below: if neither commit nor branch
    //      resolves, warn — the binary needs a runtime arg or dev-repo env.
    //
    // Build script reruns on git HEAD change so a new commit triggers
    // a rebuild without `cargo clean`.
    // -----------------------------------------------------------------

    let commit = resolve_commit_pin();
    let branch = resolve_branch_pin();

    if let Some(c) = &commit {
        println!("cargo:rustc-env=BUILD_PIN_COMMIT={c}");
        println!(
            "cargo:warning=hermes-bootstrap: pinning to commit {}",
            short(c)
        );
    }
    if let Some(b) = &branch {
        println!("cargo:rustc-env=BUILD_PIN_BRANCH={b}");
        match &commit {
            Some(_) => println!("cargo:warning=hermes-bootstrap: pinning to branch {b}"),
            None => println!(
                "cargo:warning=hermes-bootstrap: following branch {b} HEAD (no commit pin; \
                 set HERMES_BUILD_PIN_COMMIT for an immutable pin)"
            ),
        }
    }
    if commit.is_none() && branch.is_none() {
        // Fail loudly rather than silently produce a binary that errors
        // at runtime with "no install-script pin supplied". A build that
        // can't resolve a pin almost certainly indicates a misconfigured
        // build environment.
        println!(
            "cargo:warning=hermes-bootstrap: no pin resolved at build time; binary will fail at runtime without HERMES_SETUP_DEV_REPO_ROOT or runtime args"
        );
    }

    // -----------------------------------------------------------------
    // A10: bake the SHA-256 of the install scripts AT THE PINNED COMMIT so the
    // runtime can byte-verify what it downloads/reuses. The digest is over the
    // git BLOB bytes (`git cat-file blob <commit>:scripts/<file>`), which are
    // exactly what raw.githubusercontent serves at that commit — independent of
    // any working-tree line-ending (core.autocrlf) conversion. Only baked when
    // an immutable commit pin is resolved; a mutable branch-follow build ships
    // no digest (its target can legitimately change after build), and the
    // runtime then skips verification unless attestation is required (in which
    // case it fails closed).
    // -----------------------------------------------------------------
    if let Some(c) = &commit {
        if let Some(d) = git_blob_sha256(c, "scripts/install.ps1") {
            println!("cargo:rustc-env=BUILD_INSTALL_PS1_SHA256={d}");
        }
        if let Some(d) = git_blob_sha256(c, "scripts/install.sh") {
            println!("cargo:rustc-env=BUILD_INSTALL_SH_SHA256={d}");
        }
        println!("cargo:rerun-if-changed=../../../scripts/install.ps1");
        println!("cargo:rerun-if-changed=../../../scripts/install.sh");
    }

    // -----------------------------------------------------------------
    // A10: a production (RELEASE-profile) installer MUST ship an attested
    // identity — an exact FULL 40-char commit pin AND both install-script
    // digests baked from that commit. This is UNCONDITIONAL: there is no
    // optional environment gate for production. A `tauri build` (release) with
    // no HERMES_BUILD_PIN_COMMIT therefore FAILS here. The repository release
    // command (apps/bootstrap-installer/scripts/release-build.mjs) sets the pin.
    // Debug builds (`tauri dev`, `tauri build --debug`, `cargo test`) are exempt
    // and may follow a branch.
    // -----------------------------------------------------------------
    let is_release = std::env::var("PROFILE").map(|p| p == "release").unwrap_or(false);
    if is_release {
        let full_commit = commit
            .as_deref()
            .filter(|c| c.len() == 40 && c.chars().all(|ch| ch.is_ascii_hexdigit()))
            .map(|c| c.to_string())
            .unwrap_or_else(|| {
                panic!(
                    "A10: a RELEASE (production) Hermes-Setup build requires \
                     HERMES_BUILD_PIN_COMMIT set to an exact full 40-char commit SHA — \
                     no branch/dev fallback is permitted in a production installer. \
                     Use `npm run tauri:build:release` (apps/bootstrap-installer), which \
                     resolves the pin from a clean checkout."
                )
            });
        let ps1 = git_blob_sha256(&full_commit, "scripts/install.ps1").unwrap_or_else(|| {
            panic!("A10: release build could not compute the install.ps1 digest at {full_commit}")
        });
        let sh = git_blob_sha256(&full_commit, "scripts/install.sh").unwrap_or_else(|| {
            panic!("A10: release build could not compute the install.sh digest at {full_commit}")
        });
        // Re-emit defensively (idempotent — the commit block above already did
        // when a pin was present; Cargo keeps the last value).
        println!("cargo:rustc-env=BUILD_INSTALL_PS1_SHA256={ps1}");
        println!("cargo:rustc-env=BUILD_INSTALL_SH_SHA256={sh}");

        // A5/A4: INDEPENDENTLY verify the packaged/build-input IDENTITY at build
        // time over the COMPLETE closure — HEAD must equal the pinned commit AND
        // the build-input tree (the whole installer app incl Cargo.lock, the
        // baked install scripts, the root package.json/lock, and the shared
        // build inputs) must have NO tracked changes and NO untracked files, AND
        // the source trees must have NO IGNORED shadow files (a stray .js over a
        // committed .ts). git unavailable → fail closed. This does not trust any
        // JSON/stamp; it re-interrogates git directly.
        let repo_root = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("..")
            .join("..")
            .join("..");
        let head = git_capture(&repo_root, &["rev-parse", "HEAD"]);
        let status = git_capture(
            &repo_root,
            &[
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--",
                "package.json",
                "package-lock.json",
                "scripts/install.ps1",
                "scripts/install.sh",
                "apps/bootstrap-installer",
                "apps/shared",
            ],
        );
        if let Err(reason) = evaluate_input_identity(head.as_deref(), &full_commit, status.as_deref()) {
            panic!("A5: RELEASE build-input identity check failed: {reason}");
        }
        // Shadow scan: gitignored .js/.d.ts in a source tree can shadow committed
        // .ts at build time and is INVISIBLE to --untracked-files=all.
        let ignored = git_capture(
            &repo_root,
            &[
                "status",
                "--porcelain",
                "--ignored",
                "--untracked-files=all",
                "--",
                "apps/bootstrap-installer/src",
                "apps/shared/src",
            ],
        );
        if let Err(reason) = evaluate_shadow_free(ignored.as_deref()) {
            panic!("A5: RELEASE build-input shadow check failed: {reason}");
        }

        println!(
            "cargo:warning=hermes-bootstrap: RELEASE build attested at commit {} (clean tree + no shadow files, both install-script digests baked)",
            short(&full_commit)
        );
    }
    println!("cargo:rerun-if-env-changed=PROFILE");

    // Rerun build.rs when HEAD moves. With branch-follow as the default the
    // baked commit no longer changes per-commit, but a branch *switch* changes
    // the detected branch name, so we still re-trigger. When an explicit
    // HERMES_BUILD_PIN_COMMIT resolves a moving ref (tag/branch) to a SHA, a
    // HEAD move can also change that resolution. .git/HEAD changes on every
    // commit / branch switch / rebase.
    let git_dir = locate_git_dir();
    if let Some(gd) = &git_dir {
        println!("cargo:rerun-if-changed={}/HEAD", gd.display());
        // .git/HEAD often points at a ref (e.g. `ref: refs/heads/bb/gui`);
        // also watch the ref itself so a new commit on the same branch
        // re-triggers.
        if let Ok(head) = std::fs::read_to_string(gd.join("HEAD")) {
            if let Some(rest) = head.trim().strip_prefix("ref: ") {
                println!("cargo:rerun-if-changed={}/{}", gd.display(), rest);
            }
        }
    }
    println!("cargo:rerun-if-env-changed=HERMES_BUILD_PIN_COMMIT");
    println!("cargo:rerun-if-env-changed=HERMES_BUILD_PIN_BRANCH");

    // -----------------------------------------------------------------
    // Tauri windows manifest. See hermes-setup.manifest for rationale —
    // declares level="asInvoker" so Windows's installer-detection
    // heuristic doesn't refuse to launch us without UAC elevation.
    // -----------------------------------------------------------------
    #[cfg(target_os = "windows")]
    let attrs = {
        let manifest = include_str!("hermes-setup.manifest");
        let win = tauri_build::WindowsAttributes::new().app_manifest(manifest);
        tauri_build::Attributes::new().windows_attributes(win)
    };

    #[cfg(not(target_os = "windows"))]
    let attrs = tauri_build::Attributes::new();

    tauri_build::try_build(attrs).expect("failed to run tauri-build");
}

fn resolve_commit_pin() -> Option<String> {
    // Commit pinning is OPT-IN. Only bake a commit when the caller explicitly
    // asks for one via HERMES_BUILD_PIN_COMMIT. With no env var, we return
    // None and the installer follows the branch HEAD at install time.
    let requested = std::env::var("HERMES_BUILD_PIN_COMMIT").ok()?;
    let requested = requested.trim();
    if requested.is_empty() {
        return None;
    }
    // Resolve the request (which may be a SHA, tag, or branch name) to an
    // immutable commit SHA so the baked pin is reproducible. `^{commit}`
    // dereferences tags to the commit they point at.
    if let Ok(out) = Command::new("git")
        .args(["rev-parse", "--verify", &format!("{requested}^{{commit}}")])
        .output()
    {
        if out.status.success() {
            if let Ok(s) = String::from_utf8(out.stdout) {
                let s = s.trim().to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
    }
    // Couldn't resolve via git (e.g. building outside a checkout). Accept the
    // literal value only if it already looks like a SHA; otherwise fail loud
    // rather than bake an unresolvable ref into the binary.
    if is_sha(requested) {
        return Some(requested.to_string());
    }
    panic!(
        "HERMES_BUILD_PIN_COMMIT={requested:?} could not be resolved to a commit \
         (git rev-parse failed and it is not a valid SHA)"
    );
}

/// True if `s` looks like an abbreviated-or-full git SHA (7..=40 hex chars).
fn is_sha(s: &str) -> bool {
    let len = s.len();
    (7..=40).contains(&len) && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn resolve_branch_pin() -> Option<String> {
    if let Ok(v) = std::env::var("HERMES_BUILD_PIN_BRANCH") {
        if !v.trim().is_empty() {
            return Some(v.trim().to_string());
        }
    }
    let out = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    // "HEAD" is what you get on a detached checkout — no meaningful branch
    // to pin to. The commit pin still applies; just don't emit a branch.
    if s.is_empty() || s == "HEAD" {
        None
    } else {
        Some(s)
    }
}

fn locate_git_dir() -> Option<std::path::PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() {
        return None;
    }
    Some(std::path::PathBuf::from(s))
}

/// SHA-256 of a file's git-blob bytes at `commit` (A10 install-script
/// attestation). Uses `git cat-file blob <commit>:<path>` so the digest is over
/// the exact bytes raw.githubusercontent serves at that commit — no working-tree
/// EOL conversion. Returns None when the object can't be read (the digest is
/// then simply not baked, and the runtime skips verification unless attested).
fn git_blob_sha256(commit: &str, path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};

    let out = Command::new("git")
        .args(["cat-file", "blob", &format!("{commit}:{path}")])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(&out.stdout);
    Some(hex::encode(hasher.finalize()))
}

/// Run a git command in `repo_root` and capture trimmed stdout, or None when git
/// is unavailable / the command fails (A5 fail-closed signal).
fn git_capture(repo_root: &std::path::Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .current_dir(repo_root)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok().map(|s| s.trim().to_string())
}

/// A5 (pure, testable): decide whether the packaged/build-input tree is exactly
/// the pinned commit and clean. `head`/`status` are `None` when git is
/// unavailable → fail closed. Mirrors the JS beforePack guard so the two gates
/// enforce the same contract independently.
fn evaluate_input_identity(head: Option<&str>, pin: &str, status: Option<&str>) -> Result<(), String> {
    let head = head.ok_or_else(|| "git unavailable (rev-parse HEAD)".to_string())?;
    let head = head.trim().to_lowercase();
    if head.len() != 40 || !head.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("HEAD '{head}' is not a full 40-char commit"));
    }
    if head != pin.trim().to_lowercase() {
        return Err(format!(
            "HEAD {} does not match the pinned commit {}",
            &head[..12.min(head.len())],
            &pin[..12.min(pin.len())]
        ));
    }
    let status = status.ok_or_else(|| "git status unavailable".to_string())?;
    if !status.trim().is_empty() {
        return Err(format!(
            "build-input tree is NOT clean (tracked/untracked change: {})",
            status.lines().next().unwrap_or("").trim()
        ));
    }
    Ok(())
}

/// A5 (pure, testable): reject when the `git status --ignored` scan of the
/// source trees is non-empty — a gitignored file present in a source dir (e.g. a
/// stray `.js` over a committed `.ts`) can shadow the real source at build time.
/// `None` (git unavailable) fails closed.
fn evaluate_shadow_free(ignored_status: Option<&str>) -> Result<(), String> {
    let status = ignored_status.ok_or_else(|| "git status --ignored unavailable".to_string())?;
    if !status.trim().is_empty() {
        return Err(format!(
            "source tree contains ignored/untracked shadow file(s): {}",
            status.lines().next().unwrap_or("").trim()
        ));
    }
    Ok(())
}

fn short(commit: &str) -> &str {
    if commit.len() >= 12 {
        &commit[..12]
    } else {
        commit
    }
}
