// IPC surface for git-driven features: worktree management ("Start work"),
// the composer coding rail's repo status, the Codex-style review pane, and
// repo-first project discovery. Extracted from main.ts; the git/gh binary
// resolvers stay injected because main.ts also uses them for self-update and
// plugin installs.
import { scanGitRepos } from './git-repo-scan'
import {
  fileDiffVsHead,
  repoStatus,
  reviewCommit,
  reviewCommitContext,
  reviewCreatePr,
  reviewDiff,
  reviewFetchPrComment,
  reviewList,
  reviewPrList,
  reviewPush,
  reviewRevert,
  reviewRevParse,
  reviewShipInfo,
  reviewStage,
  reviewUnstage
} from './git-review-ops'
import {
  addWorktree,
  listBaseBranches,
  listBranches,
  listWorktrees,
  removeWorktree,
  switchBranch
} from './git-worktree-ops'
import { type IpcRegistrar } from './ipc-registry'

export interface GitIpcDeps {
  registrar: IpcRegistrar
  resolveGitBinary: () => string
  resolveGhBinary: () => string
}

export function registerGitIpc({ registrar, resolveGitBinary, resolveGhBinary }: GitIpcDeps) {
  // Git verbs are privileged: only a registered app window's trusted main frame
  // at the packaged app origin may invoke them (SEC-AUDIT-003/005).
  const gitHandle = (channel: string, handler: (event: unknown, ...args: any[]) => unknown) =>
    registrar.handle(channel, 'git', handler)

  // Git-driven worktree management ("Start work" flow). Errors surface to the
  // renderer as rejected promises so it can toast a friendly message.
  gitHandle('hermes:git:worktreeList', async (_event, repoPath) => listWorktrees(repoPath, resolveGitBinary()))

  gitHandle('hermes:git:worktreeAdd', async (_event, repoPath, options) =>
    addWorktree(repoPath, options || {}, resolveGitBinary())
  )

  gitHandle('hermes:git:worktreeRemove', async (_event, repoPath, worktreePath, options) =>
    removeWorktree(repoPath, worktreePath, options || {}, resolveGitBinary())
  )

  gitHandle('hermes:git:branchSwitch', async (_event, repoPath, branch) =>
    switchBranch(repoPath, branch, resolveGitBinary())
  )

  gitHandle('hermes:git:branchList', async (_event, repoPath) => listBranches(repoPath, resolveGitBinary()))

  gitHandle('hermes:git:baseBranchList', async (_event, repoPath) => listBaseBranches(repoPath, resolveGitBinary()))

  // Compact repo status (branch, ahead/behind, change counts + files) for the
  // composer coding rail. Returns null on a non-repo / remote backend so the rail
  // hides cleanly rather than erroring.
  gitHandle('hermes:git:repoStatus', async (_event, repoPath) => repoStatus(repoPath, resolveGitBinary()))

  // Codex-style review pane: list changed files for a scope, fetch one file's
  // unified diff, and stage / unstage / revert. Reads return empty on failure;
  // mutations reject so the renderer can toast.
  gitHandle('hermes:git:review:list', async (_event, repoPath, scope, baseRef) =>
    reviewList(repoPath, scope, baseRef, resolveGitBinary())
  )
  gitHandle('hermes:git:review:diff', async (_event, repoPath, filePath, scope, baseRef, staged) =>
    reviewDiff(repoPath, filePath, scope, baseRef, staged, resolveGitBinary())
  )
  // Working-tree-vs-HEAD diff for one file (the preview's "show the diff" view).
  gitHandle('hermes:git:fileDiff', async (_event, repoPath, filePath) =>
    fileDiffVsHead(repoPath, filePath, resolveGitBinary())
  )
  gitHandle('hermes:git:review:stage', async (_event, repoPath, filePath) =>
    reviewStage(repoPath, filePath ?? null, resolveGitBinary())
  )
  gitHandle('hermes:git:review:unstage', async (_event, repoPath, filePath) =>
    reviewUnstage(repoPath, filePath ?? null, resolveGitBinary())
  )
  gitHandle('hermes:git:review:revert', async (_event, repoPath, filePath) =>
    reviewRevert(repoPath, filePath ?? null, resolveGitBinary())
  )
  gitHandle('hermes:git:review:revParse', async (_event, repoPath, ref) =>
    reviewRevParse(repoPath, ref, resolveGitBinary())
  )
  gitHandle('hermes:git:review:commit', async (_event, repoPath, message, push) =>
    reviewCommit(repoPath, message, Boolean(push), resolveGitBinary())
  )
  gitHandle('hermes:git:review:commitContext', async (_event, repoPath) =>
    reviewCommitContext(repoPath, resolveGitBinary())
  )
  gitHandle('hermes:git:review:push', async (_event, repoPath) => reviewPush(repoPath, resolveGitBinary()))
  gitHandle('hermes:git:review:shipInfo', async (_event, repoPath) => reviewShipInfo(repoPath, resolveGhBinary()))
  gitHandle('hermes:git:review:prList', async (_event, repoPath, branches, numbers) =>
    reviewPrList(repoPath, resolveGhBinary(), branches, numbers)
  )
  gitHandle('hermes:git:review:fetchPrComment', async (_event, repoPath, url) =>
    reviewFetchPrComment(repoPath, resolveGhBinary(), url)
  )
  gitHandle('hermes:git:review:createPr', async (_event, repoPath) =>
    reviewCreatePr(repoPath, resolveGitBinary(), resolveGhBinary())
  )

  // Repo-first project discovery: scan bounded roots for git repos (pure fs walk,
  // no native addon). Never throws to the renderer — failures yield an empty list.
  gitHandle('hermes:git:scanRepos', async (_event, roots, options) => {
    try {
      return await scanGitRepos(roots || [], options || {})
    } catch {
      return []
    }
  })
}
