---
trdd-id: SFY0AS3N
title: bugbot changes.rs joins cwd-relative untracked paths onto repo_root
column: todo
created: 2026-09-13T22:38:22+0200
updated: 2026-09-13T22:38:22+0200
current-owner: emanuelesabetta
created-by: emanuelesabetta
task-type: bugfix
min-approval-requirement: none
assignee: emanuelesabetta
mandate: true
mandated-by: none
approved: true
approval-judge: emanuelesabetta
approval-datetime: 2026-09-13T22:38:22+0200
---

# bugbot changes.rs joins cwd-relative untracked paths onto repo_root

## Root cause (verified empirically 2026-09-13, scratchpad git probe)

In `crates/tldr-cli/src/commands/bugbot/changes.rs`, `detect_changes` takes the
`base_ref == "HEAD"` (uncommitted) branch and collects untracked paths with

    git ls-files --others --exclude-standard

`git diff --name-only` prints **root-relative** paths, but `ls-files` prints
**cwd-relative** paths unless `--full-name` is passed. The code joins both onto
`repo_root`, so whenever `project != repo_root` (a crate subdir, the normal case
in this workspace) every untracked path becomes a non-existent
`<repo_root>/<cwd-relative-path>`.

## Fix

Add `--full-name` to the `ls-files` invocation so it reports root-relative paths
like `diff --name-only` already does.

## Derived work in the same change

- Regression test: uncommitted branch, untracked file inside a crate subdir,
  assert the emitted path exists.
- Correct the doc comment that claims git always prints root-relative paths
  (false for `ls-files`).

## Known-adjacent, NOT in scope here

- The escape guard's `Path::starts_with` check is lexical and passes
  `/repo/../../etc/passwd`.
- `canonicalize` may break callers doing `strip_prefix(project)`.

## Provenance

Diagnosed and probe-verified in the session of 2026-09-13 (~19:40-20:03 +0200).
The patch was never committed; the working-tree copy was reverted at 21:30
(file mtime 21:30, content == HEAD, HEAD unmoved, no matching stash). This card
exists so the diagnosis is not re-derived from scratch.

## Approval log

- 2026-09-13T22:38:22+0200 — MANDATE issued by emanuelesabetta (min-approval-requirement: none). Pre-approved: issuer authority >= required approver. No approval request was sent.
