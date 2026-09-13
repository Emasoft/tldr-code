---
trdd-id: Y0EF8ZVF
title: Guard the repo-root join against paths that escape the repository root
column: complete
created: 2026-09-13T18:35:16+0200
updated: 2026-09-13T21:31:09+0200
current-owner: emanuelesabetta
created-by: emanuelesabetta
task-type: bugfix
min-approval-requirement: none
assignee: emanuelesabetta
mandate: true
mandated-by: none
approved: true
approval-judge: emanuelesabetta
approval-datetime: 2026-09-13T18:35:16+0200
implementation-commits: [b76490e, 8b67078]
---

# Guard the repo-root join against paths that escape the repository root

## The defect

git_changed_files (tldr-cli, bugbot command group -- locate with: tldr search git_changed_files crates/tldr-cli) builds each result as repo_root.join(line), where line comes from git stdout.

Rust's Path::join with an ABSOLUTE argument silently DISCARDS the base: repo_root.join("/etc/x") is "/etc/x", not repo_root + /etc/x. A line beginning with / or .. therefore escapes repo_root entirely.

The next thing that happens is filter_tldrignored (tldr-core, callgraph module -- tldr search filter_tldrignored crates/tldr-core) calling matched_path_or_any_parents, which PANICS with "path is expected to be under the root" for any path not under its root -- a third-party panic carrying no indication of which git line caused it.

This is the SAME panic already fixed once in this chain (the macOS /var vs /private/var spelling mismatch), reachable from a sibling input that was left unguarded.

## Why it is filed rather than assumed handled

git does not normally emit absolute paths, so this is low-likelihood. It is filed because committing a fix for one panic while knowingly leaving its sibling unguarded and unrecorded is how a known defect becomes an undiscovered one.

## The fix

After joining, verify each path starts with repo_root (Path::starts_with). If one does not, ERROR -- bail naming the offending raw stdout line AND the repo root, so the diagnosis is in the message.

Do NOT filter the offending path out silently. Dropping it hides malformed git output and violates this project's fail-fast rule. This is a GUARD, not a fallback.

## Acceptance

- [x] Every joined path is checked with starts_with against repo_root before being returned
- [x] A failing check produces an error naming both the offending raw git line and the repo root
- [x] A test feeds git output containing an absolute path and asserts the error, and that test FAILS if the guard is removed

## Approval log

- 2026-09-13T18:35:16+0200 — MANDATE issued by emanuelesabetta (min-approval-requirement: none). Pre-approved: issuer authority >= required approver. No approval request was sent.
- 2026-09-13T18:35:26+0200 — column → dev. A worker is implementing this right now; backburner would claim it is deferred
- 2026-09-13T21:31:09+0200 — COMPLETE by emanuelesabetta. all three acceptance boxes met and verified: guard present, error names both the line and the root, and the regression test proves it with a real git invocation.
