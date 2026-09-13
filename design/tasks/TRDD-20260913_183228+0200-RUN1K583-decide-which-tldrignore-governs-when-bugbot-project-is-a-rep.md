---
trdd-id: RUN1K583
title: Decide which tldrignore governs when bugbot project is a repo subdirectory
column: todo
created: 2026-09-13T18:32:28+0200
updated: 2026-09-13T18:34:59+0200
current-owner: emanuelesabetta
created-by: emanuelesabetta
task-type: spike
min-approval-requirement: none
assignee: emanuelesabetta
mandate: true
mandated-by: none
approved: true
approval-judge: emanuelesabetta
approval-datetime: 2026-09-13T18:32:28+0200
---

# Decide which tldrignore governs when bugbot project is a repo subdirectory

## Why this exists

Split out of the TRDD-M2MUQ7QH repo-root fix chain (7d6a2bb, a17e57b, and the tldrignore-root fix). Filed so a REJECTED alternative does not vanish into a conversation.

## The situation

detect_changes (in changes.rs, bugbot command group) joins every git-reported path onto a
canonicalized repo_root, because git prints paths relative to the repository top level
regardless of the process working directory. It then calls filter_tldrignored(root, paths)
(in scanner.rs, callgraph module), which loads .tldrignore from root and matches with
matched_path_or_any_parents -- a method that PANICS when a path is not under that root.

Passing project there panics whenever project and repo_root differ, including by macOS
spelling alone (/var vs /private/var). Fix taken: pass repo_root.
Locate the code with symbol search, not filenames -- both basenames are generic in this 4-crate workspace: tldr search detect_changes crates/tldr-cli and tldr search filter_tldrignored crates/tldr-core. Symbol plus crate survives edits, which a line number does not.

## The alternative that was REJECTED, and why it may still be right

Fix C: filter changed_files down to those under project first, then root the matcher at a
canonicalized project.

Rejected for scope -- it changes the OUTPUT SET of detect_changes, not just its join base,
and that is a larger semantic change than a panic fix should carry.

But it is not obviously wrong, and it avoids a hazard the taken fix has:

- With repo_root, a crate subdirectory carrying its OWN .tldrignore, inside a repo whose
  root has none, silently gets NO filtering at all -- load_tldrignore returns None and
  filter_tldrignored returns the paths unchanged. Files a user deliberately excluded start
  being analysed, with no error and no warning. That is worse than a panic because it is
  invisible.
- Fix C keeps the ignore file next to the code being analysed, and arguably matches what a
  user pointing bugbot at a crate directory wants: only that crate's changed files.

## What is NOT yet known

- Which semantic users actually expect. Unmeasured, and this project has no PRRD to appeal to.
- gitignore patterns anchor to the directory of the ignore file, so a subdirectory
  .tldrignore containing a pattern like corpus/ would mis-anchor if the matcher root and the
  pattern source are separated. Any hybrid needs its own test.
- No .tldrignore exists anywhere in this repository today (verified 2026-09-13), so this
  repo's own suite cannot catch a regression in either direction. That is an argument for
  writing the test, not for relaxing.
SCOPE QUALIFIER on the line above, and it is load-bearing: this is a PUBLISHED CLI, so the population that matters is every consumer's repository, not this one. The absence of a .tldrignore here is evidence about the TEST ENVIRONMENT, not about the hazard. Do not read it as grounds to close this card as not-applicable.

## Acceptance

- [ ] A decision is recorded here naming which ignore file governs when project is a repo subdirectory, with the reason
- [ ] A test exists in which project is a SUBDIRECTORY of the repo root, .tldrignore sits at the repo root, and the asserted path set is exact (not a subset or contains check). Checkable by opening the fixture and confirming those three facts -- no re-derivation of this card's argument required
- [ ] A verdict is recorded for the silent-no-filtering case (subdirectory carries .tldrignore, repo root has none, so NO filtering happens at all): made to fail loudly, or deliberately accepted
- [ ] If it was accepted, a user-facing note states that filtering is skipped in that configuration

## Approval log

- 2026-09-13T18:32:28+0200 — MANDATE issued by emanuelesabetta (min-approval-requirement: none). Pre-approved: issuer authority >= required approver. No approval request was sent.
- 2026-09-13T18:34:59+0200 — column → todo. Not deferred -- the semantic is ALREADY SHIPPING in three unpushed commits, so backburner asserted something false about live behaviour
