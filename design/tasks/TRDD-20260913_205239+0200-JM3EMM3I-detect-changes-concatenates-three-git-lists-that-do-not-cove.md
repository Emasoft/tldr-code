---
trdd-id: JM3EMM3I
title: detect_changes concatenates three git lists that do not cover the same scope
column: blocked
created: 2026-09-13T20:52:39+0200
updated: 2026-09-13T21:03:34+0200
current-owner: emanuelesabetta
created-by: emanuelesabetta
task-type: bugfix
min-approval-requirement: none
assignee: emanuelesabetta
mandate: true
mandated-by: user
approved: true
approval-judge: emanuelesabetta
approval-datetime: 2026-09-13T20:52:39+0200
blocked-by: TRDD-M2MUQ7QH
pre-block-column: todo
blocker-probe: git grep -q SCOPE-CONTRACT -- crates/tldr-cli/src/commands/bugbot/changes.rs
blocker-holds-if: exit-nonzero
---

# detect_changes concatenates three git lists that do not cover the same scope

The defect

detect_changes (tldr-cli, bugbot command group -- locate with: tldr search detect_changes crates/tldr-cli) builds its uncommitted list by concatenating the output of three git calls, all run with current_dir set to project:

  diff --name-only HEAD
  diff --name-only --staged
  ls-files --others --exclude-standard --full-name

The two diff calls report the WHOLE repository regardless of current_dir -- git diff takes a pathspec, and an absent one means the whole tree, not the cwd. ls-files defaults to the CWD SUBTREE, but that is a pathspec DEFAULT, not a property of the command: the pathspec :/ makes it repo-wide. The --full-name flag changes the SPELLING of its output, never the SCOPE.

So when project is a subdirectory of the repo root (a crate dir, say), the result is asymmetric: modified and staged files are collected repo-wide, while untracked files are collected only from under project. A caller asking for changes in one crate gets modified files from other crates, but not untracked files from them.

Verified 2026-09-13 on this repo, read-only. (An earlier probe used a modified file INSIDE the probed subtree, which BOTH hypotheses predict -- it proved nothing. Do not repeat it.) The probes that settle it:

  git -C crates/tldr-cli diff --name-only HEAD~1 HEAD lists two design/tasks cards -- outside that subtree, spelled root-relative; a cwd-scoped diff would have printed nothing. NOTE this is a commit-to-commit diff, not the worktree and index ones the code uses; git parses the pathspec before the diff-mode dispatch, so the rule is shared -- that step is structural, not probed.
  git -C crates/tldr-cli ls-files --full-name lists only paths under that crate; the same command with the pathspec :/ lists .gitattributes, .github/workflows/release.yml and .gitignore. So the subtree scoping is a default, and one token overrides it.

diff.relative is unset on this repo. Setting it (or passing --relative) WOULD scope diff output to the cwd, silently invalidating the premise above and breaking the root-relative spellings the code depends on. Check it before implementing.

Why it is filed rather than fixed inline

Found while fixing the sibling defect of TRDD-M2MUQ7QH (ls-files being CWD-relative, fixed by --full-name). The scope asymmetry is a DIFFERENT bug with a different fix, and landing it inside a one-flag path-spelling fix would have made that change two changes. Filed so the knowledge is not lost.

Which behaviour is correct is a DECISION, not a lookup

Three answers, stated without preference. The choice belongs to whoever owns the bugbot contract. Whichever is chosen, the FIRST acceptance box requires the decision be written into the doc comment -- documenting it is never the optional part:

  A. Repo-wide for all three, making project purely a repo locator. Two spellings: pass the pathspec :/ to the ls-files call, or run that call with current_dir set to repo_root, which the code already holds. Prefer the second -- :/ is MAGIC pathspec syntax, neutralised by GIT_LITERAL_PATHSPECS=1 which some CI systems set; current_dir carries no such dependency.
  B. Project-scoped for all three. Pass project as a pathspec to both diff calls. The three lists then agree, scoped to the subtree. Alters existing behaviour on the diff paths.

  C. Leave all three git calls repo-wide and filter the final union by the project prefix. Not free: it moves path matching from git to hand-written code. git honours core.ignorecase and does not follow symlinks; a naive starts_with prefix filter does neither, and it also wrongly accepts a sibling directory whose name merely begins with the project name (crateXtra, under a project named crate) as being inside it. Component-wise comparison is required.

Do NOT pick one by reading this card. Establish what the callers expect from project first.

Do NOT implement this until the --full-name fix of TRDD-M2MUQ7QH has landed -- both edit the same call site, and concurrent work would conflict.

Acceptance

- [ ] The intended scope semantics of the project argument are stated explicitly in the detect_changes doc comment, on a line beginning with the literal marker SCOPE-CONTRACT: -- the marker is what this card blocker-probe greps for, so without it the card stays blocked
- [ ] detect_changes returns a file set matching the stated scope -- enforced in the git invocations or after the union, either is acceptable
- [ ] A test creates, inside the repo but OUTSIDE project, BOTH a modified tracked file and an untracked file, calls detect_changes with project set to a subdirectory, and asserts that EITHER BOTH appear in changed_files OR NEITHER does -- naming which, per the semantics chosen in the first box
- [ ] That test was confirmed to FAIL before the fix was applied, and its failure message is quoted in this card

## Approval log

- 2026-09-13T20:52:39+0200 — MANDATE issued by emanuelesabetta (min-approval-requirement: none). Pre-approved: issuer authority >= required approver. No approval request was sent.
- 2026-09-13T20:56:15+0200 — column → backburner. blocked on a contract decision only the bugbot owner can make, and on the --full-name fix landing; todo would claim it is ready to work
- 2026-09-13T20:59:43+0200 — column → blocked. blocked on TRDD-M2MUQ7QH landing (same call site, concurrent work would conflict) and on a contract decision only the bugbot owner can make; backburner means deferred-by-design and is drift-exempt, which would bury a card that should be picked up as soon as the fix lands
