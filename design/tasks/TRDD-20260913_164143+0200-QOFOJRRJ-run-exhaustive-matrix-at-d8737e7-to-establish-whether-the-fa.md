---
trdd-id: QOFOJRRJ
title: Run exhaustive_matrix at d8737e7 to establish whether the failure pre-existed
column: backburner
created: 2026-09-13T16:41:43+0200
updated: 2026-09-13T16:45:58+0200
current-owner: session-claude
created-by: session-claude
task-type: audit
min-approval-requirement: none
assignee: unassigned
mandate: true
mandated-by: none
approved: true
approval-judge: session-claude
approval-datetime: 2026-09-13T16:41:43+0200
review-after: 2026-12-13
---

# Run exhaustive_matrix at d8737e7 to establish whether the failure pre-existed

Split out of TRDD-8K4YKK1Q on 2026-09-13, which closed with this measurement UNPERFORMED and its box struck rather than ticked.

WHAT IS ALREADY ESTABLISHED (from git history, no build): the test/emitter key mismatch pre-dated d8737e7 by four months. The matrix test was created asserting the Rust field name at 91ea0fb (2026-04-25); the emitters were realigned at 66fa8bc (2026-05-05); both are ancestors of d8737e7 (2026-09-06); no emitter commit touched that key after it; the fix 5c1d56d (2026-09-08) is the only commit touching the test after it. A -G cross-check returns commit lists identical to -S on both sides.

WHAT IS NOT ESTABLISHED, and is this card: that exhaustive_matrix actually FAILED at d8737e7. Mismatch is necessary, not sufficient — a target can fail there for unrelated reasons, or pass despite a mismatch when the assertion is never reached. Only running the suite at that revision settles it.

WHY IT IS DEFERRED, not refused: it needs a worktree build of an old checkout, multi-GB, and disk is the binding constraint on this machine (stop line 20 GB). The value is retrospective attribution only — the fix has landed and is green — so it does not justify the space today. Pull this card when disk is plentiful or when a build at that revision is needed for another reason.

TWO RESIDUAL LIMITS worth carrying: the direction of 66fa8bc rename was read from its commit SUBJECT, not measured, and a literal-count search cannot see a serde rename at all — field name and wire key are known to diverge in this codebase. And `git grep -c <literal> <rev> -- <path>`, which prints counts rather than contents and is the direct instrument for what a file contained at a revision, is refused by the code_tool_gate, so even the cheap direct measurement is unavailable under current tooling.

## Approval log

- 2026-09-13T16:41:43+0200 — MANDATE issued by session-claude (min-approval-requirement: none). Pre-approved: issuer authority >= required approver. No approval request was sent.

## Acceptance

- [ ] A worktree at d8737e7 runs `cargo test -p tldr-cli --test exhaustive_matrix` and the full `test result:` line is quoted on this card verbatim, with the exit code.
- [ ] The recorded outcome states explicitly whether the failure was present at d8737e7, and if it was, whether the failing assertion is the key mismatch or a different one, naming the test. A quoted run that does not say WHICH assertion failed leaves the same necessary-vs-sufficient gap that struck box 3 on the parent card.
- [ ] REVISION PROOF (hardens box 1, which does not verify WHERE the run happened): the worktree is created as `git worktree add <session-scratchpad>/wt-d8737e7 --detach d8737e7`, NOT under builds_dev; `git -C <worktree> rev-parse --short HEAD` is quoted on this card and reads d8737e7; the quoted `test result:` line is the one emitted by the exhaustive_matrix BINARY specifically, not a doc-test or sibling-target line; the exit code is captured by `echo "exit=$?"` on its own line; and free disk is recorded BEFORE and AFTER, with `git worktree remove` plus `git worktree prune` run afterwards so the multi-GB target/ does not outlive the measurement and recreate the very constraint that deferred this card.
- [ ] ARTIFACT, NOT JUDGEMENT (hardens box 2, which asks for prose and so cannot fail mechanically): if the run is RED, the failing test NAME and its assertion text are quoted VERBATIM from the output, and the card then states whether that assertion is the function/function_name key mismatch or a different one. If the run is GREEN, the card says so and notes that the mismatch therefore did not produce a failure at that revision. Rationale: quoting named output can be checked by eye in a second; "the card states X" cannot, and ticking box 2 on an unrelated flake would reproduce one level down the exact necessary-vs-sufficient substitution that struck box 3 on the parent.

## Notes and lessons learned

PULL WHEN — the trigger that matters, because the review-after date is a clock unrelated to the constraint and will fire whether or not disk is free: pull this card when free disk exceeds roughly 60 GB, OR when a worktree at ANY pre-2026-09-08 revision is being built for another reason. In the second case ride along — the build IS the whole cost, so this measurement becomes nearly free. review-after: 2026-12-13 is a backstop, not the plan. An unassigned backburner card with only a date is indistinguishable from deletion with an audit trail; the ride-along clause is what makes it a real queue item.
ONE RUN CLOSES TWO CARDS: the parent TRDD-8K4YKK1Q carries a struck, unticked box that depends on this same unperformed run. Whoever performs it must go back and tick the parent box too. The parent is archived and frozen, so that is easy to miss — this line exists so it is not.
