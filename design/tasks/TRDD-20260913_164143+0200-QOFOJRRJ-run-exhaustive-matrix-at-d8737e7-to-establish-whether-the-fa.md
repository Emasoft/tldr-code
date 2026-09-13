---
trdd-id: QOFOJRRJ
title: Run exhaustive_matrix at d8737e7 to establish whether the failure pre-existed
column: backburner
created: 2026-09-13T16:41:43+0200
updated: 2026-09-13T16:41:43+0200
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
---

# Run exhaustive_matrix at d8737e7 to establish whether the failure pre-existed

Split out of TRDD-8K4YKK1Q on 2026-09-13, which closed with this measurement UNPERFORMED and its box struck rather than ticked.

WHAT IS ALREADY ESTABLISHED (from git history, no build): the test/emitter key mismatch pre-dated d8737e7 by four months. The matrix test was created asserting the Rust field name at 91ea0fb (2026-04-25); the emitters were realigned at 66fa8bc (2026-05-05); both are ancestors of d8737e7 (2026-09-06); no emitter commit touched that key after it; the fix 5c1d56d (2026-09-08) is the only commit touching the test after it. A -G cross-check returns commit lists identical to -S on both sides.

WHAT IS NOT ESTABLISHED, and is this card: that exhaustive_matrix actually FAILED at d8737e7. Mismatch is necessary, not sufficient — a target can fail there for unrelated reasons, or pass despite a mismatch when the assertion is never reached. Only running the suite at that revision settles it.

WHY IT IS DEFERRED, not refused: it needs a worktree build of an old checkout, multi-GB, and disk is the binding constraint on this machine (stop line 20 GB). The value is retrospective attribution only — the fix has landed and is green — so it does not justify the space today. Pull this card when disk is plentiful or when a build at that revision is needed for another reason.

TWO RESIDUAL LIMITS worth carrying: the direction of 66fa8bc rename was read from its commit SUBJECT, not measured, and a literal-count search cannot see a serde rename at all — field name and wire key are known to diverge in this codebase. And `git grep -c <literal> <rev> -- <path>`, which prints counts rather than contents and is the direct instrument for what a file contained at a revision, is refused by the code_tool_gate, so even the cheap direct measurement is unavailable under current tooling.

## Approval log

- 2026-09-13T16:41:43+0200 — MANDATE issued by session-claude (min-approval-requirement: none). Pre-approved: issuer authority >= required approver. No approval request was sent.
