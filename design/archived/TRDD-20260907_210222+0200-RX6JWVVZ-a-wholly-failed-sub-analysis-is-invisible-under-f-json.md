---
trdd-id: RX6JWVVZ
title: Determine whether a wholly failed sub-analysis is invisible in todo -f json output
column: todo
created: 2026-09-07T21:02:22+0200
updated: 2026-09-07T21:21:01+0200
current-owner: session-claude
task-type: spike
min-approval-requirement: none
labels: [robustness, silent-failure, json-output]
parent-trdd: O66FM8TN
---

# Determine whether a wholly failed sub-analysis is invisible in todo -f json output

*(Typed `spike`, not `bugfix`, and titled as a question: the first acceptance
criterion below is "or the card is closed if the defect does not exist". A card
whose own confidence section says ? INFERRED cannot assert the defect in its
title.)*

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body)

Filed 2026-09-07 as a sibling of TRDD-K3XQ7M2V, which fixed the adjacent case:
a sub-analysis that RAN but skipped some files. **This card is the other half —
a sub-analysis that did not run at all.**

**Not started, and the defect is NOT yet confirmed by execution.** See
"Confidence" — the first task is to reproduce it, not to fix it.

## What (claimed)

In `TodoCommand::run`, each sub-analysis is matched on its `Result`. The `Ok`
arm carries `(Vec<TodoItem>, Value)` into the report. The `Err` arm is believed
to report **only** through `writer.progress`, which emits nothing under
`-f json`.

If so, a sub-analysis that fails outright — panicked parser, unreadable root,
missing dependency — produces JSON indistinguishable from one that ran and found
nothing. **A clean, empty, authoritative-looking result for an analysis that
never happened.** That is strictly worse than K3XQ7M2V's case, where at least
the numbers were computed over a real (if smaller) file set.

## Confidence — read this before acting

✓ VERIFIED: `run_sub_analysis` returns `(Vec<TodoItem>, Value)` and the `Ok` arm
is the only path that contributes to `sub_results` / the item list. This was
read while implementing K3XQ7M2V.

? INFERRED, NOT VERIFIED: that the `Err` arm's *only* output is
`writer.progress`, and that `writer.progress` is silent under `-f json`. Both
were noted in passing, neither was read end-to-end and neither was reproduced.
**Do not write a fix against this description.** Read the `Err` arm and the
writer's `progress` implementation first; if the claim is wrong, correct this
card rather than quietly fixing something else.

The reproducer is the harder half: forcing a sub-analysis to return `Err` may
need a fixture the repo does not have yet. A fix accepted without one is
untested by construction.

## Likely shape of the fix

K3XQ7M2V added `TodoReport.warnings: Vec<String>`, lifted by key from each
sub-report and emitted whenever non-empty. **An `Err` has no sub-report to lift
from**, so it needs its own push at the `Err` arm — the existing field is
probably the right destination, but the plumbing is not shared.

Whether a failed analysis should also change the process exit status is a
separate question this card does not decide.

## Acceptance

- [ ] The `Err` arm's actual behaviour is read and recorded here, replacing the
      INFERRED claim above with a VERIFIED one — or the card is closed if the
      defect does not exist.
- [ ] A reproducer exists that makes a sub-analysis genuinely return `Err`.
      Not a mocked writer: a real failing analysis.
- [ ] With it, `tldr todo <repro> -f json` names the failed analysis in the
      payload. Asserted on the name PRESENT, never on absence.
- [ ] Red-proofed: the guard is observed failing before it is accepted as passing.
