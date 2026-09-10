---
trdd-id: EX9JW9O4
title: Statement-granular PDG residue by node kind
column: todo
created: 2026-09-10T19:08:05+0200
updated: 2026-09-10T19:08:05+0200
current-owner: session-claude
task-type: bugfix
scope: project
min-approval-requirement: none
labels: [pdg, slicing, precision]
---

TRDD-3TCJKGWM moved the PDG node unit from "one CFG block" to "one recorded statement span",
fixing the backward-slice-includes-unrelated-statements defect. That fix records a span only for
node kinds the CFG builder's `record_spans_for_statement` walk covers; several kinds still fall
through to the per-line fallback (sound, just coarser than the fixed cases), and the review of
that card (`reports/kanban-wave1/20260910_190305+0200-review-3TCJKGWM.md`) found two more places
where the span attribution is not what the card's own design table claims. This card carries the
residue forward so each kind gets a deliberate decision instead of staying an unlisted gap.

## Residue, by node kind

- **Wrapped `Branch`/`LoopHeader` conditions.** A condition expression that spans multiple source
  rows is reported by the CFG as the condition's first line only (pre-existing CFG limit, not
  introduced by 3TCJKGWM); the PDG per-line fallback then makes one node per row of the wrapped
  condition instead of one node for the whole condition.
- **Compound statement headers** (`if`/`for`/`while`/`loop`/`try`/`match`). The header line itself
  is not covered by `record_spans_for_statement`'s span recording, so it gets a per-line node —
  correct in effect (a header is normally one line) but not a recorded span.
- **Rust `?`** (`try_expression` without an `expression` field, dispatched through
  `process_question_mark`). No span recorded; per-line fallback.
- **A nested `function_definition`/`function_declaration`/`arrow_function` reached DIRECTLY**
  through `process_statement`'s explicit arm (`cfg/extractor.rs:494-496`): gets its own CFG, no
  span in the enclosing function — by design, not a gap.
- **N1 (reviewer) — the same nested-function kinds reached INDIRECTLY**, via the generic
  `body`/`definition` recursion in `record_spans_for_statement` (`cfg/extractor.rs:343-382`) —
  e.g. a method inside a local `class_body`, or a `def` nested inside a `with` block's body. These
  DO get a span, and it is attributed to the OUTER block id — a silent scope-crossing the card's
  own design table doesn't mention (the table says "none — its own CFG" for this kind
  unconditionally, which is only true for the direct-dispatch case above). Empirically harmless
  today (the DFG already found refs on those rows pre-diff), but the invariant as stated is false
  for this path. Either stop the recursion at a nested-function-kind node (delegate, produce no
  span, matching direct dispatch) or the code comment / design doc must say the "own CFG, no span"
  guarantee holds only for top-level nested statements.
- **N2 (reviewer) — a JS/TS `switch`/`case` body is one span, not one span per statement.**
  `switch_body` is a listed container in `record_spans_for_statement` (descends without recording),
  but a `case`/`case_clause` node is not — its statement children are typically direct
  (unnamed-field) children, not exposed through a `body` field, so the whole node falls to the
  `None => record_statement_span(start, end)` leaf branch and the entire case body (potentially
  several statements) becomes one span. Not a regression — the pre-existing block-granular code
  had the same imprecision at the whole-switch level — and untested either way.

## Acceptance

- [ ] Each residue kind listed above either gets a recorded span (finer PDG node) or the card
  documents explicitly why it must stay per-line/whole-block, with a test pinning the chosen
  behavior for that kind (a red-then-green pair if a span is added, an explicit assertion of the
  current per-line/whole-span shape if left as documented residue).

## Notes and lessons learned
