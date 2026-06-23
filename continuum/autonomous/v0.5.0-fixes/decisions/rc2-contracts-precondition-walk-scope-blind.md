# RC2 — contracts precondition walk is scope-blind (nested asserts missed; mid-body local asserts mislabeled high-confidence preconditions)

**Cluster:** invariants-specs (analysis[7]); command: contracts (and verify's `sweep_contracts`)
**Classification:** design-fork. NOT implemented in this closeout.
**File/fn:** `crates/tldr-cli/src/commands/contracts/contracts.rs` : `extract_preconditions` (body-walk ~L1947) + `precondition_from_assert_call`

## Problem

`extract_preconditions` inspects ONLY the DIRECT children of the function body
and treats every top-level assert/guard as an *entry precondition* with
`confidence: High`, regardless of whether the asserted value is a function
parameter or an internally-computed local. Two distinct facets:

- **(a) Nested asserts are never reached.** Asserts inside a leading
  `if cond then ... end` block (e.g. Luau `createElement` guarding its params
  inside an `if`) are invisible because the walk does not recurse into nested
  blocks. After the RC1 `statements` unwrap this is the remaining recall gap for
  guarded preconditions.
- **(b) Body-local asserts are mislabeled.** An assert on a local defined
  earlier in the body is still emitted as a high-confidence *precondition* even
  though a precondition must constrain INPUTS at entry. Live example (IDX 124,
  `luau/classes.luau`):
  ```lua
  local success, actual = pcall(function() ... end)
  assert(not success)          -- about a LOCAL computed at body line ~9
  assert(actual == expected)   -- ditto
  ```
  These three asserts surface as `confidence: high` preconditions — an
  over-claim: they are post-computation assertions, not entry contracts.

No def-before-assert ordering check and no parameter-membership check exist.

### Reproduced (LIVE)
- IDX 124 `luau/classes.luau`: asserts on `success`/`actual` (computed via
  `pcall` mid-body) reported as `confidence: high` preconditions.
- IDX 129 `luau-roact createElement`: param asserts nested inside `if` are
  missed (forced `--lang luau` yields empty preconditions).

## Attribution

PRE-EXISTING. `git diff 5635a77..HEAD --stat` on `contracts.rs` is empty in the
v0.5.0 campaign for this path; the body-walk and confidence assignment are
identical at baseline. The RC1 fix in this closeout (Swift `statements` unwrap +
first-arg extraction) does NOT change scope/confidence semantics — it only makes
Swift bodies iterable; the scope-blindness applies to all call-assert languages
and is unchanged.

## Options

| Option | Scope | Risk | Effect |
|---|---|---|---|
| **A — precision** | Treat an assert as a precondition only when (i) it is reachable before any assignment/definition in the body AND (ii) every identifier it references is a function parameter; otherwise downgrade to an invariant or `confidence: low`. Recurse into leading guard-if blocks for param asserts. | needs a small def-before-use/param-membership dataflow notion not currently present | Removes false high-confidence preconditions (IDX 124). May drop genuine guarded preconditions if the membership check is too strict. |
| **B — recall** | Recurse into all nested blocks and keep emitting, but cap confidence at `medium` and relabel body-local asserts as `assertions` (a new taxonomy bucket) rather than `preconditions`. | output-schema change (precondition-vs-assertion split) | Keeps/raises recall (fixes IDX 129) but requires a schema/label change and updates to every `contracts` consumer + verify's `constrained_functions` (which counts `has_pre`). |

## Blast radius

`extract_preconditions` is shared across all languages AND verify's
`sweep_contracts`. Changing confidence/labeling affects the `contracts` output
schema and verify coverage (`constrained_functions` counts `has_pre`). The
existing characterization tests in the contracts unit module (and
`cli_patterns_contracts_tests`) pin current behavior and would need
re-baselining. Option A additionally needs a (small) parameter-set +
def-before-use pass.

## Recommendation

This is a genuine taxonomy/precision tradeoff (entry-precondition vs
body-assertion) with cross-command schema impact, so it is filed as a fork
rather than forced into the closeout. **Recommend A** for the high-confidence
over-claim (the more damaging defect: a *wrong* high-confidence contract is worse
than a missing one), combined with the nested-guard recursion from B *limited to
param asserts* (so recall improves without inventing a new output bucket). The
RC1 `statements` unwrap already landed the prerequisite (iterable Swift bodies);
a param-membership filter can be layered on the same shared body-walk.

## Pointers
- `extract_preconditions` (~L1931), `precondition_from_assert_call` (~L2044),
  `precondition_from_guard`, `get_function_body` (now unwraps Swift `statements`
  after RC1).
- verify coverage: `crates/tldr-cli/src/commands/contracts/verify.rs`
  `compute_coverage` (`constrained_functions` via `has_pre`).
