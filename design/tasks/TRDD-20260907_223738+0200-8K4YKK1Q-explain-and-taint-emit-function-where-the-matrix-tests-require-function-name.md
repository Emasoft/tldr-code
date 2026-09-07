---
trdd-id: 8K4YKK1Q
title: explain and taint emit a function key where exhaustive_matrix requires function_name
column: todo
created: 2026-09-07T22:37:38+0200
updated: 2026-09-07T22:37:38+0200
current-owner: session-claude
task-type: bugfix
min-approval-requirement: none
labels: [test-failure, json-output, schema, undecided-cause]
---

# explain and taint emit a function key where exhaustive_matrix requires function_name

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body)

Filed 2026-09-07 from an unfiltered `cargo test -p tldr-cli --no-fail-fast` run.
**Not started. The cause is UNDECIDED and that is the point of the card** — see
"Do not assume this is a stale test".

## What is measured

`crates/tldr-cli/tests/exhaustive_matrix.rs` fails 36 tests. Scoped to that
target's own section of the run output (lines 3387-4977), measured on a
SNAPSHOT of the capture — the run was still appending, and four greps against a
growing file are four different files:

| check | result |
|---|---|
| distinct TEST NAMES emitting the message (`awk` pairing name→message) | **36** |
| `^test .* \.\.\. FAILED$` lines in the section | 36 |
| `grep -cF 'SILENT_FAIL — missing \`function_name\` field'` | 36 |
| distinct panic sites | 18 at `:1137`, 18 at `:1185`, nothing else |
| cargo's own tally for the target | `641 passed; 36 failed` |

**The first row is the one that carries the claim, and it was added after a
review refused the others.** A `grep -c … | sort | uniq -c` counts OCCURRENCES
and destroys the test↔message association: 36 failures and 36 occurrences is one
equation with two unknowns, satisfiable by 30 tests emitting 36 messages while 6
fail for unrelated reasons. Pairing each message back to its `---- <name> stdout
----` header and taking `sort -u` gives 36 DISTINCT NAMES, which is the claim.

**Nor were the other rows "three independent checks", as first written.** The
message line and the `panicked at` line are printed by the SAME panic event, and
cargo's tally is computed from the same outcomes as the `FAILED` lines. That is
two observations plus a consistency check, not four.

**Section boundary corroborated** (this was the strongest structural evidence and
was initially omitted): the section contains exactly ONE `test result:` line, and
every `panicked at` path in it is `exhaustive_matrix.rs`. Had the end-boundary
regex missed and fallen back to EOF, both would have shown it. That same
`test result:` line also proves the target had FINISHED before it was read, which
is what makes a count off an in-flight capture legitimate here.

641 tests in the same binary pass. That bounds the blast radius **as observed by
this test binary's assertions** — it is not evidence the underlying defect is
narrow. If the same key is read by consumers this file does not assert on, they
are equally broken and equally invisible here.

Two failures were read in full rather than sampled by name:

- `test_explain_on_rust` — panics at `exhaustive_matrix.rs:1137`,
  `[explain × rust] SILENT_FAIL — missing \`function_name\` field`
- `test_taint_on_rust` — panics at `exhaustive_matrix.rs:1185`,
  `[taint × rust] SILENT_FAIL — missing \`function_name\` field`

Both dump a payload that opens `{ "function": "main", ...`. So the emitted key
is `function`; the asserted key is `function_name`.

The remaining 34 were NOT read individually. What covers them is the fixed-string
count above — 36 failures, 36 occurrences of that exact message, in a section
bounded by the target's own `Running` lines. That is total coverage of the
section for the message, not an extrapolation from the two that were read.

## Do not assume this is a stale test — the cause is genuinely open

**This card was nearly filed as one more cell of TRDD-DPL55YB3's stale-test
sweep. An adversarial review refused it, correctly.** DPL55YB3's clusters have a
mechanism read from production source: a field that still exists on
`FileStructure`, still populated in memory, carrying `#[serde(skip_serializing)]`
and a doc comment naming `schema-cleanup-v1 BUG-13` with a named replacement.

**None of that has been established here.** Different command (`explain` /
`taint`, not `structure`), and the dumped payload — `function`, `file`,
`line_start`, `line_end`, `signature`, `purity` — is not `FileStructure`. No
struct has been read. No `skip_serializing`. No BUG-13 reference. No commit.

And the test's own wording cuts the other way: **`SILENT_FAIL — missing
\`function_name\` field`** is the vocabulary of *the product dropped a field*,
not of *the test is out of date*. Filing this under a stale-test heading would
have decided that question by placement — which is exactly the failure
DPL55YB3 warns about in its own words: *"Rewriting an assertion until it matches
current output is how a real regression gets ratified into the test suite."*

## The fork in the road — decide it from source, do not skip it

| | Change | What it means |
|---|---|---|
| a | fix the TESTS to read `function` | the rename was deliberate; 36 assertions are stale |
| b | fix the COMMAND to emit `function_name` | a field was renamed out from under consumers |

Unlike DPL55YB3, **(b) is live here.** Nothing yet excludes it.

**One partial data point, stated at its real strength.** A review raised a third
possibility — that `function_name` was NEVER emitted and the test was wrong from
birth (the shape DPL55YB3's route 2 raised and was refuted on). `git log -S
'function_name' -- crates/tldr-cli/src crates/tldr-core/src` is non-empty
(`62bfe3a`, `c0266aa`, `a439bab`, …), so the literal has existed in production
source. That makes "wrong from birth" less likely — but `-S` reports commits
where the OCCURRENCE COUNT changed, so it establishes the literal existed, NOT
that this payload ever carried the key, and NOT its current state. Do not
upgrade this to "it was renamed"; read the emitter.

**"drift" is the wrong word for this card and is deliberately not used.** Drift
implies unintentional divergence. If (a) turns out right, the correct
description is *stale tests after an intentional migration*, which sends a
triager looking for an incomplete sweep instead of an accident. If (b), it is a
regression. Either way, not drift.

## Acceptance

- [ ] The struct behind the `explain` / `taint` payload is located and read, and
      whether `function` is a deliberate rename of `function_name` is settled
      from source and history — not from which side is the smaller diff.
- [ ] Whether the two panic sites (`:1137`, `:1185`) are one shared assertion
      helper or two independent ones is read, since that decides whether this is
      one fix or two.
- [ ] Pre-existing or not is MEASURED, not argued: the target is run at a
      pre-chain checkout (`d8737e7` or earlier) in a worktree with
      `git status --porcelain` empty. Source-level argument is not a substitute —
      see the correction below.
- [ ] Whichever side is fixed, it is red-proofed: observed failing under a
      deliberate mutation before being accepted as passing.

## Provenance — what is and is not established

**Not established: that this predates the current work chain.** An earlier draft
of this reasoning leaned on `git show b64d541 -- crates/tldr-core/src/types.rs`
returning no hits for the serde attributes. That check is worthless here on two
counts: it inspects ONE commit of a ten-commit chain, and it inspects a file that
does not contain `function_name` at all. It was dropped rather than qualified,
because an evidence line that looks like provenance gets read as settled.

The decisive measurement is the pre-chain run in the acceptance list. It has not
been done.

## Origin

Surfaced by the same unfiltered run that TRDD-K3XQ7M2V's acceptance box 4
required. Sibling cards: TRDD-DPL55YB3 (the `functions`/`methods` stale-test
sweep, a genuinely different mechanism) and TRDD-BJ9T0U9I (eight files that
assert against a stale release binary — NOT this one, which resolves its binary
with `assert_cmd::cargo::cargo_bin!`).
