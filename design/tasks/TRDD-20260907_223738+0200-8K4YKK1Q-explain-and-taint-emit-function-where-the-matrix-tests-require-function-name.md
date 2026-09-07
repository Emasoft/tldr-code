---
trdd-id: 8K4YKK1Q
title: explain and taint emit a function key where exhaustive_matrix requires function_name
column: todo
created: 2026-09-07T22:37:38+0200
updated: 2026-09-07T22:52:00+0200
current-owner: session-claude
task-type: bugfix
min-approval-requirement: none
labels: [test-failure, json-output, schema, stale-test]
---

# explain and taint emit a function key where exhaustive_matrix requires function_name

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body)

Filed 2026-09-07 from an unfiltered `cargo test -p tldr-cli --no-fail-fast` run.

**RESOLVED to (a) the same day, from production source. The tests are stale.**
Filed with cause UNDECIDED; that was the right posture for ~20 minutes and it is
now settled — see "RESOLVED". The fix itself is not started.

**And the card's original framing was wrong in a way worth keeping.** It argued
cluster 3 was a *different mechanism* from TRDD-DPL55YB3's. It is the same
INTENT (a deliberate schema alignment, with the test sweep left incomplete)
implemented a different WAY (a custom `Serialize` impl instead of a serde
attribute). An adversarial review predicted exactly this before the emitter was
read: *"different implementation of the same intent is exactly what a
split-by-implementation hides."*

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

## RESOLVED — it is (a). The rename is deliberate and documented at the field.

`crates/tldr-cli/src/commands/remaining/types.rs:730`, `ExplainReport`:

```rust
/// cross-command-consistency-v1 (BUG-14): emitted in JSON as
/// `function` so the function-name field is identical across commands
/// (`slice`, `dead-stores`, `resources`, `reaching-defs`, `taint`,
/// `explain`, ...). The custom `Serialize` impl below handles the
/// rename; deserialise still accepts both names via `alias`.
#[serde(alias = "function")]
pub function_name: String,
```

Landed in `66fa8bc` — *"cross-command-consistency-v1: align call-graph, metrics,
paths, schema field names (BUG-5, BUG-7, BUG-8, BUG-14)"*. The field is still
named `function_name` in Rust; the WIRE name is `function`, by a custom
`Serialize` impl. That is why `git log -S 'function_name'` found the literal in
src while the payload does not carry it — both observations were right and
neither implied the other.

**And `taint` was covered SEPARATELY, because `ExplainReport` does not cover it.**
18 of the 36 are `taint` tests, and the read above is `explain`'s struct — so
resolving both halves from it would have been the one-command-to-two
generalization this session kept making. `taint` has its own type,
`TaintInfo` at `crates/tldr-core/src/security/taint.rs:246`:

```rust
#[serde(rename = "function", alias = "function_name")]
pub function_name: String,
```

A different struct in a different crate, and a THIRD implementation of the same
decision — a plain serde `rename` rather than a custom `Serialize` impl. Same
deliberate wire name `function`, same `alias` keeping the old name readable on
input. Two independent reads, both halves covered.

**So (b) is affirmatively excluded**: emitting `function_name` again would revert
a cross-command consistency guarantee whose whole purpose is that this key is
spelled the same in `slice`, `dead-stores`, `resources`, `reaching-defs`, `taint`
and `explain`. The 36 assertions are stale.

**The test's own `SILENT_FAIL` wording is wrong about its cause**, and that is
the lesson to carry: `SILENT_FAIL — missing \`function_name\` field` reads as
*the product dropped a field*, and it was cited in this card's first draft as
evidence for (b). It is the test author's guess at a cause, written before the
rename existed. **A test's error message is a claim, not a measurement** — it
was authored by someone who could not see the change that would later break it.

## Why the original framing was wrong — do not repeat the taxonomy

This card was created to keep cluster 3 out of DPL55YB3, on the grounds that it
had "no `skip_serializing`, no BUG-13 reference" and therefore a different
mechanism. **Nobody had looked.** The absence of a FOUND mechanism is not a
FOUND absence — the same error this card's sibling commits spent the day
correcting, committed here as a taxonomy, which is worse because taxonomies
persist and a later reader inherits "different mechanism, established".

The split by CARD is still fine — different file, different fix, and the
`function`-vs-`method_infos` remedies genuinely differ. The split by MECHANISM
was not. Both cards are cells of ONE incomplete test sweep across at least two
schema efforts (BUG-13 suppression, BUG-14 rename), and the open question that
generalizes is: **what else did those sweeps miss?**

## Superseded framing, kept because the correction is only legible beside it

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

- [x] The struct behind the `explain` / `taint` payload is located and read, and
      whether `function` is a deliberate rename of `function_name` is settled
      from source and history — not from which side is the smaller diff.
      **DONE: `ExplainReport` at `remaining/types.rs:730`; deliberate rename,
      `cross-command-consistency-v1` BUG-14, landed `66fa8bc`. See RESOLVED.**
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
