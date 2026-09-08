---
trdd-id: 8K4YKK1Q
title: explain and taint emit a function key where exhaustive_matrix requires function_name
column: todo
created: 2026-09-07T22:37:38+0200
updated: 2026-09-08T10:28:19+0200
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

## CORRECTION to commit 5c1d56d's message — a false claim, not corrected in place

**`5c1d56d` says BUG-14 "updated exactly one test literal in the same diff".
That is FALSE.** A `git notes` correction is attached to the commit itself
(`git log --notes` shows it), so a reader is no longer dependent on following
the TRDD reference to learn it. This section is the long form.

**The comparable measurement — per FILE, so no two figures can be juxtaposed
into a false implication.** BUG-14 removed 10 `"function_name"` literals:

| file | removals | kind |
|---|---|---|
| `crates/tldr-core/tests/bench_quality_multilang.rs` | 8 | test literals |
| `crates/tldr-cli/src/commands/remaining/types.rs` | 1 | test literal, in an inline `#[cfg(test)]` block |
| `crates/tldr-cli/src/commands/remaining/types.rs` | 1 | production `serialize_field` line |

**Test-side total: 9**, not one.

**The `'*tests/*'` pathspec undercounted, and that was the THIRD instance of the
scoping error this section is about.** A `#[cfg(test)]` module inside `src/`
does not match that pathspec, so the 8 it returned excluded
`assert!(json.contains(r#""function_name":"calculate_total""#));` — a test
literal living in `types.rs`. A reviewer predicted this before it was measured.
The lesson is not "count more carefully"; it is that **every one of these
figures was produced by a filter chosen before the question was settled**, and
each successive filter looked obviously adequate at the time.

Stopping here deliberately: the `git notes` on `5c1d56d` carries the corrected
breakdown, which is the artifact a reader actually meets. This claim changes no
decision — "one" and "nine" both support "the sweep was incomplete" — so it gets
one correct statement in two places and no further prose.

**This has a consequence for the sibling claim.** BUG-14's sweep DID reach a
`tldr-core` test file. The residue claim was measured over `-p tldr-cli` only,
so whether `tldr-core` carries its own stale assertions is UNMEASURED, not
known-clean. `bench_quality_multilang.rs` is the obvious place to look first.

**Two figures written into an earlier draft of this section were themselves
wrong, and are recorded here rather than quietly replaced.** They were "7 test
files" (from `--name-only | grep -c 'tests/'`) and "12 changed literal lines"
(from `grep -cE '^[+-]...'`), presented as "7× and 12×" the asserted one.
Neither is commensurable with "one test literal":

- `--name-only` counts files under `tests/` touched for **any** reason — an
  unrelated import edit counts. It measures touched files, not changed literals.
- `^[+-]` counts **additions as well as removals**, source as well as test. It
  therefore counts the `alias = "function_name"` line the rename *added*.
  Whole-commit: 10 removed, 2 added — the "12" was those two summed.

So a correction of an over-scoped quantifier was drafted using two more
over-scoped quantifiers. Recorded because the recurrence is the point.

**How the original false number was produced.** The evidence was
`git show 66fa8bc -- <two source paths>`. Within those two files the grep was
correct; across the commit it measured nothing. **A quantifier was stated over a
region I had selected myself.**

**An earlier draft claimed this card's "What is measured" section "documents
this same error twice already". That is false** — the two errors documented
there are a *conflation* error (`grep -c` counting occurrences instead of
distinct test names) and a *false-independence* error (three observations that
share one panic event). Neither is the self-selected-region error. The filtered
`git show` is the FIRST instance of that class in this card.

**What survives and what does not.** The CONCLUSION is untouched: BUG-14 renamed
the wire key and left these 44 assertions behind, so the sweep was incomplete.
The supporting FIGURE is false by an order of magnitude. Do not restate the
error as harmless because the conclusion held — the conclusion surviving is luck
about this instance, not evidence about the method. (A first draft of this
paragraph said the measurement "changes the story for the better"; a review
correctly called that spin, since it attaches a positive valence to a
self-inflicted scoping error. Removed.)

A second sentence in the same message is scoped the same wrong way: *"these are
the residue"* was measured over `-p tldr-cli` only. `tldr-core`, `tldr-daemon`
and `tldr-mcp` have their own test targets and were never run. The supported
claim is **"the residue in `tldr-cli`"**.

**Why the message was not amended.** `git commit --amend` was attempted and
`git_safety_guard.py` blocked it, offering a single-use override
(`GIT_GUARD_OTP`). The override was DECLINED: rewriting history is gated behind
explicit approval that no one has given in this session, and a guard's escape
hatch existing is not the same as being authorized to use it.

**The amend-or-nothing framing was itself wrong.** An earlier draft argued the
cost of declining was that `git log` shows the false sentence and only a reader
who follows the TRDD reference reaches the correction. That treated
`--amend` and this card as the only two options. **`git notes add` is a third**:
it attaches to the commit without rewriting it (the SHA is unchanged; the note
lives in `refs/notes/commits`), and `git log --notes` displays it. It was
applied to `5c1d56d` and the guard did not object, because nothing was
rewritten. Most of the cost the refusal appeared to incur simply did not have to
be paid.

**Limit of the note, stated so nobody over-reads it:** `git notes` do NOT
propagate on a normal `push`/`fetch` — `refs/notes/commits` needs an explicit
refspec. The note reaches anyone reading THIS clone's log; it does not reach a
fresh cloner. This card remains the durable, tracked correction of record.

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

**THE COMMENT IS NOT THE EVIDENCE — the impl is. Read it, `types.rs:765`:**

```rust
impl Serialize for ExplainReport {
    ...
    s.serialize_field("function", &self.function_name)?;
    s.serialize_field("file", &self.file)?;
    s.serialize_field("line_start", ...)  ("line_end", ...)  ("line", &self.line_start)
    s.serialize_field("language", ...)  ("signature", ...)  ("purity", ...)
```

Unconditional — no `cfg`, no feature gate, no branch — and it emits `function`
ONLY, never both spellings. The emitted field ORDER matches the observed failing
payload exactly (`function, file, line_start, line_end, line, language,
signature, purity, …`), which is what ties this struct to that output.

**This paragraph replaces one that rested on the doc comment alone, and the
correction is the point.** A review caught the card applying two opposite
standards to comments in a single commit: on TRDD-OGK2ROKJ it argued at length
that a doc comment is weak evidence of intent, then here it resolved a card,
excluded a branch and ticked a box on a comment describing code nobody had
opened. **A doc comment is a claim, exactly like the test's `SILENT_FAIL`
message this card already discounts.** Both were written by someone who could
not see what would happen next.

It also refutes an alternative that was live while only the comment was read:
`ExplainReport` derives `Deserialize` but NOT `Serialize`, and
`#[serde(alias = "function")]` affects deserialization only — which is equally
what a tolerant CONSUMER type looks like. The missing derive could not
discriminate; the hand-written impl does.

The attribute and doc comment landed in `66fa8bc` — *"cross-command-consistency-v1:
align call-graph, metrics, paths, schema field names (BUG-5, BUG-7, BUG-8,
BUG-14)"*. Stated at that strength deliberately: `-S` reports commits where the
literal's OCCURRENCE COUNT changed, so it dates the attribute, not necessarily
the impl. `d64dead` ("Initial release") also appears, so `function_name` has
existed since the beginning — which makes "the test was wrong from birth"
unlikely on evidence rather than on assertion.

That is also why `git log -S 'function_name'` found the literal in src while the
payload does not carry it: the Rust field keeps the name, the wire does not.
Both observations were right and neither implied the other.

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

**(b) is excluded AS A REMEDY, which is narrower than it first read here.**
Emitting `function_name` again would revert a cross-command consistency
guarantee whose whole purpose is that this key is spelled the same in `slice`,
`dead-stores`, `resources`, `reaching-defs`, `taint` and `explain`. So the 36
assertions are stale and the fix belongs in the tests.

**That is NOT the same as "no product defect exists here", and the card said
"affirmatively excluded" as though it were.** What was read is two structs'
serialization of ONE field. Nothing here investigated whether BUG-14's rename was
applied completely across the six commands it names, whether either custom impl
dropped or altered anything else, or whether a non-test consumer still reads the
old spelling. A card labelled `stale-test` with (b) crossed off will be read as
"this area is fine"; it means "this remedy is wrong". Whether a defect exists
nearby is **uninvestigated**, not excluded.

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
