---
trdd-id: DPL55YB3
title: test_structure_json_output expects a functions key absent from structure's python output
column: complete
created: 2026-09-07T21:02:22+0200
updated: 2026-09-10T14:28:23+0200
implementation-commits: [76c2d21]
current-owner: session-claude
task-type: bugfix
min-approval-requirement: none
labels: [test-failure, json-output, schema]
---

# test_structure_json_output expects a functions key absent from structure's python output

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-10

**Boxes 2, 3, 4 (partial) DONE — worker-3, TEST FILES ONLY (no production edit).**

- `cli_tests.rs:80::test_structure_json_output` (fix at :95-118) — parses
  stdout as JSON, asserts `files[0].definitions[]` contains `{name:"foo",
  kind:"function"}` and `{name:"Bar", kind:"class"}`. Red-proofed by deleting
  `def foo(): pass` from the fixture (assert panicked "expected a function
  definition named foo"), then reverted. `cargo test -p tldr-cli --test
  cli_tests test_structure_json_output` → `1 passed`.
- `elixir_method_infos_v1.rs:63-78` and `:126-152` — both replaced the
  suppressed `f0.get("methods")` access with `definitions[]` filtered to
  `kind == "method"` (names for test 1, count for test 2). Red-proofed by
  dropping `defp baz` from `FIXTURE` (assert panicked "must contain `baz`,
  got [\"bar\"]"), then reverted. `cargo test -p tldr-cli --test
  elixir_method_infos_v1` → `2 passed; 0 failed`.
- `language_command_matrix.rs` — untouched (already green, no functions/methods
  key assertions in it); full run `872 passed; 0 failed; 28 ignored`.

**Box 4 REWORDED and closed 2026-09-10 (coordinator).** It asked for the whole
unfiltered `cargo test -p tldr-cli` to be green, which this card cannot deliver
and never owned. What it CAN assert, and now does, is that its three owned
files are green in the unfiltered workspace run: `cli_tests` 16/0,
`language_command_matrix` 872/0 (28 ignored), `elixir_method_infos_v1` 2/0.
**The whole-crate-green ambition moved to TRDD-2U7D9PNS**, which enumerates the
2026-09-08 baseline reds that actually block it.

**One failure observed outside this card's scope, left untouched:**
`cli_tests.rs::test_cold_start_performance` — a wall-clock perf assertion,
unrelated to the functions/methods schema question. It **failed once under the
7-worker parallel build load** on this machine ("Cold start took 1818ms,
expected <1000ms") and **PASSED in the 2026-09-10 workspace gate**, where
`cli_tests` reports 16 passed / 0 failed with `test_cold_start_performance ...
ok`. Carded as TRDD-YM857S4Y (load-sensitive bucket). Not touched here.



Filed 2026-09-07. **The suite is RED on `main` and was already red before
this was noticed** — found incidentally while running `cargo test -p tldr-cli`
unfiltered for TRDD-K3XQ7M2V's acceptance, which is why the card exists at all:
nothing else in the repo was reporting it.

**Not started.** The first decision is which side is wrong, and that decision is
the whole task — see "The fork in the road".

## What

`crates/tldr-cli/tests/cli_tests.rs:80::test_structure_json_output` asserts:

```rust
.stdout(predicate::str::contains("\"functions\""))
.stdout(predicate::str::contains("\"classes\""))
```

`tldr structure <dir> -l python -q` exits 0 and emits, per file:

```json
{ "path": "test.py",
  "classes": ["Bar"],
  "method_infos": [ ... ],
  "imports": [],
  "definitions": [ {"name":"foo","kind":"function", ...},
                   {"name":"Bar","kind":"class", ...},
                   {"name":"method","kind":"method", ...} ] }
```

`"classes"` is present, so that half passes. **The payload carries no `functions`
key** — functions live in `definitions[]` under `"kind": "function"`. The first
predicate fails and the binary exits 101.

**Scope of that reading, stated because the title used to exceed it:** one
invocation, the test's own — `tldr structure <tmpdir> -l python -q`. Whether any
other language backend emits a `functions` key, and what `-q` does to the shape,
were not checked. The FAILURE is measured; "the command never emits it" is a
generalization from a single sample and is not.

Even this card's current title still quantifies over all python inputs and all
flag combinations. The scope-safe form names the EVENT rather than the command's
behaviour — *"test_structure_json_output fails a functions-key assertion"* — and
asserts no universal at all. Not renamed a second time: the file is untracked and
a shrinking-delta rename is churn. Noted so the next editor picks that form.

## Evidence it is pre-existing, not a regression

The same single test was run at HEAD
`2d3b87f1ec1cba73699ab3f53577d210f5b17113` in a **detached worktree** with
`git status --porcelain` empty — i.e. with no uncommitted work present at all —
and failed identically (`Unexpected stdout, failed var.contains("functions")`,
`test result: FAILED. 0 passed; 1 failed`).

**CORRECTED 2026-09-07 22:37 — that reproduction proves LESS than this section
claimed.** `git merge-base --is-ancestor 2d3b87f b64d541` returns FALSE:
`2d3b87f` is **not** an ancestor of the O66FM8TN chain's base, so it sits inside
or after the chain. The reproduction therefore establishes only *"not caused by
UNCOMMITTED work"* — never *"predates the chain"*, which is how this section was
being read. "Pre-existing" was carrying two different meanings.

**What does establish it, read at the pre-chain base.** `b64d541~1` is
`d8737e7`, and at that commit `crates/tldr-core/src/types.rs` ALREADY carries

    #[serde(skip_serializing)]
    #[serde(default)]
    pub functions: Vec<String>,

and the identical treatment on `pub methods`. The suppression predates the whole
chain, from the file's own state at the base — not from a diff-grep of one
commit inside it. An earlier draft argued this from `git show b64d541 -- …`
returning no hits, which inspects ONE commit of ten and cannot see a change to a
line's neighbour; it was dropped rather than qualified.

## The sweep is wider than one test — cluster 2

`crates/tldr-cli/tests/elixir_method_infos_v1.rs` fails two tests for the SAME
reason with a different key, and they meet this card's own evidence bar:

- `:64-66` — `.get("methods").and_then(Value::as_array).expect("methods array present")`
- `:140` — the same access via `.unwrap()`
- `types.rs:1297-1299` — `#[serde(skip_serializing)] #[serde(default)] pub methods: Vec<String>`,
  doc comment: *"schema-cleanup-v1 BUG-13 … JSON output emits `method_infos`
  (objects) and `definitions` instead."*
- the test's own assertion message calls it **"legacy methods[]"**

So `a5c2e3b`'s alignment sweep missed at least two cells, not one. **A fix that
touches only `cli_tests.rs` leaves the suite red.**

**The fix here is NOT a key swap.** The test asserts `methods` *contains* the
strings `"bar"` and `"baz"`; `method_infos` holds OBJECTS. Reading names out of
`method_infos`/`definitions[]` is a different assertion, not a renamed one.

**Not in this card:** the 36 `exhaustive_matrix.rs` failures over a
`function_name` key. Different command, different struct, no `skip_serializing`,
no BUG-13 reference — grouping them here would have decided their (a)/(b)
question by placement, which is the exact failure this card documents twice.
They are TRDD-8K4YKK1Q, cause explicitly undecided.

**RESOLVED — it is (a). Settled from PRODUCTION SOURCE at both ends, 2026-09-07.**
This section reached the right answer on its third try; the two wrong routes are
kept below because each failed in a way worth not repeating.

**The decisive evidence — `crates/tldr-core/src/types.rs`, `FileStructure`.**

At `d64dead` (initial release) the struct was, verbatim:

    pub path: PathBuf,
    pub functions: Vec<String>,      <- present, NO skip_serializing_if
    pub classes: Vec<String>,
    pub methods: Vec<String>,
    pub imports: Vec<ImportInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub definitions: Vec<DefinitionInfo>,

`functions` was serialized UNCONDITIONALLY, so `contains("\"functions\"")`
**passed at birth**. Today the same field still exists, at `types.rs:1283`, and
the only change is the attribute now above it:

    #[serde(skip_serializing)]
    #[serde(default)]
    pub functions: Vec<String>,

with the intent written in its own doc comment: *"schema-cleanup-v1 BUG-13: kept
on the in-memory struct for internal consumers but `#[serde(skip_serializing)]`
so JSON output never carries this redundant string list. New consumers should
read `definitions[]`."* `methods` carries the same treatment and the same note.

That is a deliberate, documented, in-production schema decision — not changelog
testimony about one. **So (a): the test is stale.** And (b) is affirmatively
excluded: re-emitting `functions` would revert a cleanup whose reasoning is
recorded at the field.

**The null-vs-absent contradiction dissolves.** `skip_serializing` makes the key
ABSENT, and `jq` prints a missing key as `null` — so the changelog's "`functions`
null" and this card's "no `functions` key" were the same observation in two
renderings. Neither was wrong.

**Route 1 that failed — changelog testimony.** This section first said
"RESOLVED → (a)" citing `a5c2e3b`, whose diff is `CHANGELOG.md` (+79) and
`language_command_matrix.rs` (+14/-2): **zero production diff**. It is a
test-alignment follow-up, so it could evidence that a rework happened but never
its INTENT — which is the whole (a)/(b) question. "It left `cli_tests.rs` behind"
was invented outright. The conclusion was right and the evidence did not reach
it; that is not a near-miss, it is a coin landing correctly.

**Route 2 that failed — a pickaxe on the wrong literal.** The retraction that
replaced route 1 asserted the assertion "may never have been satisfiable and
shipped red", because `git log -G '"functions"'` found no rework commit. **Both
halves were artifacts.** The struct field is `pub functions: Vec<String>` — the
QUOTED literal never appears there at all, serde derives the wire name — so a
search for `"functions"` structurally cannot see the schema. Worse, the correct
literal `-G 'pub functions: Vec<String>'` ALSO returns only `d64dead`, because
the line was never deleted; only an attribute above it was added. **A pickaxe
cannot see a change that edits a line's neighbour.** Third quoted-literal search
artifact of this session, and the second time an empty result was nearly recorded
as a finding.

**One flatly false statement was published here and is retracted.** Route 2
claimed the struct "carries `classes`, `method_infos`, `definitions` and **no
`functions` field**". It has one, at :1283. The field list was read starting at
line 1285 — one line PAST the top of the struct — and absence was reported from a
window that excluded the thing sought. A partial read cannot support an absence
claim about the whole.

**Confirmed independently at RUNTIME, 2026-09-07 22:06.** The `--no-fail-fast`
run dumped the actual failing payload, and it matches what the struct predicts:

    "files": [ { "path": "test.py",
                 "classes": ["Bar"],
                 "method_infos": [ {"name":"method", ...} ],
                 "imports": [],
                 "definitions": [ {"name":"foo","kind":"function", ...},
                                  {"name":"Bar","kind":"class", ...},
                                  {"name":"method","kind":"method", ...} ] } ]

No `functions` key — exactly what `#[serde(skip_serializing)]` produces — and
`foo` present in `definitions[]` under `"kind": "function"`. Source reading and
runtime output now agree, which is what closes this: the two could have
disagreed, and a schema conclusion drawn only from a struct would not have
noticed.

**This also fixes the fix's target.** The replacement assertion must key on
`"definitions"` plus `"kind": "function"`; asserting on `"functions"` in ANY form
is asserting on a field the schema deliberately suppresses.

Original route-1 evidence kept below; the corrections are only legible beside it.

`a5c2e3b` ("language-command-matrix-test-followup-v1: align check_structure with
M4 `.definitions[]` schema") describes the M4 change in its own message: it folded
the "redundant `functions`/`methods` string arrays into a structured
`.files[].definitions[]` array", and its worked example records

    `tldr structure /tmp/x` on a 2-function Python file
      → `definitions[]` len 2, `functions` null   (production code untouched)

So `functions` disappearing is the **deliberate M4 schema change**, not a
regression. `a5c2e3b` aligned `crates/tldr-cli/tests/language_command_matrix.rs`
— the only test file it touches — and left `cli_tests.rs` behind. **This card is
that sweep's missed cell.** Follow its precedent: it KEPT the
`functions`/`classes` checks OR'd with `definitions` rather than replacing them.

**History, and the method that actually established it.** `cli_tests.rs` has only
THREE commits in its entire history, and `git log -G 'functions'` over it returns
just `d64dead` ("Initial release"). **`-G` is what supports "never textually
touched since"; the `-S` I ran first does NOT** — `-S` is a pickaxe on occurrence
COUNT, so a commit that moves, reflows, or reformats the line leaves the count
unchanged and is never reported. The conclusion held; the citation had to be
replaced.

*And the first search of all returned EMPTY:* `-S '"functions"'` matches nothing,
because the Rust source contains `\"functions\"`. **An empty `-S`/`-G` result is a
search artifact until the literal is checked against the real source text** — it
nearly got recorded here as "no commit ever touched it".

## The fork in the road — do NOT skip this decision

Two repairs, and they are not equivalent:

| | Change | What it means |
|---|---|---|
| a | fix the TEST to assert `"definitions"` / `"kind": "function"` | the test was stale; `definitions[]` is the intended schema |
| b | fix the COMMAND to emit a `functions` key | the schema regressed and consumers lost a key |

**(a) is the tempting one and is the one that must be justified, not assumed.**
Rewriting an assertion until it matches current output is how a real regression
gets ratified into the test suite — the test would then be green and prove
nothing. Before taking (a), establish that `definitions[]` is deliberate:
`method_infos` sitting beside `definitions` suggests the shape has been
reworked at least once, so the history is worth reading.

Whichever is chosen, the fixed test must be **red-proofed** — seen failing
before it is accepted as passing.

## Acceptance

- [x] Which of (a)/(b) is correct is decided from the schema's history, and the
      reasoning is recorded here — not chosen because it was the smaller diff.
      **DECIDED: (a), on production source.** `FileStructure.functions` exists at
      both ends; `d64dead` serialized it unconditionally, today it carries
      `#[serde(skip_serializing)]` with the intent in its own doc comment
      (`schema-cleanup-v1 BUG-13`). See the RESOLVED section. *Ticked, unticked,
      and re-ticked the same day — the first tick rested on changelog prose, the
      untick on a search artifact. Only this one rests on the struct itself.*
- [x] `cargo test -p tldr-cli --test cli_tests test_structure_json_output`
      passes, and was observed FAILING first under a deliberate mutation.
      **DONE 2026-09-10 (worker-3).** Parses stdout as JSON and asserts
      `files[0].definitions[]` has `{name:"foo", kind:"function"}` and
      `{name:"Bar", kind:"class"}` — see STATE block for the red-proof.

      **Do NOT write the fix as `contains("\"definitions\"")`.** Not "a weaker
      test" — **not a test.** `definitions` carries `#[serde(default)]` and no
      `skip_serializing_if`, so the key is emitted for every file entry
      regardless of what the extractor found. The predicate has NO failing
      input: it would pass on a completely broken Python extractor returning
      zero definitions. It tests serde's field list, not the parser.

      Note the direction of that trade: the CURRENT assertion
      (`contains("\"functions\"")`) *can* fail, and does. The proposed
      replacement would convert a red test into a permanently green one that
      cannot fail — and a green test is trusted. That is strictly worse than
      the bug being fixed, and it is the same red-proof failure this card
      demands be avoided elsewhere.

      **Generalize it rather than blacklisting keys one at a time:** the schema's
      stated purpose is a stable shape for consumers, so EVERY key-presence
      assertion against this payload is dead on arrival — `"classes"`,
      `"imports"`, `"method_infos"` included. The only reason
      `contains("\"functions\"")` still discriminates is that its field's
      attribute changed out from under it.

      `contains("\"kind\": \"function\"")` is no better: it pins the serializer's
      exact whitespace and breaks on a formatting change, while still asserting
      nothing about WHICH definition has that kind.

      **Parse stdout as JSON and assert structurally** — `files[0].definitions`
      contains an element with `name == "foo"` AND `kind == "function"`. That is
      the property the test is actually for.

      **Red-proof by deleting `foo` from the fixture, not by deleting the
      assertion.** Removing the assertion proves only that the assertion runs;
      removing the thing it looks for proves it can still fail for the right
      reason.
- [x] Cluster 2 lands too: `elixir_method_infos_v1.rs` `:66` and `:140` stop
      asserting on the suppressed `methods` key. Reading names out of
      `method_infos`/`definitions[]` is a NEW assertion, not a key swap —
      `methods` holds strings, `method_infos` holds objects. Red-proof each.
      **DONE 2026-09-10 (worker-3).** Both now derive from `definitions[]`
      filtered to `kind == "method"` (names for the populated test, count for
      the parity test). Red-proofed by dropping `defp baz` — see STATE block.
- [x] **REWORDED 2026-09-10** — from whole-crate green (never met, and not this
      card's to meet) to the three files this card owns; the whole-crate
      ambition moved to **TRDD-2U7D9PNS**. Same treatment as TRDD-RX6JWVVZ
      boxes 2-3: the box is reworded to what was established, not ticked as
      written. The three owned files are green in the UNFILTERED workspace run,
      cargo's own exit status: `cli_tests` 16 passed / 0 failed, `language_command_matrix` 872
      passed / 0 failed (28 ignored), `elixir_method_infos_v1` 2 passed / 0
      failed. The original wording asked for the whole `cargo test -p tldr-cli`
      target to be green, which is not something a card about one JSON key can
      deliver — it depends on a baseline set of reds this card never touched.
      **That ambition moved to TRDD-2U7D9PNS**, which owns the unfiltered
      tldr-cli run and enumerates every red blocking it. Reworded rather than
      left unticked, so this card stops claiming work it does not own.
- [x] N/A — this box was conditional on fork (b), and box 1 decided (a). No
      other command's JSON was checked for the same rename because no rename
      happened: `FileStructure.functions` was suppressed, not renamed.

## Origin

Surfaced by TRDD-K3XQ7M2V's acceptance box 4, which required the pre-existing
suite to be run unmodified. That box is satisfied — K3XQ7M2V does not cause
this — but the repo's suite does not return to green until this card lands.
