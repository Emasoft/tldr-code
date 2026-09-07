---
trdd-id: DPL55YB3
title: test_structure_json_output expects a functions key absent from structure's python output
column: todo
created: 2026-09-07T21:02:22+0200
updated: 2026-09-07T21:35:33+0200
current-owner: session-claude
task-type: bugfix
min-approval-requirement: none
labels: [test-failure, json-output, schema]
---

# test_structure_json_output expects a functions key absent from structure's python output

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body)

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

Measured, not inferred. The same single test was run at HEAD
`2d3b87f1ec1cba73699ab3f53577d210f5b17113` in a **detached worktree** with
`git status --porcelain` empty — i.e. with no uncommitted work present at all —
and failed identically (`Unexpected stdout, failed var.contains("functions")`,
`test result: FAILED. 0 passed; 1 failed`). It is not caused by anything in
flight.

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
- [ ] `cargo test -p tldr-cli --test cli_tests test_structure_json_output`
      passes, and was observed FAILING first under a deliberate mutation.
- [ ] `cargo test -p tldr-cli` (UNFILTERED) is fully green — capture cargo's
      OWN exit status, never a wrapper's.
- [ ] If (b): a note on whether any other command's JSON carries the same
      rename, since a consumer reading `functions` would break everywhere at once.

## Origin

Surfaced by TRDD-K3XQ7M2V's acceptance box 4, which required the pre-existing
suite to be run unmodified. That box is satisfied — K3XQ7M2V does not cause
this — but the repo's suite does not return to green until this card lands.
