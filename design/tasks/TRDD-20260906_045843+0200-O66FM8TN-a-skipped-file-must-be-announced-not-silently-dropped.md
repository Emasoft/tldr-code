---
trdd-id: O66FM8TN
title: A file the analysis skips must be announced, not silently dropped from the result
column: dev
created: 2026-09-06T04:58:43+0200
updated: 2026-09-07T22:30:42+0200
current-owner: session-claude
task-type: bugfix
min-approval-requirement: user
labels: [robustness, encoding, silent-failure]
parent-trdd: BKALIK1B
implementation-commits: [b64d541, e83d2b4, 9dabab1, 6d43608, b888b2d, 804dd75, 0063e1b]
---

# A file the analysis skips must be announced, not silently dropped from the result

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-07 19:59

### 2026-09-07 — daemon + MCP done. Only units 2-4 remain.

- **SUPERSEDES the 2026-09-06 bullet below that says "the daemon `dead` handler and the MCP `dead`
  tool were NOT touched". Both are now done.** MCP landed in `9dabab1`; the daemon in `6d43608`,
  corrected by `b888b2d` and `804dd75`.
- **Unit 5 (daemon) verdict: CAN, and it does.** `handlers/callgraph.rs` builds the IR directly and
  carries `ir.warnings` into the report. `ir.warnings.len()` is an EXACT skipped-file count, not a
  proxy: `CallGraphIR.warnings` is written at exactly three places — `Vec::new()` at
  `cross_file_types.rs:1317` and `:1331`, and the single assignment `ir.warnings = skipped` at
  `builder_v2.rs:668`, fed by one push per skipped file at `builder_v2.rs:154` followed by
  `continue`. Established by RENAMING the field and letting the compiler enumerate; the grep used
  first (`warnings.push`, `warnings:`) structurally could not see an assignment and missed `:668`.
  Caveat: `cargo check` aborted in `tldr-core`, so that enumeration covers `tldr-core` only.
  Verdict file: `reports/colony/daemon-dead-skip-verdict.md`.
- **First test in `crates/tldr-daemon/` that asserts on the `dead` handler's output at all** —
  `tests/dead_handler_reports_skipped_files_test.rs`. Three red-proofs, not one: zeroing
  `files_skipped` (positive test red, control green); zeroing `warnings` with `files_skipped` left
  correct (proves the warnings assertions can fail — they had never run to completion, because Rust
  panics short-circuit and `files_skipped` is asserted first); and removing the fixture write
  (proves the control is not vacuous — `files_skipped == 0` plus `warnings == []` are both
  satisfied by a scan that found nothing).
- **Two false claims were committed and then corrected on this card's own commits.** `6d43608`
  asserted the cached path passes neither type resolution nor workspace roots — false: `builder.rs:40`
  sets `use_type_resolution = true` and `None` is what TRIGGERS workspace discovery
  (`builder.rs:48-62`), so the two build equivalently. It also re-asserted "no daemon test asserts
  on handler output content", which `handler_path_traversal_audit_test.rs` falsifies and which had
  already been retracted once in `1259493`. Both corrected in `b888b2d`.
- **Real divergence, documented in the code:** the cached closures swallow a build failure into an
  empty `ProjectCallGraph` and cache it forever (`handlers/callgraph.rs:60`, `:131`, `:328`);
  `dead` propagates (`:221`). An empty graph makes every function look dead. Any future cache
  unification must preserve BOTH the warnings and the fail-fast.
- **Unit 2 LANDED in `0063e1b`.** All five delegation rows are now terminal.
- **NEXT ACTION: the three unticked acceptance boxes** — the 56 silent sites, the un-surveyed
  `File::open`/`read_to_end` sites, and centralisation of the skip path. Those are what hold this
  card open.
- **CORRECTION (2026-09-07 22:30), because this block asserted the wrong blocker for ~15 minutes.**
  It read: *"NEXT ACTION: TRDD-OGK2ROKJ — and this card MUST NOT close without it … the DEFAULT
  human-facing output still drops the skip list silently."* **The silence half is false.**
  `remaining/todo.rs:474-476` runs `eprintln!("Warning: {warning}")` for every skipped file inside
  `run_dead_analysis`, on the default path, ungated by `--detail` and independent of output format.
  This card's own section *"Why the complexity warning is not this one"* (below) exists to defend
  that exact `eprintln!` from deletion — so the disconfirming evidence was in this file the whole
  time, and the child card contradicted its parent.
  What IS true: `format_todo_text` (`todo.rs:675-741`, whole body read) never reads
  `report.warnings`, so `todo`'s report body on stdout omits the skip line that `dead.rs:571` and
  `calls.rs:354` print in theirs. That is a consistency gap, tracked as TRDD-OGK2ROKJ, and it is
  **not** a blocker for this card — the three unticked boxes above are.
  The error came from a grep scoped to `format_todo_text` finding no `warnings` hit. The grep was
  right; its SCOPE was wrong, and re-grounding it three more ways *inside the same function*
  (`38bfe9f`) did not help. An absence inside a chosen function is not an absence in the program.
- **The near-miss is worth keeping.** Hours before, this block was edited to read "ONE unit
  remains: unit 2, uncommitted", which after the commit would have read as ready to close — a
  format-agnostic card closed on a JSON-only fix. An adversarial review fork caught it by asking
  whether the sibling commands' TEXT output had a counterpart; `dead.rs:571` and `calls.rs:354`
  both print `Files skipped: N`, and `todo` has none. I had verified the delegation rows and the
  commit, and still missed that the card's own condition was broader than the work.
- **2026-09-07 — UNIT 2 IS IN FLIGHT as child TRDD-K3XQ7M2V.** It adds a root
  `TodoReport.warnings` field, lifted by key from each sub-report, so a plain `todo -f json` names
  every skipped file without `--detail`. Implemented; its guards run by name and pass; NOT yet
  committed.
- **Units 3 and 4 WERE stalled; both dispatched 2026-09-07 21:59.** `reports/colony/DELEGATION.md`
  showed rows 2, 3 and 4 all at `Status: pending`, with `worker-3`/`worker-4` named but never
  spawned. The ledger's stated gate — "workers spawn only after piece 1 is committed" — **had been
  satisfied since 2026-09-06 ~06:30**, when piece 1 landed. So nothing was blocking them; they were
  simply never launched, and the gate was being cited for a wait it had already released. Both are
  report-writing units over the silent read sites, no code change, output under gitignored
  `reports/colony/`, so neither touches the frozen tree the in-flight suite run is measuring.
  Recorded because `column: dev` was asserting activity while only unit 2 moved — a card that claims
  to be in progress while nothing touches most of it is invisible in the one view anyone checks. A
  janitor heartbeat surfaced this and I dismissed it by pointing at unit 2, which was moving; that
  was answering a question nobody asked.
- **Units 3 and 4 are now `verified` (2026-09-07 22:0x).** Both delivered; the coordinator ran
  each acceptance command itself rather than trusting the workers' reports. Row 3 additionally
  got two checks its own command cannot perform — an EXACT set-diff of its 56 `file:line` values
  against the survey's 56 (empty in both `comm` directions) and one verdict read against source —
  because `-eq 56` is a format gate that a worker could satisfy with 56 well-formed wrong lines.
  Receipts and the residual "55 verdicts not individually verified" limit are in the ledger's
  Evidence section.
- **The planned "split units 3-4 into their own `todo` card" is DROPPED, and that is the point.**
  It existed only because a 5-unit card had no honest single column while most of it was frozen.
  Ending the stall removes the dishonesty at its source; filing a card ABOUT a stall would have
  added an artifact and left the work where it was. The insurance argument for keeping it — that
  `dev` is only true while the workers actually run, so a failed worker silently re-freezes the
  card — was real but is now spent: both units are terminal and verified.
- **ONE unit remains: unit 2, uncommitted.** With 3 and 4 verified and 1 and 5 verified, this
  card's `dev` claim is now narrow and exactly true — it names the single in-flight change
  (TRDD-K3XQ7M2V), not a 5-unit spread with most of it frozen.
- Not blocking this card, noted so it is not rediscovered: `tldr-core` could expose the
  IR-returning half of `build_project_call_graph` so `dead` and `calls` share one config path.

- **Piece 1 LANDED (2026-09-06 ~06:30): `dead`, `calls`, `smells` now announce every file they
  drop.** One shared helper, `tldr_core::fs::skipped_file_warning(path, reason)`, produces the
  `Skipped <path>: <reason>` line for all of them AND for `structure` (which was rewritten to use
  it), so a new command has one thing to call. Per command:
  - `dead` (CLI, both the refcount default and `--call-graph`): the collectors used
    `if let Ok(..) = parse_file(..)` / `extract_file(..)` and dropped the error. They now return
    the skip list; `DeadCodeReport` gained `files_skipped: usize` + `warnings: Vec<String>`
    (`#[serde(default)]`, emitted in the hand-rolled Serialize), text mode prints
    `Files skipped: N (results exclude them)` under the headline numbers.
  - `smells` (core): `filter_map(|f| analyze_file(f).ok())` swallowed every failure. Now
    partitioned; failures go to the pre-existing `SmellsReport.warnings`, which the text
    formatter already rendered. The `--deep` aggregate path carries them through too.
  - `calls` (core builder + CLI): `build_indices_parallel` read with plain `fs::read_to_string`,
    which SUCCEEDS on BOM-less UTF-16 (valid UTF-8, ASCII interleaved with NUL) — so a wide file
    was pushed as an EMPTY `FileIR`, present in the graph with zero functions. It now reads via
    `fs::read_to_string_tolerant` (the same guard as `structure`), and a file whose
    `FileParseResult.error` is set is recorded in the new `CallGraphIR.warnings` and left OUT of
    the graph. The CLI's `CallGraphOutput` gained `files_skipped` + `warnings`.
  - **Correction to the parent card's table:** `calls` did NOT "reach the guard" before this.
    It had no guard on its read path at all; the wide files were analysed-as-empty, which is the
    parent card's original bug shape, on a second path. The probe that "settled" the row could
    not distinguish analysed-as-empty from skipped, because both leave the file out of `nodes`.
  - The two OTHER consumers of the dead collector (`todo`, `bugbot born-dead`) have no warnings
    channel; they print the skip list to stderr rather than drop it. Wiring it into their
    reports is still open on this card.
  - The daemon `dead` handler and the MCP `dead` tool were NOT touched: the daemon derives
    `all_functions` from graph edges (its own pre-existing oddity) and the MCP tool drops
    `structure.warnings` on the floor. Both are still silent. Open.
- **SUPERSEDES the bullet above, 2026-09-07: the MCP half is DONE and committed (`9dabab1`).**
  `handle_dead` now carries `structure.warnings` / `structure.files_skipped` into the emitted
  `DeadCodeReport`. The daemon half is still open, and its status is NOT the same as the MCP
  half's — see below. Only the daemon sentence in that bullet is still true.
- **Two different verification standards, and they must not be reported under one word.**
  - MCP (unit 1) is verified BEHAVIOURALLY: removing the two assignment lines turns
    `crates/tldr-mcp/tests/skipped_files_dead_test.rs` red (exit 101, at the `files_skipped`
    assertion); restoring turns it green. Three checks in that file are load-bearing, not one —
    the `filesSkipped == 5` equality, the `.expect("warnings array present")`, and the positive
    `warnings.iter().any(|w| w.contains(name))` loop over the five unreadable fixtures. That
    loop cannot pass on an empty vec, and the vec IS empty under the neutered build because
    `analysis/dead.rs` initializes every `DeadCodeReport` literal with `warnings: Vec::new()`
    (the analysis never reads files). The negative loop over the three readable fixtures is
    vacuous on an empty vec BY DESIGN — it guards over-reporting, not under-reporting.
  - Daemon (unit 5) has cleared a COMPILER, nothing more. It is uncommitted and has **no test
    at all**. Settled by ENUMERATION, which is the read that answers "what is covered": the
    harness lists 39 test functions for `tldr-daemon`, all 39 were read, and every one is a
    path-traversal rejection (9), a message-format check (12), a `state::`/`server::`/socket
    unit test (13), a cache test (3) or a perf test (2) — 9+12+13+3+2 = 39. **Not one
    exercises any handler's OUTPUT CONTENT**, and there is no `dead_handler_…` among the 9
    traversal tests (they are cfg, complexity, dfg, imports, maintainability, secrets, slice,
    smells, vuln). The right words are "compiles and is plausibly correct" — never "verified".
    **These counts were published wrong once, in `4d3e91c`, as 11 traversal / 2 cache.** They
    summed to 40 against a list of 39 — the arithmetic was the tell, and nobody checked it
    before it was committed. Counting BEFORE bucketing is how a number gets quoted forever with
    its qualifier stripped; the fix is to count the buckets after assigning every item, which
    is what the 9+12+13+3+2 above records. The CONCLUSION never moved — no daemon test touches
    handler output either way — but a wrong count in an authoritative block is inherited as
    fact, which is the whole reason this block exists.
    **Two superseded methods, recorded because the method matters more than the answer.** The
    first pass concluded "no test" from `grep -rn 'files_skipped' crates/tldr-daemon/` → one
    hit: a TOKEN SEARCH standing in for a COVERAGE claim. The second replaced it with
    `--list | grep -iE 'dead|skip|warn'` → empty: better instrument, same class of error, since
    it matches test-function NAMES and a test called `callgraph_excludes_bad_encoding` would be
    invisible. It also suppressed stderr, which is the channel a failed test-target build would
    have used. Both conclusions held; neither method supported them. Reading all 39 names does.
  - **`e83d2b4` added to `implementation-commits`.** It cleared rustc warnings that piece 1's
    own changes introduced, so a future bisect landing there must find this card. `a902ce9` and
    `91812be` stay out: they corrected this card's survey, not the product code.
  - **CORRECTION to the `9dabab1` commit message.** That message asserts "this repo DOES emit
    `filesSkipped` — the MCP test hedges across both spellings". **False.** The wire name is
    snake_case: `DeadCodeReport` has a hand-rolled `Serialize` and `types.rs:2521` emits
    `serialize_field("files_skipped", …)`. The test's `or_else` hedge is the worker being
    defensive about a format it had not checked; I read that defensiveness as evidence about
    the format. History is not rewritten for this — the correction lives here.
  - **Why the daemon suite stays green despite unit 5's bypass — now read at the BODY level.**
    `state::tests::test_cache_invalidation` and `test_get_or_build_call_graph_caches_per_language`
    both build through a STUB closure returning `ProjectCallGraph::new()` — an empty graph they
    hand in themselves — and assert only on `call_graph_cache.len()` and `contains_key`. Neither
    calls a handler; neither inspects graph contents. So the bypass cannot redden them. That is
    measured two ways: the bodies above, and `cargo test -p tldr-daemon` exiting 0 with unit 5's
    modified handler present in the tree.
  - **⚠ THE CLAIM "no daemon test exercises any handler's OUTPUT CONTENT" IS FALSE. Retracted
    2026-09-07, one commit after it was written.** `tests/handler_path_traversal_audit_test.rs`
    (423 lines) imports SEVEN handlers directly — `handlers::ast::{imports}`,
    `handlers::flow::{…}`, `handlers::quality::{…}` — calls them against a real `DaemonState`,
    and inspects the returned `Json<Value>` with a recursive `json_contains_substring` helper
    plus a `files_analyzed == 0` assertion. That is output-content testing, by any reading.
    **What survives is the NARROW claim, and it is the one that mattered all along: no daemon
    test touches the `dead` handler.** That file has ZERO references to `callgraph` or `dead`
    (the `dead` handler lives in `handlers::callgraph`, which nothing imports), and the
    both-spellings `files_skipped` grep found nothing outside the implementation line.
    **Established by `grep -rniE 'callgraph|dead'` over all four test files** — case-insensitive,
    no character-class guard. Six hits: five are `ProjectCallGraph` in
    `val004_cache_oncecell_test.rs`, every one of them `ProjectCallGraph::new()` handed to
    `get_or_build_call_graph` as an empty stub (the same shape as the two `state::tests` cache
    tests); the sixth is the English phrase `// not kept as dead weight` in a comment. **No test
    references the `dead` handler, `handlers::callgraph`, or `DeadCodeReport.**
    **Two earlier versions of this check were wrong in the same direction, and the second was
    committed as an "enumeration".** v1 ran on ONE file with `[^_a-z]dead` — a guard requiring a
    preceding character. v2 (`c377b3b`) ran on all four but as `grep -rnw 'dead\|callgraph\|
    DeadCode'`, and reported "exactly one hit". That was FALSE: `-w` cannot match `callgraph`
    inside `ProjectCallGraph`, and case-sensitivity blocked it independently, so five real
    references were invisible. **The lesson is about pattern DIRECTION, not pattern quality:**
    both guards existed to suppress false positives, on a question where a false NEGATIVE is the
    dangerous outcome. When missing a hit is the risk, widen the pattern and read the noise.
  - **The same commit made the same error a second way: a FILTERED READ published as an
    enumeration.** `c377b3b` claimed all twelve `message_tests` bodies had been read; 8 of them
    had been piped through `grep 'fn \|use \|assert\|r#"'`, which drops every line not matching
    those four patterns — including the one line that would reveal a call into daemon code.
    Re-read raw, the claim holds. **A filter is not a read.** Both defects in that commit share
    one cause: choosing an instrument that suppresses what would falsify you, on a question
    where being falsified is the useful outcome.
    **How the false version got committed:** I dismissed this file because the other traversal
    file's names end `_rejects_absolute_path_outside_project`, so "traversal tests assert
    rejection" — reasoning from ONE file's naming pattern to a differently-named file I had not
    opened. It was the highest-`handlers::`-count file of the four and the likeliest falsifier,
    and I read two `state::` bodies a reviewer handed me instead of the one file whose name said
    *audit*. Ninth instance this session of a proxy standing in for the thing.
  - **This file is the TEMPLATE for the test unit 5 is missing.** It shows the working shape:
    build a `DaemonState` over a tempdir, call the handler function directly with its request
    struct, assert on the returned JSON. Whoever implements the daemon decision below should
    copy that pattern rather than invent one.
  - Superseded support for the retracted claim, kept because the method is the lesson:
    `crates/tldr-daemon/tests/` holds FOUR files (`daemon_tests.rs`,
    `handler_path_traversal_audit_test.rs`, `path_traversal_test.rs`,
    `val004_cache_oncecell_test.rs`), and `grep -c 'handlers::\|handle_'` over them gives
    0 / 3 / 1 / 0 — only the two path-traversal files reference a handler at all, and those
    assert REJECTION. The 12 `message_tests::*` and the cache tests reference handlers zero
    times, so they cannot assert on handler output. `server::tests::test_daemon_response_ok`
    and `_error` looked like the strongest counterexample (named for responses) and are not:
    they construct a literal `DaemonResponse::ok("pong")` and assert the ENVELOPE serializes
    with `status`/`result` — the response type, never a handler.
  - **The test-file inventory was wrong twice, in the same direction.** Both this session and a
    review fork stated `tests/` holds TWO files. It holds four. The two-file figure came from
    reading the TAIL of `cargo test` output, which shows only the last targets — a truncated
    view taken for the whole. The fork then inherited the error from this card and built its
    closing argument on it, which is how a wrong fact in an authoritative block propagates:
    the reviewer checks the reasoning, not the premise.
  - **Bucket membership, since the counts above are precise numbers over categories that were
    never defined:** buckets are by MODULE PATH (`message_tests::`, `state::`/`server::`/
    `socket_tests::`, `daemon_performance_tests::`, top-level) EXCEPT "traversal", which is
    semantic — the 9 names ending `_handler_rejects_absolute_path_outside_project`. Under a
    SUBJECT taxonomy "cache" would be 5, not 3, because `state::tests::test_cache_invalidation`
    and `test_get_or_build_call_graph_caches_per_language` are cache tests filed by path. Both
    taxonomies are defensible; mixing them without saying so is not. The counts are DECORATION
    on the output-content claim either way — a module path neither supports nor refutes a claim
    about what an assertion checks.
- **Open decision blocking the daemon half (USER):** it currently bypasses the shared call-graph
  cache (`get_or_build_call_graph`) to obtain the warnings, so daemon `dead` would rebuild the
  graph per request. The daemon's stated purpose is that cache; **the cost of bypassing it is
  UNMEASURED** — an earlier note in this session quoted "~35×" from a module header in
  `commands/dead.rs:4`, which nobody measured. Struck. The lazy alternative nobody has costed:
  cache the warnings alongside the graph and keep the cache. Either way the daemon half needs a
  test before it can claim what the MCP half claims.
- **Loose end, recorded so it is not later promoted to a fact:** `.janitor/logs/heartbeat-fires.log`
  attributes recent fires to session `s:2612dd24` while this session's task paths sit under
  `c9d26272`. Unexplained; not chased; nothing depends on it.
- **Tests:** `crates/tldr-core/tests/encoding_skip_tests.rs` +2 (smells, calls over the
  BKALIK1B fixtures: warning names each of the 5 wide files, none of the 3 readable ones, and
  for `calls` the dropped files are absent from `ir.files`). New
  `crates/tldr-cli/tests/skipped_file_warning_tests.rs` (5): dead/calls/smells JSON name exactly
  the 5, dead text prints them, and the card's measured scenario — a UTF-16 `caller.py` — now
  yields a warning naming the caller. Each CLI test pins `TLDR_DAEMON_REGISTRY_DIR` to an empty
  tempdir so a live daemon cannot serve a cached pre-fix payload.
- **Still open on this card:** the 56-site SILENT inventory decisions, the `File::open` /
  `read_to_end` bucketing, and the daemon/MCP/todo/bugbot channels above.
- Split out of TRDD-BKALIK1B, which fixed a REPRODUCED instance (a wide-encoded file analysed as
  zero symbols) and should close on that. This card carries the larger, different problem it
  exposed: **a skip that nobody is told about.**
- Nothing here is speculative. The skipping already happens and is already correct; what is
  missing is the message. Measured inventory below.

## Why

`tldr dead` over a tree containing one unreadable file returns a dead-code report computed over
a **silently smaller file set**, and exits 0.

That is not a lesser bug than a wrong answer — it *is* a wrong answer, in the shape that does the
most damage. Dead-code detection is whole-program by nature: a function is dead only if *nothing*
references it. Dropping a file removes its references, so a function referenced **only** from the
dropped file is now reported as dead.

**MEASURED, not argued** (2026-09-06). Two directories, identical file contents, encoding the only
variable. `lib.py` defines `used_only_from_utf16()` and `genuinely_dead()`; `caller.py` imports and
calls the first.

| `caller.py` encoding | `tldr dead` → `possibly_dead` |
|---|---|
| UTF-16 (skipped by the guard) | `used_only_from_utf16`, `genuinely_dead` ← **FALSE POSITIVE** |
| UTF-8 (control) | `caller`, `genuinely_dead` |

With the caller readable, `used_only_from_utf16` correctly drops off the list. With the caller
skipped, a live function is reported as possibly dead and is **indistinguishable from the
genuinely dead one** — and `warnings` is `None`, so nothing hints that a file was omitted.

**Whether this counts as a `dead` bug turns on what `possibly_dead` means, so it was settled from
the CODE, not from a doc comment.** The objection to answer: maybe `possibly_dead` is the
tool's hedge for "uncalled, but my analysis may have been incomplete" — in which case listing the
function is self-consistent and calling it a false positive is a category error.
It is not that. `analysis/dead.rs:133` splits the two buckets on **`is_public` alone**:
public-and-uncalled → `possibly_dead`, private-and-uncalled → `dead_functions`. The in-code
comment says "may be API surface". So "possibly" qualifies WHY an uncalled public function might
be legitimate, and carries no claim about analysis confidence. The module contract
(`dead.rs:3`) is likewise unqualified: *"Find functions that are never called"*.

**Being fair to the other reading, because it changes where the fix belongs.** Any static
analyser can only compute "uncalled *within what it read*" — that much is inherent, and blaming
`dead` for it would be unreasonable. So the actionable defect is NOT that `dead` computed the
wrong answer over its input; it is that **the input set was silently reduced and the report says
nothing about it.** Both readings agree on that, which is why it lives on this card and not on a
`dead`-specific one. What the measurement establishes is the CONSEQUENCE: the reduction is not
harmless bookkeeping, it changes a user-visible verdict about a real function.

Honest scoping, and the semantics were CHECKED rather than assumed — the hedge does not excuse it.
`types.rs:2454` documents `possibly_dead` as *"Public/exported but uncalled (may be API surface)"*.
The hedge is about INTENT — a public function may be uncalled on purpose. It is not a hedge about
whether the tool might have MISSED a call. `used_only_from_utf16` is genuinely called, so listing
it there is wrong against the field's own documented meaning, not merely unhelpful. It lands in
the softer of the two tiers (`dead_functions` is the harder claim), and the user still has no way
to learn a file was dropped. `calls` has the same property — a missing file means missing
edges, so the call graph is confidently incomplete.

Verified 2026-09-06 (TRDD-BKALIK1B's probes): `dead`, `calls` and `smells` DO reach the encoding
guard and correctly exclude an unreadable file — and none of them surfaces a warning naming it.
`structure`, `secure` and `vuln` already do, through `files_skipped` + `warnings`, so the pattern
to copy exists in-tree.

## What

Two pieces, in order:

1. **Make the commands that already skip say so.** `dead`, `calls`, `smells` reach the guard and
   drop the file; they need the `files_skipped` + `warnings` treatment `structure` already has.
   Smallest useful change, and it fixes the most dangerous instance first.
2. **The SILENT read-site inventory: 56 production sites.** Full list in
   `reports/encoding-survey/*-CORRECTED-production-only.md`. Each discards a read error and skips
   the file with no user-visible message. Decide per site whether the right behaviour is
   skip-with-a-warning or propagate — most sit inside directory walks, where aborting the whole
   command over one bad file would be wrong, so a warning is the likely answer.

Counts to trust, and the ones NOT to: the corrected survey reads **56 SILENT · 0 PANIC ·
94 PROPAGATED · 4 WARNED** (154 production sites). **The PANIC bucket is EMPTY** — all 24
`.unwrap()`s on a read are test code. An earlier survey said 25 production panics; it classified
by path alone and counted `#[cfg(test)]` code as production. Do not go fixing those.

**BUT 56 IS NOT THE READ SURFACE — it is the `read_to_string`-shaped part of it.** The survey
searched for `read_to_string` only, so reads through other primitives were never bucketed at all.
`File::open` (read-only in Rust; `File::create`/`OpenOptions` are the write paths) plus
`read_to_end` / `.read(&mut …)` account for the rest.

**Deliberately stated as a SCOPE claim and not a defect count.** Nobody has bucketed those sites
into silent/warned/propagated, and many will be reading config, caches or reports rather than
source. Quoting a number here as "N more silent sites" would repeat precisely the error this
card's parent made three times (25 production panics; 176 call sites; the single chokepoint).
The order of work is: bucket them, THEN count.

> **Methodology trap, because it corrupted this very figure.** An **unquoted** `--include=*.rs`
> does NOT filter — the shell eats it, and the grep silently searches every file type. My first
> count of these sites was 33 and included hits from a `.md` design document; quoted, it is 31.
> The same unquoted form inflates a `read_to_string` count from 204 to 207. **Always quote
> `--include='*.rs'`,** and treat any inventory built without it as an upper bound.
One example of why the bucketing needs judgment rather than a sweep: `is_binary_file`
(`metrics/file_utils.rs:304`) handles a read failure as `Err(_) => false` — an unreadable file is
treated as "not binary". That LOOKS like this card's defect, and it may instead be deliberate:
returning `false` lets the downstream read produce the real, specific error rather than
mislabelling the file as binary here. **Not established either way; assess in context.**

## Acceptance

- [x] `tldr dead`, `tldr calls` and `tldr smells` over a directory containing an unreadable file
      name that file in a user-visible warning, as `structure` does. — landed 2026-09-06, see
      STATE; verified by `skipped_file_warning_tests` against the built binary.
- [x] A regression test covers at least one whole-program command (`dead`) against
      `design/reproducers/TRDD-BKALIK1B/`, asserting the warning is present — not merely that the
      file is absent from the results, which is what the buggy behaviour also produces.
      — `dead_json_names_every_skipped_file` + the UTF-16-caller scenario test.
- [ ] Every one of the 56 SILENT sites has a recorded decision: warn, propagate, or
      deliberately-silent-with-a-reason.
- [x] The `File::open` / `read_to_end` / `.read(&mut …)` sites the survey never saw are bucketed
      the same way — count them AFTER bucketing, not before.
      — DONE 2026-09-08. Report:
      `reports/encoding-survey/20260908_103909+0200-file-open-read-to-end-bucketing.md`.
      **8 production sites: PROPAGATED 6 · SILENT 2 · WARNED 0 · PANIC 0.** The
      non-`read_to_string` read surface is far smaller than the 56, and it adds
      **zero new instances of this card's defect**.
      **Both SILENT sites verified FIRST-HAND, not taken from the report** — they are
      `metrics/file_utils.rs:315` and `:318`, both inside `is_binary_file`, and both are
      **deliberately-silent-with-a-reason**, which is one of the three permitted decisions:
      (1) `fn is_binary_file(path: &Path) -> bool` has NO channel to report an error, so the
      silence is structural, not a discarded error on a skip path; and (2) the direction is
      the safe one — `Err(_) => false` means "not binary", so the file is NOT dropped HERE.
      Returning `true` on error is what would have been this card's defect.
      **VERIFIED: (1) and (2), by reading the function.**
      **NOT VERIFIED, and explicitly not claimed:** that the file then "proceeds to the real
      read, which surfaces the actual error". That is a CALLER-level claim and no caller was
      traced. Asserting it would repeat this card's own retraction, where `todo`'s skip list
      was declared silent from a grep scoped to one function while the `eprintln!` sat in the
      caller 200 lines up. An absence inside a function I chose is not an absence in the
      program — and neither is a presence.
- [ ] **NEW, opened by that survey: `is_binary_file` is DUPLICATED with a divergent error
      contract.** `encoding.rs:356` is `fn is_binary_file(path: &Path) -> Result<bool,
      TldrError>` (PROPAGATES); `metrics/file_utils.rs:304` is `fn is_binary_file(path:
      &Path) -> bool` (SILENT). Two functions, same name, opposite error contracts. The
      `encoding_base_tests.rs` suite calls the `Result` one (`is_binary_file(..).unwrap()`);
      the `bool` one's production callers are UNTRACED — `metrics/loc.rs:34` imports from
      `file_utils` but whether it imports THIS symbol was not checked.
      Decide: unify on the propagating contract, or record why two must coexist. Until then
      the SILENT count of 2 is honest about the sites but silent about the duplication,
      which is the more interesting defect.
- [ ] The skip path is centralised, so a NEW command cannot silently drop a file without
      inheriting the warning.
      — PARTIAL: the MESSAGE is centralised (`fs::skipped_file_warning`, used by structure,
      dead, smells, calls). The DECISION to warn still lives at each `Err` arm; a new command
      that writes `if let Ok(..)` is not stopped by anything. Left open on purpose — a walk
      helper that owns the error arm would be the real mechanism.
      — This replaces an earlier line, "no command returns a result computed over a reduced file
      set without saying so", which was **unfalsifiable**: it quantified over all commands, all
      inputs and all future code, so nothing could ever discharge it and it would have been
      ticked on vibes or never. Same defect as the unfalsifiable standard caught on
      TRDD-MWLIUB72. Centralisation is the mechanism that actually generalises the guarantee, and
      it is checkable.

## Why the complexity warning is not this one

`run_dead_analysis`'s unconditional `eprintln!` was once deleted as apparent duplication of the
complexity analysis's `Warning: skipping <path> due to parse error`
(`tldr-core/src/quality/complexity.rs:235`), which fires for the same fixture files. It is not
duplication, and this is the worked mechanism the code comment points at — kept here rather than
in the comment so the line numbers can be corrected without touching source.

Both analyses reach files through the SAME walker: `walk_project` is just
`ProjectWalker::new(root).iter()` (`tldr-core/src/walker.rs:388`). They filter it differently, and
the sets come apart on at least two shapes:

- **`.h` under a C++ scan.** The dead analysis gates on `language.scan_extensions()`, which lists
  `.h` for `Cpp` (`types.rs:154`), so the header is scanned. Complexity gates on
  `Language::from_path`, whose `from_extension` arm reads `".c" | ".h" => Some(Language::C)`
  (`types.rs:183`) — read directly, not inferred from `from_path_with_siblings`'s doc comment. Its
  `d == l` test therefore fails `C != Cpp` and drops the file.
- **`.d.ts` under a TypeScript scan.** The dead analysis skips it via
  `is_typescript_declaration_file`. The walker's `default_ignore` filters DIRECTORIES only
  (`walker.rs:245`), so it does not drop the file on complexity's side. That is a claim about the
  walker's default ignore, not a survey of every filter in complexity's path.

**Not established, deliberately:** whether the two error sources are distinct. Complexity errs
through `calculate_all_complexities_file` / `extract_file`; the dead analysis errs through
`parse_file`. Whether those share a parser underneath has not been read, so no claim is made — an
earlier version of the code comment asserted "a different error source" while that question sat
unread on its own not-read list.

## Notes

The one methodological trap this work will hit, learned the hard way on the parent card: **a
file's absence from a command's output is not evidence about WHY it is absent.** It is equally
consistent with "skipped by the guard", "skipped by `is_binary_file`", and "read fine but parsed
to nothing". Distinguishing them needs a probe whose candidate explanations predict OPPOSITE
observations — e.g. a NUL at offset 1928, which is past the encoding guard's 1024-byte prefix but
inside `is_binary_file`'s 8 KB sample. Three successive probes were needed on the parent card
before one actually discriminated.

## Approval log

- 2026-09-06T04:58:43+0200 — Filed by the session Claude, split from TRDD-BKALIK1B on the reasoning
  that the parent had established its defect and fixed it, while "every skip is announced" is a
  larger piece of work with its own 56-site inventory. Keeping both on one card would mean the
  parent never closes and its acceptance keeps being rewritten. Filing only; no code changed.
- 2026-09-07T20:05:00+0200 — `min-approval-requirement: user` carries no written trigger here. The
  likely one is this card's own scope: it changed report shapes across the CLI, the daemon handler
  (`6d43608`) and the MCP tool (`9dabab1`). Confirm that in a line here, or lower the floor. Noted
  because the child TRDD-K3XQ7M2V was briefly raised to `user` on the strength of this card's floor
  alone, with no trigger anyone could name — that raise was reverted.
