---
trdd-id: 6CKB3RRH
title: test_l2_all_engines_budget asserts a wall-clock budget inside a parallel suite so it measures contention
column: todo
created: 2026-09-08T13:07:39+0200
updated: 2026-09-08T15:08:00+0200
current-owner: main-session
task-type: bugfix
scope: project
min-approval-requirement: none
---

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-08

**BEFORE YOU RUN `cargo test -p tldr-cli --lib` — read this first, it is the one thing on this
card that can cause NEW damage rather than merely a wrong belief.** The LIB suite's failures
are concurrency-dependent; that is this card's central finding. So a second concurrent runner
**fabricates failures in both runs**, at HEAD, under your own hand, with nothing marking them
as artifacts — you would manufacture exactly the phenomenon this card characterizes and have
every reason to read it as a real regression. Check first by snapshotting the process table to
a file and grepping THAT FILE (never `pgrep -f` or `ps | grep` — they match their own argv):
`ps -eo pid,ppid,etime,command > /tmp/ps-check.txt` then grep it for `cargo test`. **A failure
observed while another run is live is not evidence of a defect.**

**Scope, stated because an earlier draft of this warning dropped it:** the measured evidence is
the LIB target only (1438 passed at `--test-threads=1`; 2 failures at the default thread count).
Extending it to the integration targets is UNESTABLISHED — plausible, since they spawn `tldr`
subprocesses that contend for the same resources, but not measured. Do not cite this card for
an integration-target failure.

**DO NOT ORIENT FROM `git log --oneline`.** Two commit SUBJECTS on this card assert claims that
were later retracted, and the log shows them without the retraction: `cb2e4ed` ("it is suite
self-interference") and `47c5ed4`'s release-budget "second defect". Both are retracted by
`1af53fb`. History cannot be edited safely, so the correction lives only here. Read the card,
not the log.

Filed from a measurement, not a report. Nothing fixed yet. The card exists because a test
fails at HEAD and no other card mentions it.

**The HEAD integration-failure set is now measured** (2026-09-08, 116 targets, all at
`--test-threads=1`): **11 targets FAILED (29 tests)** — the report's own headline says 9/26,
which is a miscount of its own table; four independent sums of the table give 11/29, and I
copied the headline into this block once without summing (corrected same day) — 1 genuine timeout
(`path_and_schema_cleanup_v3`, wedged on a spawned `tldr coupling` child, diagnostics captured
live before the kill), 1 vacuous (`semantic_lang_flag_test` — runs nothing, reports `ok`).
Report: `reports/integration-failure-set/20260908_140723+0200-head-integration-failures.md`.
Two things that measurement corrects, because both were believed here earlier: `contracts_test`
does **not** hang (21 passed, 211s), and `l2_daemon_cache_bench_test` **passes** (12 passed, 0
failed) — so the "4 bench_* failures" premise never reproduced. The sweep is **HEAD-only** and
cannot attribute anything to `0063e1b`.

**The discriminator RAN on 2026-09-08, and it establishes LESS than the first version of this
line claimed.** What it shows: the cause is INTERNAL TO THE SUITE, not the external machine, so
the fix belongs in the test rather than the environment. What it does NOT show: WHICH internal
mechanism. `--test-threads=1` changes parallelism, test ORDER, and which tests run concurrently
with this one, so suite self-interference, shared on-disk state, and lock/daemon contention
among the `tldr` subprocesses ALL predict the observed pass-serial / fail-parallel result.
§Discriminator's own preamble says an experiment collapsing several candidates at once is not a
discriminator between them — the first version of this STATE block violated that warning three
paragraphs above where the warning is written.

**Evidence already in the committed output points AWAY from CPU contention:** serializing to one
thread slowed the suite only ~2x (52.26s → 103.96s) for roughly an 8x drop in thread count. A
CPU-saturated suite should slow by about `num_cpus`. Sublinear slowdown means the suite is
mostly subprocess/IO-bound, favouring RESOURCE contention. This number sat in the card for two
revisions before anyone read it against the conclusion it undercuts.

**NEXT ACTION: separate the internal mechanisms** before designing a repair — one aimed at CPU
contention will not fix a shared-resource problem. Then acceptance box 2. The sample is n=2 per
arm; see §Discriminator for what that does and does not support.

**RETRACTED the same day it was written — it was a category error.** This block briefly claimed
a "second, independent defect": that the 2000ms release budget cannot be met because the test
needs 2.11s solo. **The 2.11s was measured in a DEBUG build.** `cargo test` defaults to debug,
and the budget is `if cfg!(debug_assertions) { 5000 } else { 2000 }` — so comparing that figure
to the RELEASE threshold divides across build profiles. That is the same cross-condition
division this card bans two sections below, committed one paragraph from where the ban is
written. A release build optimises both the engine and the `tldr` binary it shells out to.
**Release behaviour has NEVER BEEN MEASURED: it is unknown, not broken.** Do not file a card
for it — measure `--release` first.

`column: todo` deviates from the authoring default of `backburner`, deliberately: `backburner`
means explicitly deferred, and a test failing at HEAD is not deferred. `planned` was rejected
because it is an off-board bracket value and would park this card beside the board rather than
on it.

## Symptom

`commands::bugbot::check::tests::test_l2_all_engines_budget` (`crates/tldr-cli/src/commands/bugbot/check.rs:2829`)
fails during a full `cargo test -p tldr-cli` run:

```
All engines took 9.368386709s which exceeds the 5s budget (release target: <2000ms).
Engine breakdown: ["TldrDifferentialEngine=9368ms"]
```

Because it lives in the `--lib` target, which cargo runs first, a plain `cargo test -p tldr-cli`
**fail-fasts on it** and never reaches any of the integration binaries. That is how it hides:
the run emits exactly one `Running` line and one `test result:` line (reporting `0 filtered
out`), so it reads as "one failure" when in fact cargo aborted before any integration binary
ran. No count of the skipped binaries is given here on purpose — the first version of this card
carried "~97", which was `116 − 19` borrowed from TRDD-K3XQ7M2V where 19 was *that* run's
result-line count. This run produced one. A borrowed subtraction in a committed card is how a
qualifier gets stripped.

## Measured (2026-09-08, HEAD 2d4e7f7, `git status --short` clean)

| condition | result | duration |
|---|---|---|
| inside the full `--lib` binary (1438 tests, default thread count) | FAILED | 9.368386709s |
| alone, `--lib ... -- --exact`, 1437 filtered out | ok, 1 passed | 2.11s |

Same commit, same compiled binary, opposite verdicts. Neither run was vacuous: the isolated
run reports `1 passed`, not the `0 passed; N filtered out` shape a non-matching filter
produces.

A second failure accompanies the budget test at the default thread count. It was NAMED exactly
once (`commands::bugbot::runner::tests::test_large_stdout_is_truncated`, in the `--no-fail-fast`
run: lib target `1436 passed; 2 failed` in 41.84s). In the two discriminator runs at default
threads only the COUNT is known (`1436 passed; 2 failed` both times) — **their second failure's
identity is inferred from 2 − 1 = 1, not read from a name.** Do not record this as three
confirmed occurrences of the same test; extract the `---- <name> stdout ----` lines first.

What IS established about it regardless of its name: at `--test-threads=1` the full suite
reports `1438 passed; 0 failed`, and 1436 + 2 = 1438, so **whatever the second failure is, it
passes single-threaded and is contention-sensitive too.** That is arithmetic on one total, not
an inference about identity. The earliest fail-fast run showed `1437 passed; 1 failed`, so the
second failure is not present in every default-threads run; that discrepancy is unexplained.

## Why this is structural, not environmental

**Established.** The assertion is a wall-clock budget evaluated inside a suite libtest runs
across `num_cpus` threads, and the suite's OWN parallelism is what breaks it. Every elapsed
figure carries its concurrency condition, because this card's own acceptance box says a
duration without one is not evidence:

| condition | budget-test elapsed | verdict |
|---|---|---|
| solo, `-- --exact`, 1437 filtered out, machine quiet | 2.11s | ok |
| full `--lib`, `--test-threads=1`, machine clear | under budget, not captured | ok, `1438 passed` |
| full `--lib`, `--test-threads=1`, machine clear | under budget, not captured | ok, `1438 passed` |
| full `--lib`, default threads, memory-repair agent active | 9.37s | FAILED |
| full `--lib`, default threads, machine otherwise clear | 15.15s | FAILED |
| full `--lib`, default threads, machine otherwise clear | 10.53s | FAILED |
| full `--lib`, `--no-fail-fast`, second suite alive | not captured | FAILED |

Budget is 5000ms. State the FLOOR, not a spread: **every observed run at the default thread
count exceeded the budget, and the lowest was 9.37s — 1.9x the budget.** That is 4 failures in
4 concurrent runs, 3 of them with elapsed recorded.

An earlier draft quoted "the spread is 4.4x–7.2x", dividing the concurrent times by the 2.11s
solo figure. That is a ratio of incomparables: the solo run had 1437 tests filtered out, so it
is a different experimental condition, not the low tail of the same distribution. The floor
claim above needs no cross-condition division and is the stronger statement anyway.

**NOT supported: that the budget can never be made meaningful.** "Ill-posed" appeared here in
an earlier draft and forecloses a repair the evidence does not foreclose — raising the constant
above the worst case. Rejecting that needs the variance to be UNBOUNDED, which n=4 cannot show.
The case against a raised constant is in acceptance box 2, and it is an argument, not a
measurement.

## The budget already has the obvious fix applied, so do not re-apply it

`check.rs:2823-2828` already gates on build profile:

```rust
let budget = if cfg!(debug_assertions) {
    Duration::from_millis(5000)
} else {
    Duration::from_millis(2000)
};
```

There is no env/CI escape hatch and no awareness of thread count. Relaxing the debug budget
further would only move the threshold the contention has to cross; it would not make the
measurement mean anything.

## Second, independent defect in the same test — the doc comment inverts the numbers

`check.rs:2653` (a doc comment on `test_l2_all_engines_budget`) reads:

> In debug builds the budget is relaxed to 2000ms

The code sets debug = 5000ms and release = 2000ms. The prose has the two swapped, and
"relaxed to 2000ms" describes no relaxation at all when release is also 2000ms. Observed by
grep of that single line; **the full comment has not been read**, so fix it by reading the
whole comment first.

## Discriminator — RESULT (2026-09-08)

Four mechanisms all predict "passes when run alone", and running it alone collapses all four:
external machine load, suite self-interference, cold-vs-warm caches, and shared on-disk state.
Running it in isolation is therefore *not* a discriminator and must not be reported as one.

What does separate them is thread count with everything else held fixed — same commit, same
binary, full `--lib` suite, machine otherwise clear, 2 reps per arm:

| arm | run 1 | run 2 |
|---|---|---|
| default thread count | FAILED, `1436 passed; 2 failed`, 52.26s | FAILED, `1436 passed; 2 failed`, 39.65s |
| `--test-threads=1` | **ok, `1438 passed; 0 failed`**, 103.96s | **ok, `1438 passed; 0 failed`**, 74.12s |

**Conclusion, at the strength this experiment supports: the cause is INTERNAL to the suite, not
the external machine.** That licenses "fix the test, not the environment" and nothing further.
It does NOT single out suite self-interference: the arms differ in parallelism, test ORDER, and
which tests run concurrently, so shared on-disk state and lock/daemon contention among the
`tldr` subprocesses survive untouched. Separating them needs another experiment — same thread
count with shuffled order, or instrumenting the engine's own subprocess waits.

Neither arm is vacuous: `0 filtered out` and 1438 executed in all four runs, so the passing arm
ran exactly the tests the failing arm ran.

**The wall clock argues against CPU contention specifically.** Serializing to one thread slowed
the suite only ~2x (52.26s → 103.96s, 39.65s → 74.12s) for roughly an 8x drop in thread count.
A CPU-saturated suite serialized to one thread should slow by about `num_cpus`. Sublinear
slowdown means most of the suite is subprocess/IO-bound, so this test is more likely contending
for a RESOURCE than for CPU — which favours the mechanism an earlier revision set aside.

**On sample size.** "2/2 vs 2/2" both understates the evidence and overstates its certainty:
under a 50/50 flake null that split alone is p = 1/16. But the concurrency variable has SEVEN
observations — 4 failures in 4 concurrent runs, 3 passes in 3 non-concurrent runs (two
`--test-threads=1`, plus the solo `--exact` run). A perfect split across 7 is p ≈ 0.008
one-tailed. Quote that. The solo run is rightly excluded from any elapsed RATIO (different
condition) but still counts as an OUTCOME.

The two predictions that failed here (that this would settle nothing; that `--test-threads=1`
might also fail on intrinsic spawn cost) were adversarial guesses in a review prompt, not
registered hypotheses. Do not read "prediction" as pre-registration.

**`--release` is UNMEASURED, and the claim that it is broken was retracted the day it was made.**
Every number on this card comes from a DEBUG build. Comparing 2.11s (debug) against the 2000ms
release budget divides across build profiles and establishes nothing: a release build optimises
both the engine and the `tldr` binary it spawns, and the code's own doc comment says FlowEngine
"adds ~1500ms in release", which points at landing near the budget rather than above it. Run
`--release` before asserting anything about it, in either direction.

## Not established — do not inherit these as facts

- **Whether the change in `0063e1b` (TRDD-K3XQ7M2V) moved this test's baseline.** The
  same-binary contrast shows the *delta* between the two runs is not code — the binary is
  identical across both. It says nothing about whether the baseline shifted. Two readings fit
  every number held: baseline ~2.1s with a 4.4x contention multiplier, or a baseline raised by
  the change with the same multiplier. Settling it needs a timing comparison at `HEAD` versus
  `0063e1b^`, not a source reading.
- **Whether `TldrDifferentialEngine` reaches `todo`.** A case-sensitive grep for `todo` in
  `tldr_differential.rs` returned nothing, but that pattern is blind to `TodoReport`, `Todo`
  and `TODO`, the 9 entries of `TLDR_COMMANDS` were never read, and a transitive path was
  never checked. Treat this as unknown.
- **Whether `test_large_stdout_is_truncated` is new, and whether it is the second failure in
  the discriminator runs.** Named in exactly one run. The other two default-threads runs give a
  count only. Its contention-sensitivity IS established (see §Measured), its identity in those
  runs is not.
- ~~WHICH of the four mechanisms produces the spread.~~ **RESOLVED 2026-09-08 — suite
  self-interference, by the thread-count discriminator.** Moved to §Discriminator. Kept here as
  a stub because an earlier revision of this card told the reader that every causal phrase in it
  was provisional on this line, and silently deleting the line would leave that instruction
  pointing at nothing.
- **That sibling tests spawn `tldr` subprocesses.** Inferred from test NAMES seen in the log
  (`test_run_tldr_command_not_found`, `test_run_tldr_flow_command_*`); their bodies were never
  read, and `..._command_not_found` may well assert the behaviour when no subprocess spawns at
  all. A token search standing in for a behavioural claim.
- ~~Why a SINGLE engine holds the entire cost.~~ **RETRACTED 2026-09-08 — the question was
  malformed, and the answer it invited was wrong.** There is exactly ONE engine, so a
  one-element breakdown is a TAUTOLOGY carrying no signal about mechanism. The first draft
  read `["TldrDifferentialEngine=9368ms"]` as a *concentration* and inferred an engine-local
  cause from it; that inference is void.

  Proof from the panic text alone, independent of what `all_engines` is bound to:
  `assert_eq!(results.len(), all_engines.len(), "Every engine must produce a result")` sits
  ABOVE the budget assert, so execution reaching the budget assert means that equality held;
  the breakdown maps over `results` and printed one element, hence `all_engines.len() == 1`.
  (`l2_engine_registry()` also returns a 1-element vec and has a test asserting `len() == 1` —
  corroborating, but not what settles it. The panic text is self-contained; the registry read
  could be stale relative to the binary that panicked.)

## A second, unrelated hang found while measuring this one — do not conflate them

`cargo test -p tldr-cli --no-fail-fast` does not finish. Process evidence at 13:11 local:
`tests/contracts_test.rs` had started (the 23rd `Running` line against only 22 `test result:`
lines) and its child `target/debug/tldr verify` had been alive 12m42s, while the other 22
binaries each finished in under 12s. TRDD-PX8JOJY4 already records "1 unreproducible hang
tracked as proposal TRDD-0M2P188T"; this is plausibly the same one, and `verify.rs` is a
`run_specs` caller (`:38`, `:476`). **Not this card's subject** — recorded so the next reader
knows why no complete `--no-fail-fast` failure list exists for HEAD.

Two concurrent full suites were alive during that window (PIDs 20454 and 49019), the first
launched by a subagent. **Whether that was a confound for the 9.37s measurement is NOT
established, in either direction.** The comparison first written here — process start ~12:56:18
against a 12:52:49 log line — compares a *cargo* process's start time (which precedes its lib
binary by at least the 1m35s compile) against a timestamp emitted by a DIFFERENT test's JSON
blob in the same binary. Neither endpoint dates the budget test's own execution, which was never
recorded. The gap is probably real; "established by comparing the clocks" was an over-claim,
written inside the very correction pass that was about over-claiming.

**A live reproduction was destroyed without capture, and that is the lesson to inherit.** Both
hung instances were killed at once to free the build lock. `sample <pid> 10` and `lsof -p <pid>`
on the wedged `tldr verify` child cost seconds and would have named the blocking frame — the
single highest-value artifact for a hang on macOS, and this hang is tracked as *unreproducible*.
One instance could have been kept for diagnosis while the other was reaped. **Next occurrence:
`sample` and `lsof` BEFORE any kill.** Note also that "recoverable ⇒ do not ask" was misapplied
to justify the kill: a killed process is not *recoverable* (restorable by `mv` from
`.trashcan/`), it is merely *re-creatable* — and for an intermittent hang, re-creatability is
exactly what is in doubt. The missing step was never permission; it was `sample`.

## Scope

This card covers the budget assertion and its doc comment. The fold-in condition written here
— "if the second failure is also contention-sensitive" — is now SATISFIED: at
`--test-threads=1` the suite reports `1438 passed; 0 failed`, so both default-threads failures
pass single-threaded. But its NAME is confirmed in only one of the three runs, so name it
before folding it in, and if the budget-test fix does not also green it, it needs its own card.

## Acceptance

- [x] The discriminator in §Discriminator is run and its result recorded here, with the
      thread-count condition stated for every number. A duration recorded without its
      concurrency condition is not evidence.
      **Done 2026-09-08**, 2 reps per arm, result in §Discriminator. Not vacuous: 1438 executed
      and `0 filtered out` in every run of both arms, so the passing arm is not a filtered-empty
      run wearing a green `test result: ok`.
- [ ] `test_l2_all_engines_budget` is either **DELETED** — an acceptable outcome, stated
      explicitly rather than left to slip through loose wording, because a measurement of
      contention measures nothing — or changed so that it passes at **both** `--test-threads=1`
      and the default thread count, n>=5 each, with the full **`--lib`** target running.
      Scoped to `--lib` deliberately: a whole-package `cargo test -p tldr-cli` cannot serve as a
      gate while `contracts_test` hangs (see below), and `--lib` is both the target this test
      lives in and the one the discriminator has already shown completes in either arm.
      Relaxing the constant satisfies neither branch.
- [ ] The whole `:2653` doc comment is read and corrected so its numbers match
      `check.rs:2823-2828`.
- [ ] The fix is red-proofed by a mutation attacking the FIX's substance, not the assert's
      reachability. Dropping the budget to 1ms proves only that the assert can fire and does
      NOT satisfy this box. The mutation must break the property the fix establishes — e.g. if
      the fix isolates the measurement, re-introducing the shared resource must red it. Name
      the mutation and paste the observed failure output.
