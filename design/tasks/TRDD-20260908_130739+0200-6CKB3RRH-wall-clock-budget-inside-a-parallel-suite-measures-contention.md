---
trdd-id: 6CKB3RRH
title: test_l2_all_engines_budget asserts a wall-clock budget inside a parallel suite so it measures contention
column: todo
created: 2026-09-08T13:07:39+0200
updated: 2026-09-08T13:14:24+0200
current-owner: main-session
task-type: bugfix
scope: project
min-approval-requirement: none
---

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-08

Filed from a measurement, not a report. Nothing fixed yet. The card exists because a test
fails at HEAD and no other card mentions it.

**NEXT ACTION: run the discriminator in §Discriminator.** Everything below §Measured is
already established; everything in §Not established is not, and must not be inherited as if
it were.

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

A second, heavier full-suite run (`--no-fail-fast`, with other agents active) reported the lib
target at `1436 passed; 2 failed` in 41.84s — the same budget test plus
`commands::bugbot::runner::tests::test_large_stdout_is_truncated`, which appears in no other
run. Whether that second failure belongs on this card or its own is open (see §Scope).

## Why this is structural, not environmental

**Supported:** the assertion is a wall-clock budget evaluated inside a suite libtest runs
across `num_cpus` threads, and the observed spread is 4.4x (n=2 loaded, n=1 quiet). A
wall-clock threshold measured under unspecified concurrency cannot mean the same thing on two
machines or two runs, so the assertion is ill-posed **independently of which mechanism produces
the spread**.

**NOT supported, and must not be read out of this heading: WHICH mechanism produces it.** Four
fit every number held (see §Discriminator) and none has been tested. "Load-flaky" would
understate the problem by making it environmental; "suite self-interference" would overstate
what has been measured. The isolated pass neither exonerates the test nor identifies the cause
— it demonstrates the sensitivity and nothing more.

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

## Discriminator — NEXT ACTION

Four mechanisms all predict "passes when run alone", and running it alone collapses all four:
external machine load, suite self-interference, cold-vs-warm caches, and shared on-disk state.
Running it in isolation is therefore *not* a discriminator and must not be reported as one.

What discriminates:

1. `cargo test -p tldr-cli --lib -- --test-threads=1` versus the default thread count. If it
   passes single-threaded and fails multi-threaded on the same otherwise-idle machine, the
   cause is suite self-interference, and the fix belongs in the test, not the environment.
2. Run it N times in one invocation and read the **distribution**, not a single sample. Every
   number recorded so far is n=1 per condition.
3. `--release`, since the panic text itself cites a release target. That answers whether a
   5s debug budget is meaningful at all.

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
- **Whether `test_large_stdout_is_truncated` is new.** It appeared once, under the heaviest
  observed contention. One sample.
- **WHICH of the four mechanisms produces the spread.** Unresolved until the discriminator
  runs. Every phrase in this card that reads as causal is provisional on it.
- **That sibling tests spawn `tldr` subprocesses.** Inferred from test NAMES seen in the log
  (`test_run_tldr_command_not_found`, `test_run_tldr_flow_command_*`); their bodies were never
  read, and `..._command_not_found` may well assert the behaviour when no subprocess spawns at
  all. A token search standing in for a behavioural claim.
- **Why a SINGLE engine holds the entire cost.** The breakdown is
  `["TldrDifferentialEngine=9368ms"]`. Suite-wide CPU contention would be expected to spread
  across engines; a one-engine concentration is at least as consistent with that engine's own
  subprocess spawning degrading under load — same family, different mechanism, and a different
  fix (the engine's concurrency, not the suite's). This reading was missed in the first draft
  and is not yet tested.

## A second, unrelated hang found while measuring this one — do not conflate them

`cargo test -p tldr-cli --no-fail-fast` does not finish. Process evidence at 13:11 local:
`tests/contracts_test.rs` had started (the 23rd `Running` line against only 22 `test result:`
lines) and its child `target/debug/tldr verify` had been alive 12m42s, while the other 22
binaries each finished in under 12s. TRDD-PX8JOJY4 already records "1 unreproducible hang
tracked as proposal TRDD-0M2P188T"; this is plausibly the same one, and `verify.rs` is a
`run_specs` caller (`:38`, `:476`). **Not this card's subject** — recorded so the next reader
knows why no complete `--no-fail-fast` failure list exists for HEAD.

Two concurrent full suites were alive during that window (PIDs 20454 and 49019), the first
launched by a subagent. It started ~12:56:18; the 9.37s measurement was logged at 12:52:49, so
it was **not** a confound for that number — established by comparing the clocks, not assumed
in either direction.

## Scope

This card covers the budget assertion and its doc comment. If the `HEAD` vs `0063e1b^`
name-set comparison shows `test_large_stdout_is_truncated` is also contention-sensitive, fold
it in here; if it is a genuine regression, it needs its own card.

## Acceptance

- [ ] The discriminator in §Discriminator is run and its result recorded here, with the
      thread-count condition stated for every number. A duration recorded without its
      concurrency condition is not evidence.
- [ ] `test_l2_all_engines_budget` is either **DELETED** — an acceptable outcome, stated
      explicitly rather than left to slip through loose wording, because a measurement of
      contention measures nothing — or changed so that it passes at **both** `--test-threads=1`
      and the default thread count, with the full suite running, n>=5 each. Relaxing the
      constant satisfies neither branch.
- [ ] The whole `:2653` doc comment is read and corrected so its numbers match
      `check.rs:2823-2828`.
- [ ] The fix is red-proofed by a mutation attacking the FIX's substance, not the assert's
      reachability. Dropping the budget to 1ms proves only that the assert can fire and does
      NOT satisfy this box. The mutation must break the property the fix establishes — e.g. if
      the fix isolates the measurement, re-introducing the shared resource must red it. Name
      the mutation and paste the observed failure output.
