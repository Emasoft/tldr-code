---
trdd-id: YJALU4Y2
title: Three wall-clock benchmarks fail the default cargo test run on a loaded machine
column: backburner
created: 2026-09-07T18:46:25+0200
updated: 2026-09-07T18:46:25+0200
current-owner: unassigned
task-type: bugfix
min-approval-requirement: user
labels: [tests, flaky, benchmarks, mcp]
---

# Three wall-clock benchmarks fail the default cargo test run on a loaded machine

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-07

- **MEASURED, twice, first-hand.** Not inferred from a name or a count. `cargo test -p tldr-mcp`
  exits 101 today on an otherwise-clean tree.
- Found while verifying an unrelated card (TRDD-O66FM8TN). Filed rather than fixed because
  choosing the fix is a judgement about what these tests are FOR, which is not a side effect of
  that card.

## The measurement

`cargo test -p tldr-mcp --lib`, two runs, identical code, nothing else changed:

run 1 — 42 passed, 3 failed
run 2 — 2 passed, 2 failed (filtered to `bench_`)

```
cache::tests::bench_cache_hit_latency            1.623us   threshold <1us    run 1 FAIL, run 2 pass
cache::tests::bench_cache_key_construction      15.152us   threshold <10us   run 1 FAIL
cache::tests::bench_cache_key_construction      13.398us   threshold <10us   run 2 FAIL
tools::tests::bench_call_tool_cache_hit_clone_cost         threshold <15us   both FAIL
```

**The failing SET moves between runs on identical code.** That is the discriminator: a real
regression does not change which tests it breaks from one run to the next; a wall-clock threshold
under varying machine load does. The machine was running cargo builds and several subagents.

## Why this is a defect and not just an unlucky afternoon

The assertions' own comments claim they already account for the debug build:

- `cache.rs:387` — "Release mode: ~128ns. Debug mode: ~400ns. Both well under 1us."
  Measured 1.623us. Four times the comment's debug figure.
- `cache.rs:423` — "Debug mode: ~6us due to unoptimized serde... We allow 10us here to avoid
  flaky failures in debug test builds." Measured 13.4-15.2us. The allowance does not hold.

So the thresholds were calibrated on one machine, in one state, and asserted unconditionally in
the profile `cargo test` uses by default. The comment at `cache.rs:423` shows the author
ANTICIPATED this exact failure and picked a number they believed was safe. It was not.

**The cost is not the red itself.** It is that `cargo test -p tldr-mcp` cannot be used as a gate:
a contributor who runs it sees red that has nothing to do with their change, learns the suite
lies, and stops reading it. A suite that cries wolf is worse than a smaller suite that does not.

## What (not decided)

1. **Make them opt-in** — `#[ignore]` by default, run under an explicit `--ignored` or a bench
   profile. Cheapest, honest: a timing assertion is not a unit test. Loses the regression alarm
   unless something actually runs them.
2. **Assert on operation COUNT or allocation, not wall-clock.** What the tests care about is that
   a cache hit does not clone the payload or rebuild the key; those are structural properties that
   do not vary with load. Highest value, most work.
3. **Raise the thresholds** — the reflex, and the worst option: it is what produced the current
   numbers, it will drift again on the next slower machine, and each raise makes the assertion
   mean less.
4. **Gate on release profile** — `#[cfg(not(debug_assertions))]`, so the numbers are asserted only
   where the comments' figures apply. Small, and it makes the existing thresholds honest.

2 or 4. Do not pick 3 without an argument for why this raise is the last one.

## Acceptance

- [ ] `cargo test -p tldr-mcp` exits 0 on a loaded machine, ten runs in a row, with no code change
      between runs.
- [ ] Whatever replaces the wall-clock assertion still FAILS when the property it guards is broken
      — demonstrated by breaking it (e.g. forcing a clone on the cache-hit path), watching it go
      red, and reverting. A threshold that can no longer fail is not a fix.
- [ ] If any wall-clock assertion survives, it states which profile and which machine class it is
      calibrated for, and does not run outside it.

## Notes

Filed while verifying ledger row 1 of TRDD-O66FM8TN. The failure is unrelated to that work:
the only dirty file was `crates/tldr-mcp/tests/skipped_files_dead_test.rs`, and cargo's `--lib`
target does not compile `tests/`, so it cannot be the cause. `cache.rs` contains no reference to
callgraph.
