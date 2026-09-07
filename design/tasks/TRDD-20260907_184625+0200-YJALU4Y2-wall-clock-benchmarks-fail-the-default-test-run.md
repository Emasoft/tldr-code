---
trdd-id: YJALU4Y2
title: Three wall-clock benchmarks fail the default cargo test run on a loaded machine
column: todo
created: 2026-09-07T18:46:25+0200
updated: 2026-09-07T19:05:00+0200
current-owner: unassigned
implementation-commits: [127bced]
task-type: bugfix
min-approval-requirement: user
labels: [tests, flaky, benchmarks, mcp]
---

# Three wall-clock benchmarks fail the default cargo test run on a loaded machine

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-07 19:05

### The immediate red is FIXED (127bced). The design question is not.

- **Option 4 applied.** All four benches carry
  `#[cfg_attr(debug_assertions, ignore = "...")]`. `cargo test -p tldr-mcp` exits 0 in debug
  (41 passed, 4 ignored); `cargo test -p tldr-mcp --release --lib bench_` exits 0, so the
  assertions still run where their numbers apply. Nothing was weakened.
- **CORRECTION: FOUR benches, not three.** The title and the body below say three. The fourth is
  `bench_call_tool_cache_hit`. The count came from a single run — counting before bucketing.
  Title left as-is because it is the filename; trust this block.
- **CORRECTION: two categories, not one.** Three identical runs of one command on unmodified code
  failed 3, then 2, then 1 — the failing SET moves, so most are load-sensitive. But
  `bench_cache_key_construction` failed **3 of 3** at 13.4-15.2us against its own <10us limit.
  That one is deterministically miscalibrated for a debug build, not flaky. The body below treats
  all of them as one phenomenon; it is wrong about that.
- **The regression scare, and how it was settled.** A review raised that `9dabab1` (this session's
  own change, in the lib target) enlarged `DeadCodeReport`, so gating a clone-cost bench might
  hide a regression I caused — and correctly noted the card's "unrelated to my work" argument only
  covered the UNCOMMITTED file, not the committed one. Settled by reading `call_tool`:
  `tools/mod.rs:104-107` puts `tldr_dead` in `skip_cache`, so `DeadCodeReport` never enters the L1
  cache, and the bench caches `tldr_structure`/`tldr_tree` anyway. No payload-size path exists.
- **NEXT ACTION, and it is a real decision, not cleanup:** debug now asserts NOTHING about these
  paths. Option 4 traded flakiness for zero debug coverage. Consider either (a) structural
  assertions that do not vary with load — but FIRST check whether the cache stores an `Arc`, since
  `Arc::ptr_eq`/`strong_count` is ~3 lines while allocation counting needs a custom `GlobalAlloc`
  and is the most expensive option on this card, not a middle one; or (b) an honestly-recalibrated
  debug threshold that STATES its basis, which still catches a 10x regression and never flakes.
  Do not raise a number without recording what it was calibrated against — that is what produced
  the current ones.
- Acceptance box 1 says "ten runs in a row" — it must name a PROFILE. Under option 4 it is
  trivially true in debug and untested in release.

## Superseded intake block — 2026-09-07 18:46

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
