---
trdd-id: YJALU4Y2
title: Three wall-clock benchmarks fail the default cargo test run on a loaded machine
column: todo
created: 2026-09-07T18:46:25+0200
updated: 2026-09-07T19:21:35+0200
current-owner: unassigned
implementation-commits: [127bced]
task-type: bugfix
min-approval-requirement: user
labels: [tests, flaky, benchmarks, mcp]
---

# Three wall-clock benchmarks fail the default cargo test run on a loaded machine

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-07 18:59

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

**THE DECISION TO MAKE, stated so it can be made:** a threshold denominated in wall-clock time
against a fixed constant cannot be rescued by choosing a better number — the number is in a unit
the test does not control, so machine speed and load move it. Every attempt to save the form by
qualifying the runs with a load ("on a loaded machine", "concurrent cargo builds plus several
subagents") failed because a load is not specifiable: how many builds, on what core count, at what
memory pressure. Two testers get two loads and the same criterion passes or fails at the tester's
discretion. So the choice is between exactly two shapes — **(a) assert the structural property**,
or **(b) assert a RATIO against a reference operation measured in the same process and the same
run**, so both sides degrade together. Pick one, then write the acceptance box against it.

**READ THE CACHE BEFORE COSTING (a) — this card said `Arc::ptr_eq` three times and it is NOT
available.** `L1Cache.entries` is `HashMap<String, CacheEntry>` and `CacheEntry { result:
ToolsCallResult, inserted_at: Instant }` (`cache.rs:18-29`) — an OWNED value, no `Arc` anywhere.
`get()` returns `Option<&ToolsCallResult>` (`cache.rs:48`), a borrow, so `call_tool` clones at the
boundary to hand back an owned result. A clone on that path is therefore real; whether it is what
`bench_call_tool_cache_hit_clone_cost` asserts on is NOT established — only the bench's setup was
read (`tools/mod.rs:1190-1215`: two `call_tool` calls with a `tldr_tree` fallback), never its
assertion. Do not restate the bench's purpose from its name. Consequences: `Arc::ptr_eq`/`strong_count` needs the cache changed to store
`Arc<ToolsCallResult>` FIRST, so (a) is a production change, not a ~3-line test edit — the
expensive option, as this card's STATE block already warned.
**And that reframes the card:** storing an `Arc` would reduce the clone to a refcount increment
rather than assert about it — worth weighing against writing any assertion at all. Note "reduce",
not "delete": whether that is a win depends on `ToolsCallResult`'s size, which is NOT measured, and
changing `get`'s return type has an unenumerated blast radius across its other callers. Those two
unknowns are what actually price option (a); take them before choosing.

**Do not read option 3's ranking wider than it goes.** It is aimed at raising a number and not
saying what it was calibrated against — that is what drifts. A threshold that STATES its basis is a
different proposal and this ranking does not cover it; I applied 4 partly by reusing "3 is worst"
against that different proposal, because the label matched. Judge it on its own merits.

## Acceptance

- [ ] **Debug — what a contributor actually runs:** `cargo test -p tldr-mcp` exits 0. True since
      127bced BECAUSE these four benches do not execute in debug, so this box guards only that the
      gate is still in place: it goes red if the `cfg_attr` is removed. That is worth a box on its
      own — green-for-contributors is the entire user-visible deliverable of 127bced.
      **What carries the red is not yet established — do not trust the split below.**
      `bench_cache_key_construction` failed 3 of 3 (13.4-15.2us vs its <10us limit), so it is
      deterministic in debug. The other three were called "load-sensitive" on this card, but that
      bucket rests on n=3 runs and NO idle run was ever taken — `bench_cache_hit_latency` measured
      1.623us against a 1us limit, 62% over, and was filed as flaky only because it passed once. A
      62% overshoot may be miscalibration that noise occasionally dips under. Settle it by running
      the four alone, `--test-threads=1`, five times before relying on any claim about which of
      them this box actually guards.
- [ ] **The gate is intact in BOTH directions** — checkable today, no decision required. Capture
      to a file, then assert on BOTH the exit status and the test NAMES:
      debug `cargo test -p tldr-mcp > OUT 2>&1` exits 0 and
      `grep -cE '^test .*bench_.* ignored' OUT` is 4; release the same command with `--release`
      exits 0 and that count is 0.
      **Assert on names, not on the summary's `N ignored`:** an unrelated `#[ignore]` anywhere in
      the crate moves that number and would red this box for a reason that has nothing to do with
      these four. **And keep the exit status:** `cargo test ... | grep -q` reports grep's status,
      not the suite's, so a piped-only check passes on a red suite.
      The debug box alone catches only someone stripping the `cfg_attr`. This catches the sneakier
      regression: an unconditional `#[ignore]`, which leaves debug green and silently disables the
      release enforcement too — the profile where these assertions are the only thing guarding
      the paths at all.

**There is deliberately no box for the REDESIGN yet, and that is the point.** Four were written and all four
were unfalsifiable, because an acceptance criterion is defined relative to a CHOSEN option and
`## What` above still says "Not decided". A box cannot encode a decision that has not been made;
every attempt smuggled one into the acceptance section instead. Once the decision exists, the box
names a file, a test and an observable — e.g. `no Duration comparison remains in the four benches:
grep -n 'as_micros\|as_nanos\|elapsed()' crates/tldr-mcp/src/cache.rs returns nothing`. A card
carrying an unfalsifiable box reads as having a gate it does not have, which is worse than
visibly having none.
- [ ] Whatever replaces the wall-clock assertion still FAILS when the property it guards is broken
      — demonstrated by breaking it (e.g. forcing a clone on the cache-hit path), watching it go
      red, and reverting. A threshold that can no longer fail is not a fix.
- [ ] If any wall-clock assertion survives, it states which profile and which machine class it is
      calibrated for, and does not run outside it.

## Evidence

Measurements live here with their date and command, never inside an acceptance box — a count
written into a criterion is falsified by the act of satisfying it, and a stale one makes the card
misreport its own state.

- **2026-09-07 ~19:07 — `cargo test -p tldr-mcp --release` (FULL suite): exit 0.**
  Lib target `45 passed; 0 failed; 0 ignored; 0 filtered out` in 0.31s, plus integration targets
  5/4/3/1/0, all ok. **That the four benches ran is READ, not reasoned** — the run's own test list
  carries `bench_cache_hit_latency ... ok`, `bench_cache_key_construction ... ok`,
  `bench_call_tool_cache_hit ... ok`, `bench_call_tool_cache_hit_clone_cost ... ok`. The
  test-name list is the whole of the evidence and is sufficient alone. **The tempting "45 - 41 = 4"
  arithmetic is NOT a second source** — the 41+4 debug figure is recalled from earlier in the
  session, not re-read, and the two counts are the same test population under two profiles, so the
  subtraction cannot fail unless the debug figure is wrong, which is the very thing it would be
  vouching for. A consistency check wearing the costume of corroboration. Machine was not idle —
  the unit-2 worker ran concurrently. n=1; one pass is not a variance measurement.
- **Not yet taken:** the four benches alone in debug, `--test-threads=1`, five times. That is what
  would settle whether the other three are miscalibrated or merely noisy, which the debug box's
  note currently declines to assert either way.

## Notes

Filed while verifying ledger row 1 of TRDD-O66FM8TN. The failure is unrelated to that work:
the only dirty file was `crates/tldr-mcp/tests/skipped_files_dead_test.rs`, and cargo's `--lib`
target does not compile `tests/`, so it cannot be the cause. `cache.rs` contains no reference to
callgraph.
