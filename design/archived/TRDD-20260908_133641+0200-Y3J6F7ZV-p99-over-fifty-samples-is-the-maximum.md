---
trdd-id: Y3J6F7ZV
title: p99_us returns the maximum for any sample count at or below 100 so the writer assertion is a max bound
column: complete
created: 2026-09-08T13:36:41+0200
updated: 2026-09-10T14:28:23+0200
implementation-commits: [ddb3cc1]
current-owner: main-session
task-type: bugfix
scope: project
min-approval-requirement: none
labels: [test-defect, statistics, benchmarks]
---

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-10 09:28

**Repair decided and landed jointly with TRDD-A9CD09BA** (same helper, same file, worked in
one pass to avoid two divergent fixes to `p99_us()`): nearest-rank method
(`rank = ceil(0.99n)`, `idx = rank-1`) replaces the truncating `(n as f64 * 0.99) as usize`,
at `crates/tldr-cli/tests/l2_daemon_cache_bench_test.rs:217-238`. Box 1's "computes a
defensible percentile for small n" was chosen over "change callers" — box 1 also required
stating why both are not equivalent: changing callers (e.g. dropping the assertion, or
switching to `max_us() < LIMIT` with a raised limit) would have hidden the statistical
defect behind a renamed metric instead of fixing the metric; fixing the metric fixes every
call site (5, per A9CD09BA box 1) with one change and keeps the name honest.

**Box 2, honestly not fully satisfied for THIS call site — recorded, not hidden:** the
writer assertion (`:772-810`, n=50) still reduces to a single-worst-sample bound after the
fix, and this is provably unavoidable, not an implementation gap: `ceil(0.99n) == n` for
every n < 100 (`0.01n < 1`), so the true 99th percentile of 50 samples IS the maximum by
definition — no percentile algorithm produces otherwise at that n. Verified against the
fixed code: `bench_concurrent_access_latency` still failed once during verification
(p99==max, 20389.9us, matching this card's own 12277.2us observation and prediction), passed
clean on 5 immediate re-runs (isolated single-target). **This card does not retune the
threshold or change the writer's sample count** — box 1 is satisfied by fixing the
*statistic*; the *threshold-vs-n=50-reality* mismatch this leaves behind is a distinct
decision this card explicitly says both options are "legitimate and not equivalent" for, and
retuning was out of scope for the A9CD09BA card this was co-landed with (its box 4 forbids
threshold adjustment). Flagging for a human/MANAGER call: either accept writer-p99-as-max at
n=50 as the intended (if noisy) bound, or raise `writes_per_thread` well past 100 so a real
percentile applies — a code change this worker's write scope (test file + these two cards
only) does not authorize deciding unilaterally beyond what was asked.

Box 3 (proof the writer assertion no longer reduces to a single-worst-sample bound) is
**NOT satisfied and cannot be, at n=50, by a statistics-only fix** — see above; the
`p99_us_at_n_100_is_not_the_planted_outlier` / `_n_101_` tests added under A9CD09BA prove the
general mechanism is fixed, but the specific writer call site stays a max-bound until its `n`
changes. Left unchecked below.

Box 4 (debug-only reader failure) intentionally not touched — out of scope per the
dispatch that ran this pass; noted here again so it is not silently dropped.

**Follow-up 2026-09-10 09:45 — box 2 CLOSED at the call site.** Coordinator directed fixing
this at the writer call site rather than leaving it as a flagged decision: `writes_per_thread`
raised `50 -> 200` at `l2_daemon_cache_bench_test.rs:800` (was `:800` before, comment added
explaining why — `ceil(0.99n) == n` for every n < 100, so n must cross 100 for the writer's
p99 to stop being the max; picked 200, not the bare minimum 101, for margin). Threshold
(`:805`, `10_000.0`) untouched — this is exactly the "call-site fix, not a threshold retune"
the coordinator specified.

Also added `p99_us_pins_nearest_rank_exact_value` (records `1..=100`, asserts
`p99_us() == 99.0` exactly) — the two prior `assert_ne!(…, max)` tests alone would also pass
against a buggy `sorted[n-2]` or even a median-in-disguise implementation; this test pins the
one value nearest-rank actually produces at n=100.

Verified twice: `cargo test --manifest-path …/Cargo.toml -p tldr-cli --test
l2_daemon_cache_bench_test` -> `test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0
filtered out` (both runs, back to back). `bench_concurrent_access_latency` (the writer/reader
test) passed clean both times post-fix — no flake observed after raising the sample count,
consistent with the writer now computing a real percentile instead of a single-worst-sample
bound.

`bench_concurrent_access_latency` fails **in release, in an isolated single-target run**
(12 tests, 0.30s). No suite-level effect can reach it, which is what separates this card from
TRDD-6CKB3RRH — that one's failure is internal to its suite and clears when the suite is
serialized. **Do not restate that as "thread contention": which internal mechanism it is has
explicitly NOT been discriminated there.**

**Mechanism established by reading the source, not inferred from the numbers:** for any
`n <= 100`, `p99_us()` returns the maximum sample. The writer thread collects `n = 50`, so its
assertion is `max < 10ms` wearing a percentile's name.

**NEXT ACTION: decide the repair** (acceptance box 2). The mechanism is not in question; the
right fix is.

`column: todo` rather than the authoring default `backburner`, following TRDD-6CKB3RRH's
reasoning: a test failing at HEAD is not deferred work.

## Symptom

`bench_concurrent_access_latency` (`crates/tldr-cli/tests/l2_daemon_cache_bench_test.rs:804`)
fails on the **writer** thread:

```
writer thread: n=50, mean=295.5us, median=5.4us, p99=12277.2us, max=12277.2us

panicked at crates/tldr-cli/tests/l2_daemon_cache_bench_test.rs:804:9:
writer thread p99 12277.2us exceeds 10ms under contention
```

`p99` and `max` are the same number to the tenth of a microsecond. That is not a coincidence in
the data; it is forced by the code.

## Mechanism (read at `l2_daemon_cache_bench_test.rs:217-225`)

```rust
fn p99_us(&self) -> f64 {
    if self.samples.is_empty() { return 0.0; }
    let mut sorted = self.samples.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((sorted.len() as f64) * 0.99) as usize;
    sorted[idx.min(sorted.len() - 1)]
}
```

`as usize` **truncates**. For `n = 50`: `50 * 0.99 = 49.5` → `49`, and `49` is the last index of
a 50-element vector, so the function returns the maximum. This generalizes: **for every
`n <= 100`, `(n as f64 * 0.99) as usize == n - 1`**, so `p99_us()` is `max_us()` for any sample
count at or below 100.

The defect is therefore **n-dependent, and both roles run through the same assertion loop**
(`~:800-807`, `stats.p99_us() < 10_000.0`, with `role` only interpolated into the message):

| role | n | index used | last index | p99 == max? | observed |
|---|---|---|---|---|---|
| reader | 250 | 247 | 249 | no — a real near-tail value | p99 712.9us, max 10040.6us |
| writer | 50 | 49 | 49 | **yes, by construction** | p99 12277.2us, max 12277.2us |

`reads_per_thread = 250` and `writes_per_thread = 50` at `:748-749`.

So one 12ms outlier out of 50 writes fails the test against a median of 5.4us. The assertion
cannot do what its message claims — it never measures a 99th percentile for the writer.

## Measured (2026-09-08, HEAD 2d4e7f7, `git status --porcelain` clean)

| condition | result |
|---|---|
| `cargo test --release -p tldr-cli --test l2_daemon_cache_bench_test` | 11 passed, **1 failed** — this test, on the writer |
| same target, debug, inside `--no-fail-fast` | 8 passed, 4 failed — this test failed on a **reader** (p99 32356.5us) |

**The debug reader failure is a DIFFERENT failure and must not be folded into this card's
mechanism.** At `n = 250` the reader's p99 is a genuine percentile (index 247 of 249), so a
reader p99 of 32356.5us is real tail latency under a debug build, not the degeneracy described
here. This card is about the writer.

The other three benches that failed in that debug run — `bench_warm_query_latency_small_payload`,
`bench_persistence_round_trip`, `bench_call_graph_cache_large_payload` — **all pass in release**
and are debug-build artifacts. They need no card. Recorded here so a future reader does not
re-derive them as open failures.

## Not established

- **Whether the writer's 12ms outlier is itself a defect.** The statistics bug is proven; the
  underlying latency is not characterised. A correct percentile might still exceed the bound.
- **Whether any other caller of `p99_us()` is affected.** Only this test's two call sites were
  read. Other benches with `n <= 100` would silently have the same degeneracy, and none were
  surveyed.
- **The failure rate.** Observed once in release. Not repeated, so "flaky" vs "reliable" is
  unknown — do not record it as either.
- **Whether `max_us()` at `:227-229` is used anywhere the two are compared**, which would have
  made the equality visible sooner.

## Acceptance

- [x] `p99_us()` either computes a defensible percentile for small `n`, or its callers are
      changed so no assertion is made on a percentile the sample count cannot support. State
      which was chosen and why; both are legitimate and they are not equivalent.
      Done 2026-09-10 — chose "computes a defensible percentile" (nearest-rank,
      `crates/tldr-cli/tests/l2_daemon_cache_bench_test.rs:236-238`); rationale in STATE block.
- [x] The writer assertion no longer reduces to a single-worst-sample bound. **Closed
      2026-09-10 09:45 per coordinator direction: fixed at the call site**, not by threshold
      retune. `writes_per_thread` raised `50 -> 200` (`:800`), crossing the `n>=100` boundary
      where `ceil(0.99n) < n`. Proven by `p99_us_pins_nearest_rank_exact_value` (exact-value
      pin, `1..=100 -> p99==99.0`) plus the pre-existing `p99_us_at_n_100/101_...` tests
      (`!= max`), all of which fail against the old truncating implementation (see
      A9CD09BA's mutation test). `bench_concurrent_access_latency` verified passing twice in
      a row post-fix (was flaky pre-fix, matching the n=50 mechanism this card describes).
- [x] Every other `p99_us()` call site with `n <= 100` is enumerated and either fixed or
      recorded as deliberate. Done via TRDD-A9CD09BA box 1 (five sites, all read) + box 4
      (per-site n<=100 impact stated) — same table reused here rather than duplicated.
- [x] The debug-only reader failure is either explained or carded separately.
      **Carded as TRDD-YM857S4Y** (2026-09-10), which owns every wall-clock
      instance in this family and keeps two buckets separate: load-sensitive
      failures (daemon cold-start, the l2_ir taint bench) and debug-build
      calibration, of which the reader p99 32356.5 us at n=250 is the instance
      this box was about. It is real tail latency under a debug build, not the
      `n <= 100` degeneracy this card fixed — which is exactly why it is a
      different card and not a loose end on this one.

## Relationships

- TRDD-6CKB3RRH — same family (timing assertions that do not measure what they name), different
  mechanism. **Cite that card, never a verdict about it.** Its failure is internal to its suite
  and clears when serialized; WHICH internal mechanism — CPU contention, shared on-disk state,
  or lock contention among the `tldr` subprocesses — is explicitly undischarged there, and an
  earlier revision of that card overclaimed exactly this and was corrected.
  **This card's separation does not depend on the answer:** the failure here reproduces in an
  isolated release run of one target (12 tests, 0.30s), so no suite-level effect of any kind
  reaches it. Neither card subsumes the other.
- Surfaced while verifying the suite state for TRDD-K3XQ7M2V. Not caused by it —
  `0063e1b` touches `todo.rs`, `types.rs` and its own test file, and not this bench file.
