---
trdd-id: Y3J6F7ZV
title: p99_us returns the maximum for any sample count at or below 100 so the writer assertion is a max bound
column: todo
created: 2026-09-08T13:36:41+0200
updated: 2026-09-08T13:36:41+0200
current-owner: main-session
task-type: bugfix
scope: project
min-approval-requirement: none
labels: [test-defect, statistics, benchmarks]
---

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-08

Filed from a measurement, not a report. Nothing fixed yet.

`bench_concurrent_access_latency` fails **in release, in an isolated single-target run**
(12 tests, 0.30s). Suite contention cannot explain it, which is what separates this card from
TRDD-6CKB3RRH — that one is suite self-interference and passes at `--test-threads=1`.

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

- [ ] `p99_us()` either computes a defensible percentile for small `n`, or its callers are
      changed so no assertion is made on a percentile the sample count cannot support. State
      which was chosen and why; both are legitimate and they are not equivalent.
- [ ] The writer assertion no longer reduces to a single-worst-sample bound. Proven by a test
      whose PASS depends on the distinction — one that fails against the current
      truncating implementation and passes against the fix, not merely a green suite.
- [ ] Every other `p99_us()` call site with `n <= 100` is enumerated and either fixed or
      recorded as deliberate. A grep for `p99_us` is the floor, not the proof — the sample
      count is set at the call site, so each one must be read.
- [ ] The debug-only reader failure is either explained or carded separately. It is out of
      scope here and must not be closed by this card's fix.

## Relationships

- TRDD-6CKB3RRH — same family (timing assertions that do not measure what they name), different
  mechanism: that card is suite thread contention and clears at `--test-threads=1`; this one
  fails in isolation and is a sample-size defect. Neither subsumes the other.
- Surfaced while verifying the suite state for TRDD-K3XQ7M2V. Not caused by it —
  `0063e1b` touches `todo.rs`, `types.rs` and its own test file, and not this bench file.
