---
trdd-id: YM857S4Y
title: Wall-clock test thresholds fail under load or in debug builds
column: todo
created: 2026-09-10T14:24:17+0200
updated: 2026-09-10T14:24:17+0200
current-owner: session-claude
task-type: bugfix
scope: project
min-approval-requirement: none
labels: [test-defect, wall-clock, benchmarks, flaky]
---

# Wall-clock test thresholds fail under load or in debug builds

## Symptom

Several tests assert a hard millisecond or microsecond budget against a
wall-clock measurement. They pass on an idle machine in the profile their
author used and fail otherwise — under parallel build load, or in a debug
build. A red from one of these says nothing about the code under test, which
is what makes them expensive: every occurrence has to be re-diagnosed by hand
before it can be dismissed.

## The two buckets, and they are kept separate deliberately

They look identical in a test log — a timing assertion, a number over budget —
and they have different fixes. Merging them is how the debug-calibration
instances get "fixed" by re-running until green, and how the load-sensitive
ones get "fixed" by inflating a threshold that was correct.

### (a) Load-sensitive — the measurement is right, the machine was busy

| instance | observed | note |
|---|---|---|
| `cli_tests::test_cold_start_performance` | "Cold start took 1818ms, expected <1000ms" | failed ONCE under 7-worker parallel build load 2026-09-10; **PASSED in the 2026-09-10 workspace gate** (`cli_tests` 16 passed / 0 failed, `test_cold_start_performance ... ok`) |
| `l2_ir_cost_bench_05_taint` | 153.8 ms in the gate against a 100 ms budget | **green in isolation on the same tree**: 21.9 ms on an isolated re-run. Discriminated first-hand, not assumed |

Both are reproducible only by reproducing the load, and both recover without
any code change. The honest description is that the budget is calibrated for
an idle machine and the suite does not run on one.

### (b) Debug-calibration — the latency is real, the budget was set in release

| instance | observed | note |
|---|---|---|
| l2 reader p99 | 32356.5 us at n=250, 2026-09-08 | real tail latency **under a debug build**, not a percentile-degeneracy artifact |

This one is explicitly NOT the `n <= 100` degeneracy TRDD-Y3J6F7ZV fixed. That
card corrected `p99_us()` to a nearest-rank percentile and raised the writer
site past n=100; at n=250 the statistic is already non-degenerate, so the
number is a genuine measurement of a debug binary. Recording that distinction
is the point of this bucket — an earlier reading of this failure as "the p99
bug again" would have closed it with a fix that does not apply.

## What this card must decide, not assume

For each bucket, on evidence, with the reason recorded:

- **(a)** — serialize the affected tests, gate them behind a feature/`#[ignore]`
  so they run deliberately rather than in every workspace run, or drop the hard
  budget for a relative one. Inflating the threshold until the busiest observed
  run fits is the tempting answer and the worst one: it makes the assertion
  unable to fail.
- **(b)** — either calibrate the budget per profile (`cfg!(debug_assertions)`)
  or run the bench in release only. Do not retune a release budget to fit a
  debug number; that silently weakens the release assertion, which is the one
  anybody cares about.

## Acceptance

- [ ] Every instance above is reproduced or refuted at HEAD, and the bucket it
      belongs to is confirmed by that run — not inherited from this card.
- [ ] Bucket (a) has one mechanism applied to all its instances, with the
      reason recorded. No threshold is raised to fit an observed failure.
- [ ] Bucket (b) has its budget made profile-aware or its bench made
      release-only, with the release budget unchanged.
- [ ] Red-proofed: each changed assertion is observed FAILING under a
      deliberate mutation before being accepted as passing. A timing assertion
      that cannot fail is the defect this card is about.
- [ ] The whole workspace run is re-run twice back to back and neither run
      reports any instance listed here.

## Relationships

- TRDD-Y3J6F7ZV — fixed the `p99_us()` degeneracy for `n <= 100`. Bucket (b)'s
  reader instance is what remained after that fix, and is a different
  mechanism. Cite it; do not re-open it.
- TRDD-A9CD09BA — the sibling `p99_us()` card (empty-samples vacuity,
  nearest-rank). Same file, same helper, also not this card's mechanism.
- TRDD-6CKB3RRH — same family (timing assertions that do not measure what they
  name), different mechanism. Cite it, never a verdict about it.
- TRDD-2U7D9PNS — the unfiltered tldr-cli run. The l2_ir instance shows up
  there too.

## Notes
