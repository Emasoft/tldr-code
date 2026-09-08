---
trdd-id: A9CD09BA
title: p99_us returns 0.0 on empty samples and is identically max for n at or under 100
column: todo
created: 2026-09-08T15:01:09+0200
updated: 2026-09-08T15:05:00+0200
current-owner: main-session
task-type: bugfix
scope: project
min-approval-requirement: none
---

# p99_us returns 0.0 on empty samples and is identically max for n at or under 100

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-08 15:01

Nothing implemented. Two defects in one helper, both read first-hand in the
source. Neither has been mapped to the tests that consume it.

**The call-site measurement LANDED (2026-09-08 15:03)** — report:
`reports/integration-failure-set/20260908_150341+0200-verify-semantic-and-p99-callsites.md`.
Five call sites, all with statically determinable literal `n`. **Defect 2 is
NOT hypothetical: two sites sit in the degenerate range.** Table in box 1.

**NEXT ACTION:** box 2 (close the vacuity by construction). That is the defect
worth fixing first — see §Verified for why it is worse than defect 2.

**Do not inherit:** any claim about *which* tests are affected. See
§Not established. In particular this card does NOT assert that the bench
failures discussed elsewhere this session touch `p99_us` at all — at HEAD
with `--test-threads=1`, `l2_daemon_cache_bench_test` was measured **passing**
(12 passed, 0 failed), so the "4 bench_* failures" premise did not reproduce.
These defects are established from the code, not from any failing run.

## Symptom

`p99_us()` is the percentile helper behind the latency assertions in
`crates/tldr-cli/tests/l2_daemon_cache_bench_test.rs`. As written it can report
a passing number for a benchmark that measured nothing, and for small sample
counts it does not compute a 99th percentile at all — it returns the maximum
under a name that claims otherwise.

Source, read first-hand (≈ lines 210-232):

```rust
fn p99_us(&self) -> f64 {
    if self.samples.is_empty() {
        return 0.0;
    }
    let mut sorted = self.samples.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((sorted.len() as f64) * 0.99) as usize;
    sorted[idx.min(sorted.len() - 1)]
}
```

## Verified

**1. Vacuity — empty samples report success.**
`return 0.0` on an empty vector. `0.0 < threshold` holds for every positive
threshold, so any assertion of the form `p99 < LIMIT` passes when the benchmark
collected zero samples. A collection loop that never ran, exited early, or
silently dropped every measurement is indistinguishable from a fast one. This
is a property of the helper alone and needs no call-site knowledge.

This is the worse of the two defects: truncation (defect 2) makes an assertion
*stricter* than advertised, which fails safe. Vacuity makes it *unfalsifiable*.

**2. Degeneracy — p99 is identically the maximum for every n ≤ 100.**
`as usize` truncates toward zero, so `idx == floor(0.99 * n)`. Arithmetic,
checked by hand:

| n | `0.99 * n` | `idx` | last index (`n-1`) | idx == last? |
|---|---|---|---|---|
| 50 | 49.5 | 49 | 49 | yes |
| 100 | 99.0 | 99 | 99 | yes |
| 101 | 99.99 | 99 | 100 | no |

So for all n ≤ 100 the function returns `sorted[n-1]` — the maximum. It becomes
a genuine percentile only at n ≥ 101. A single outlier therefore sets the
reported "p99" outright at small n, which is the opposite of why a percentile
is chosen.

**3. `idx.min(sorted.len() - 1)` is dead code.**
`floor(0.99n) < n` for every n ≥ 1, so `idx` is always already a valid index and
the clamp never binds. Not a bug on its own; noted because it reads as a guard
and so discourages looking at the truncation above it.

## Not established — do not inherit these as facts

- **The `n` values in box 1 are RELAYED, not first-hand.** What I read myself is
  the two ASSERTION sites (`:805` and `:1092`, quoted verbatim in box 1). The
  sample counts come from a worker that read the filling loops; I did not open
  those loops. The `n ≤ 100` classification therefore rests on relayed numbers —
  confirm them before acting on box 4. The two assertions themselves are
  first-hand.
- **Whether any assertion has ever actually passed vacuously.** Defect 1 is a
  latent capability, demonstrated from the code. No run has been observed
  passing on zero samples.
- **The status of `warm_query`, `persistence`, `call_graph`.** An agent dismissed
  these as "passes in release, therefore a debug artifact, therefore no card".
  That inference is unsound on its own terms and is independent of this helper:
  a debug-miscalibrated threshold, a real performance bug masked by
  optimization, and a concurrency bug whose window closes under release timing
  all produce the same observation. This card neither adopts nor refutes it.

## Scope

`p99_us()` in `crates/tldr-cli/tests/l2_daemon_cache_bench_test.rs` and whatever
its call sites turn out to be. Test-side only — no production code is
implicated, and no other percentile helper has been surveyed for the same shape.

Out of scope: the thresholds themselves (whether a limit is correctly calibrated
is separate from whether the statistic is computed correctly), and the
debug-vs-release behaviour of any test.

## Acceptance

- [x] **1. Call-site map, from the source.** Done 2026-09-08. All five sites in
      `crates/tldr-cli/tests/l2_daemon_cache_bench_test.rs`, every `n` a
      statically determinable literal (no duration-driven or config-derived
      loop bound):

      | site | n | n ≤ 100? | defect 2 bites |
      |---|---|---|---|
      | `:244` (generic/helper use) | — | — | see report |
      | `:280`, `:282` | 1000 | no | no |
      | `:325`, `:327` | 1000 | no | no |
      | `:805` (readers), `:808` (writer) | 250 / 50 | writer: **yes** | **writer site** |
      | `:1092`-`:1095` | 100 | **yes** | **yes** |

      The two assertions, read first-hand:
      `:805` → `stats.p99_us() < 10_000.0` ("p99 exceeds 10ms under contention"),
      inside `for (role, handle) in handles` so it runs once per thread;
      `:1092` → `lookup_stats.p99_us() < 50_000.0` ("Full-scale lookup p99
      exceeds 50ms"). Both are exactly the `p99 < LIMIT` shape defect 1
      defeats. Report:
      `reports/integration-failure-set/20260908_150341+0200-verify-semantic-and-p99-callsites.md`
- [ ] **2. Vacuity is closed by construction, not by assertion.** An empty
      `samples` vector cannot yield a value that satisfies a `<` threshold — the
      helper panics, returns an error the caller must handle, or an explicit
      non-empty precondition is enforced at every call site found in box 1.
      Demonstrated by a check that FAILS if the empty case is made to pass
      silently again: construct the empty-sample state and show the assertion
      path does not report success. A test that merely calls `p99_us()` on a
      populated vector and passes does NOT satisfy this box.
- [ ] **3. The percentile is a percentile, evidenced at a boundary.** The index
      computation is corrected (rounding rule chosen and stated — e.g.
      nearest-rank `ceil(0.99n) - 1`), and correctness is shown at the boundary
      the current code gets wrong: for a constructed sample set of size n ≤ 100
      with a single planted outlier at the maximum, the returned value is NOT
      the outlier. A check that passes equally against the old truncating
      implementation does NOT satisfy this box.
- [ ] **4. Real-`n` impact stated.** Using the box-1 table, state for each call
      site whether it fell in the degenerate range (n ≤ 100) and whether the
      corrected statistic changes that site's pass/fail outcome. If an assertion
      flips to failing, that is a separate finding to card — it is not fixed by
      adjusting the threshold under this card.
- [ ] **5. No sibling left behind.** The file is searched for other percentile or
      aggregate helpers sharing either shape (empty-returns-zero, or truncating
      index arithmetic); each listed with `file:line` and either fixed here or
      carded, with the reason for the split stated.
