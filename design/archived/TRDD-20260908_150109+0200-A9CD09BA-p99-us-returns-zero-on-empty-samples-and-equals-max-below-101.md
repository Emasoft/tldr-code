---
trdd-id: A9CD09BA
title: p99_us returns 0.0 on empty samples and is identically max for n at or under 100
column: complete
created: 2026-09-08T15:01:09+0200
updated: 2026-09-10T14:28:23+0200
implementation-commits: [ddb3cc1]
current-owner: main-session
task-type: bugfix
scope: project
min-approval-requirement: none
---

# p99_us returns 0.0 on empty samples and is identically max for n at or under 100

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-10 09:28

**Boxes 1-4 done, box 5 done as a documented survey (not a fix).** Fix landed at
`crates/tldr-cli/tests/l2_daemon_cache_bench_test.rs:217-238` (was 210-225): `p99_us()`
now `assert!`s on empty samples (panics with "zero samples", never returns `0.0`) and
computes a nearest-rank percentile — `rank = ceil(0.99 * n)`, `idx = rank - 1` — instead of
truncating `(n as f64 * 0.99) as usize`. The old `.min(n-1)` clamp (defect 3, dead code) is
gone; nothing replaces it because `saturating_sub(1)` on `rank >= 1` for `n >= 1` cannot
underflow and `ceil(0.99n) <= n` always, so `rank - 1 <= n - 1` by construction — no clamp
needed.

Two new `#[test]` fns at lines ~251-283 (same file, same crate): `p99_us_panics_on_empty_samples`
(`#[should_panic(expected = "zero samples")]`) and `p99_us_at_n_100_is_not_the_planted_outlier`
/ `p99_us_at_n_101_is_not_the_planted_outlier` (100/101 samples, one planted outlier at the
max, assert the returned p99 != the outlier). Mutation check performed and reverted
(2026-09-10): reinstated the old truncating formula, `p99_us_at_n_100_...` failed
(`left: 1000000.0 right: 1000000.0`), `p99_us_at_n_101_...` still passed (n=101 was already
non-degenerate under the old code too) — confirms the n=100 test is the one that actually
exercises the fix. Diffed byte-identical against a pre-mutation backup after revert.

**Box 4 — real-n impact, honest finding:** the writer call site (`:772-810`, n=50) is
**mathematically unfixable by this class of change** — for any n < 100, `ceil(0.99n) == n`
always (`0.01n < 1`), so the nearest-rank p99 of 50 samples IS the max, by definition of the
statistic, not by implementation defect. Confirmed empirically: `bench_concurrent_access_latency`
still fails intermittently post-fix with p99==max (observed 20389.9us on one run, matching the
STATE block's own prediction and Y3J6F7ZV's 12277.2us observation) and passes on immediate
re-runs (5/5 clean after the flaky one, isolated single-target runs) — same shape Y3J6F7ZV
already measured, not introduced by this fix. **Not retuned** — box 4 explicitly forbids
threshold adjustment under this card, and Y3J6F7ZV box 1 already owns "decide the repair" for
that call site. The `:1092` lookup site (n=100) is now non-degenerate (idx 98 of 99, not the
max) and still passes.

Full run `cargo test -p tldr-cli --test l2_daemon_cache_bench_test`: 15/15 passed (12 original
benches + 3 new) at the time this block was written. Report:
`reports/kanban-wave1/20260910_093500+0200-worker4-p99.md` (path may differ slightly by
seconds — see final report timestamp).

**Verified 2026-09-10 by the coordinator, first-hand against
`crates/tldr-cli/tests/l2_daemon_cache_bench_test.rs`, not on the worker's report.** All 5
boxes re-checked. Read in the working tree: the `assert!` on empty samples (`:231`), the
nearest-rank body `let rank = ((n as f64) * 0.99).ceil() as usize; sorted[rank.saturating_sub(1)]`
(`:238-239`), and the tests `p99_us_panics_on_empty_samples` (`:255`),
`p99_us_at_n_100_is_not_the_planted_outlier` (`:261`),
`p99_us_at_n_101_is_not_the_planted_outlier` (`:277`). Whole target re-run: 16 passed / 0
failed, exit 0. **Two facts in the block above have MOVED since it was written, both under
TRDD-Y3J6F7ZV, not under this card:** the writer call site is now `writes_per_thread = 200`
(`:817`), not 50, so it is no longer in the degenerate `n < 100` range; and a fourth test
`p99_us_pins_nearest_rank_exact_value` (`:288`) now pins the exact nearest-rank value at
n=100, which is why the target reports 16 and not 15. The paragraphs above are kept as the
record of what this card established when it landed.

**The call-site measurement LANDED (2026-09-08 15:03)** — report:
`reports/integration-failure-set/20260908_150341+0200-verify-semantic-and-p99-callsites.md`.
Five call sites, all with statically determinable literal `n`. **Defect 2 is
NOT hypothetical: two sites sit in the degenerate range.** Table in box 1.

**NEXT ACTION:** box 2 (close the vacuity by construction). That is the defect
worth fixing first — see §Verified for why it is worse than defect 2.

**Do not inherit:** any claim about *which* tests are affected. See
§Not established. In particular this card does NOT assert that the bench
failures discussed elsewhere this session touch `p99_us` at all — at HEAD
with `--test-threads=1`, `l2_daemon_cache_bench_test` was reported **passing**
(12 passed, 0 failed), so the "4 bench_* failures" premise did not reproduce.
**That passing figure is RELAYED** — it comes from an agent's report I read in
full plus a re-measurement worker, not from a run I performed. The source
defects below ARE first-hand; this one is not, and the two must not be read in
the same register. These defects are established from the code, not from any
failing run.

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

**Both defects degrade the assertion, in opposite directions, and NEITHER is
safe.** An earlier revision of this card said truncation "makes an assertion
stricter, which fails safe" — that is wrong and it was the one line most likely
to steer a fix, so it is corrected here rather than quietly edited. Vacuity makes
the assertion *unfalsifiable*: it cannot fail. Truncation-to-max makes it strict
**and noisy** — a true p99 discards the tail, whereas a max *is* the tail, so at
n ≤ 100 one GC pause or scheduler hiccup sets the reported value outright. That
is the textbook shape of a flaky latency test, and the usual repair for a flaky
latency test is to raise the limit, which permanently weakens the real guarantee.
"Stricter" is not "safer" when the strictness is noise.

The two also compose: if a threshold here was ALREADY loosened to accommodate
max-behaviour, then fixing the truncation shrinks the statistic and leaves an
over-loose limit that now catches nothing. Box 4 must check that direction too,
not only the flip-to-failing one.

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

Two caveats on that table, both of which a fix must respect:

- **The n=100 row is true by IEEE ROUNDING, not by exact arithmetic.** `f64(0.99)`
  is `0.98999999999999999111…`, strictly below 0.99, so the true product is
  ~8.9e-16 under 99.0 — inside half an ULP at that magnitude, so it rounds to
  exactly 99.0 and `as usize` yields 99. Had it rounded the other way the
  boundary would be n ≤ 99. The general claim is still safe (`99n/100` is an
  integer only when `100 | n`; otherwise the fractional part is ≥ 0.01, dwarfing
  ~1e-14 of error), but the exact boundary should not be quoted as if it were
  pure integer arithmetic.
- **n=0 never reaches the index code, and that guard is load-bearing against
  UNDERFLOW, not just vacuity.** `sorted.len() - 1` on an empty vec is
  `0usize - 1`. So a fix that closes defect 1 by simply deleting the early
  return produces a panic — but an underflow/out-of-bounds one with a useless
  message. The fix must be an explicit panic or a `Result`/`Option`, never a
  deletion.

**3. `idx.min(sorted.len() - 1)` is dead code.**
`floor(0.99n) ≤ 0.99n < n` for every n ≥ 1, so `idx ≤ n-1` always and the clamp
never binds. Not a bug on its own; noted because it reads as a guard and so
discourages looking at the truncation above it.

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
- [x] **2. Vacuity is closed by construction, not by assertion.** Done
      2026-09-10. `p99_us()` (`:217-238`) now `assert!(!self.samples.is_empty(), …)`
      before touching the index — an empty vector panics with "p99_us() called
      with zero samples — nothing was measured" instead of returning `0.0`.
      `p99_us_panics_on_empty_samples` (`#[should_panic(expected = "zero
      samples")]`, line ~253) constructs a zero-sample `TimingStats` and calls
      `p99_us()`; it fails if the panic is removed. Chose panic over
      `Option`/`Result` because the caller is always `stats.p99_us() < LIMIT`
      inline in an assertion — a `Result` would need `.unwrap()` at every call
      site anyway, which is the same loud failure with more ceremony; a panic
      makes an empty sample set a hard test failure with zero call-site changes.
- [x] **3. The percentile is a percentile, evidenced at a boundary.** Done
      2026-09-10. Nearest-rank method: `rank = ceil(0.99 * n)`, `idx = rank - 1`
      (`:236-238`). `p99_us_at_n_100_is_not_the_planted_outlier` (100 samples,
      1 outlier at the max) and `p99_us_at_n_101_is_not_the_planted_outlier`
      (101 samples) both assert the returned p99 != the outlier. Mutation-tested
      2026-09-10: reverted to the old truncating formula, ran
      `cargo test … p99_us_at`, the n=100 test FAILED
      (`assertion left != right failed … left: 1000000.0 right: 1000000.0`);
      reverted the mutation, diffed byte-identical against a pre-mutation
      backup, re-ran the full suite green. **Caveat honestly stated, not
      hidden:** for n < 100 the nearest-rank p99 IS the max by definition of
      the statistic (`ceil(0.99n) == n` whenever `0.01n < 1`) — this is not a
      residual bug, it is why the boundary test uses n=100, not n<100.
- [x] **4. Real-`n` impact stated.** Done 2026-09-10 — see STATE block. `:805`
      writer (n=50): still reduces to a single-worst-sample bound after the fix,
      because no percentile algorithm can do otherwise at n=50; assertion still
      intermittently fails on a slow sample (observed once during verification,
      passed 5/5 on immediate re-runs) — same shape Y3J6F7ZV already owns, not
      retuned here. `:805` readers (n=250) and `:1092` (n=100): both now compute
      a real percentile and both still pass.
- [x] **5. No sibling left behind.** Surveyed 2026-09-10, not fixed — kept
      strictly in this card's own declared scope ("no production code
      implicated, and no other percentile helper has been surveyed" was the
      pre-existing scope note; this box asks for the survey, not a fix).
      `mean_us()` (`:196-201`) and `median_us()` (`:203-215`) share the
      empty-returns-`0.0` vacuity shape and both feed `< threshold` assertions
      (`median_us()` at `:275,320,386,482,487,638` — six sites). `max_us()`
      (`:242-244`) folds from `0.0` on empty, same shape, zero call sites use it
      in an assertion (`:245` only, inside `Display::fmt`, not asserted on).
      None of the three share `p99_us()`'s truncating-index shape (defect 2/3) —
      only the vacuity shape (defect 1) — and none is this card's title or
      scope. Recommend a follow-up card for `median_us()` specifically (it has
      live `<`-threshold assertions, unlike `max_us()`); not filed here because
      this worker's write scope is limited to this file and the two cards named
      in its dispatch.
