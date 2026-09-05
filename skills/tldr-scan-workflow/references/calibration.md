# Calibration — what this workflow actually cost

Two runs over one Rust workspace (~306K lines in its largest crate) on
2026-09-05. Every number below is copied from TRDD-PX8JOJY4; each row says
whether it was **measured** or is **unmeasured**. Nothing here is estimated —
an unmeasured row stays unmeasured until a run fills it in.

Use these to price a fan-out before launching it, and to decide whether your
pilot batch came in cheap or expensive.

## The table

| measure | value | status |
|---|---|---|
| tokens per landed fix (run 2 only: 36.85M / 186 fixes in its 142 batches) | ~198K | measured |
| scan vs verify transcript size (bytes; the billing split is unmeasured — the tool reports one total) | 201 KB vs 61 KB avg | measured (bytes) / unmeasured (billing) |
| run 1 (grep prompt, stalled mid-run) | 78 scans, 101 fixed / 57 skipped / 119 refuted, 0 verifies | measured; tokens **unmeasured** (the journal has no usage) |
| detection quality | high/critical band sampled and real; the 73 `low \| FIXED` cleanups are unaudited and mostly untested | measured (sample) / unmeasured (the low band) |
| verify verdicts | 350 KEEP, 0 REVERT; at least 2 kept hunks broke ~200 tests | measured |
| cross-file evidence in KEEP lines | 39 of 353 cite a location in a second, distinct file | measured |
| tldr navigation calls vs `sed -n` dumps vs `grep -r` vs `find /` | 191 vs 209 vs 69 vs 13 — every prose ban was violated | measured |
| the 13 `find /` calls | 5 `-maxdepth 0` probes (a worker testing whether `find` is allowed, then walking home anyway), 3 `-maxdepth 6` walks, 5 unbounded hunts for `node-types.json` / `grammar.js` despite the hint | measured |
| run-2 fixed count | 186 FIXED report lines; 189 by worker self-report; the gap is range-style lines (`:431-466`) | measured; the gap is **unresolved** |
| hunks in `git diff` | not counted | unmeasured |
| batches with zero fixes (both runs) | 67 of 220; only 4 entirely in uncompiled `commands/archived/` | measured |
| findings the worker itself refuted | 305 of 768 (40%) | measured |
| pilot (grep prompt, one batch: 4 files, 2825 lines, medium effort) | 158K tokens, 171 s, 27 tool calls, 3 real fixes, 3 refuted, compiled clean, **zero** tldr calls | measured |
| run 2, whole | 143 scan + 153 verify + 1 consolidation agents, 36.9M tokens, 77 min, 0 errors, 185 files edited | measured |
| per-wave `cargo check` + targeted-test time (~9 serialized incremental checks) | — | **unmeasured** — capture it in your pilot wave |
| tokens and finding quality under the hardened tldr-only prompt | — | **unmeasured** — run 2 used the softer wording |
| verify-stage revert rate under the evidence gate | — | **unmeasured** — the old verifier reverted nothing |
| fastedit as the write path | 302 Edit calls in run 2, run 1 uncounted, 0 fastedit in either | **unmeasured** — never exercised, so no comparison exists |

## Reading it

- **Price the run from the pilot, not from this table.** 158K tokens for 2825
  lines is *this* codebase, at medium effort, on a Rust workspace whose
  functions are dense. Your pilot is the number that matters; these are the
  sanity band it should land in.
- **~198K tokens per landed fix is the honest headline**, and it includes the
  40% of findings the workers refuted themselves and the 67 batches that landed
  nothing. Ranking batches by `tldr hotspots` and scanning the long tail last
  is the lever against both.
- **The two failure numbers are the point of the wave gate.** 0 REVERT out of
  350 hunks, and 2 of those hunks broke ~200 tests. A diff reader approves
  almost everything; only a compiler and a test suite disagree with it.
- **`low | FIXED` is the unaudited band.** 73 cleanups landed there with no
  test behind them. Treat a run's low-severity fixes as the part a human should
  actually read.
