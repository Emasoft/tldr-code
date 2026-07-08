# Worker Brief — VAL-032b (m3-honesty-layer): measured per-rung precision + evidence-based re-binning

Repo: `/Users/cosimo/Desktop/PatchWork/tldr-code` (cd there for EVERY command). `implement` archetype.
Report `worker_done` to term_240a1ffa-8d57-44d0-a3f7-d48e784e4c48. TIMEBOXED: one pass; a documented
irreducible-residual is an acceptable outcome. No decision_gates — decisions pre-answered.

## Why
VAL-032 measured that excluding T2 barely moved python impact precision (0.190→0.187: −1 FP, −1 TP) —
the phantom callers ride on T1-BINNED rungs. The user's VAL-030 clause pre-authorizes re-binning:
"re-binning a rung between T1/T2 based on measured precision is allowed with benchmark evidence cited in
the commit — no new schema approval needed." This task produces the evidence and the re-bin.

## Part 1 — per-rung attribution in the harness (also closes VAL-021's rung stub)
`run_truth.py`: calls.v2 edges carry `provenance.rung` — set `rung_supported: true` and aggregate per-rung
TP/FP (+precision) per language across ALL truth cases (micro + pycg + repos), for calls AND for impact
(impact FPs attribute to the rung of the underlying edge — impact.v2 output should carry the edge rung on
each caller; if it doesn't yet, add it, additive). Emit a `by_rung` section in report.json + a table in
BENCHMARK-BASELINE.md.

## Part 2 — evidence-based re-bin
Rule (pre-answered): a rung re-bins T1→T2 iff measured precision < 0.75 on >= 5 scored samples (across
languages; note per-language splits where a rung is fine in one language and bad in another — if the skew
is strong, that is a LanguagePolicy-shaped finding: document it, still re-bin globally only if the global
number fails the rule). Apply as one-line diffs in `tier()` (confidence.rs), each with a comment citing the
measured number. Raw rung stays in provenance regardless (already true).

## Part 3 — re-measure + report
Rebuild release (cargo build --release --bin tldr; do NOT install/codesign — orchestrator owns that), rerun
the harness with target/release/tldr: report python impact P before/after, phantom-caller count on impact
truth cases, overall impact/calls P/R deltas per language, and dead numbers (should be unchanged: 0 FP).
If phantoms remain after the rule-based re-bin, attribute the residual (which rungs, which languages, which
cases) and state plainly whether it is (a) more re-binnable with a different threshold — do NOT re-bin
below the rule, just report — or (b) a resolution-quality issue deferred to m4 scope-substrate.

## HARD CONSTRAINTS
- Code changes ONLY in: confidence.rs (tier match one-liners), impact emit path if rung needs surfacing
  (additive), run_truth.py, BENCHMARK-BASELINE.md, DESIGN.md. Resolution behavior untouched (gate must stay
  byte-identical; orchestrator verifies).
- The re-bin changes DEFAULT impact/definition output composition (more callers become approximate) — that
  is the intended, pre-authorized effect. TDD: extend val032 tests with one case pinning a re-binned rung's
  edge landing in approximate_callers.
- NO regex, NO clippy #[allow]. Leave UNCOMMITTED.

## WHEN DONE report worker_done with
(1) the by_rung precision table (top offenders), (2) rungs re-binned + their measured numbers, (3) python
impact P + phantom count before/after, (4) per-language skews worth a LanguagePolicy follow-up, (5) residual
attribution + disposition, (6) files changed + suite counts.
