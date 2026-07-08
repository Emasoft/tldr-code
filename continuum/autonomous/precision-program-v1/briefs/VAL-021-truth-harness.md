# Worker Brief — VAL-021 (m2-benchmark-harness): the truth harness

Repo: `/Users/cosimo/Desktop/PatchWork/tldr-code` (cd there for EVERY command). `implement` archetype.
Report `worker_done`. Everything lands under `continuum/benchmark/` — NO crates/ edits, no parity gate.

## Context
- `continuum/benchmark/DESIGN.md` — the corpus architecture + your harness interface sketch (VAL-020a, committed 2c48f9c).
- `continuum/benchmark/schemas/truth.schema.json` — truth.v1.
- 134 truth/meta case pairs live under `suites/python/` + `vendored/pycg/cases/`.
- Contract VAL-021: "Harness computes precision AND recall per language, per command (calls/impact/
  definition/dead), and per resolution rung, emitting a machine-readable report."

## Deliverable: `continuum/benchmark/run_truth.py` (stdlib-only Python 3; no pip deps)
1. **Case discovery**: walk `suites/` + `vendored/*/cases/`, load truth.json + meta.json, validate against
   truth.v1 (fail loudly on schema drift).
2. **Execution**: per case run `~/.cargo/bin/tldr calls <case-dir> --format json` (binary path via
   `--binary`, default ~/.cargo/bin/tldr; timeout per case, default 30s; TLDR_NO_DAEMON=1 env).
3. **Matching**: normalize tldr edges and truth edges to a comparable key (src_file, src_func, dst_file,
   dst_func — module-qualification differences documented + handled deterministically; line numbers ignored
   when truth has null). Compute per case: true-positives, false-negatives (missed truth edges),
   false-positives. IMPORTANT precision semantics: a reported edge is a false positive ONLY if it (a) matches
   a negative_edge, or (b) contradicts truth for a call-site truth covers (same src_func+dst_func name but
   wrong owner file). Extra edges truth doesn't mention (imports of stdlib, etc.) are counted separately as
   "unscored" — document this in the report schema so precision is honest, not vacuously low.
4. **Expected-unresolved cases**: truth cases whose meta marks undecidable/negative-only: reporting the
   forbidden edge = false positive; not reporting = true negative.
5. **Aggregation**: precision, recall, F1 — per language, per suite-family (feature dir), per defect_class,
   and totals; per command starting with `calls` ONLY (impact/definition/dead are follow-ups — structure the
   report so more commands slot in; note them as not-yet-run, do NOT fake them).
6. **Per-rung attribution (forward-hook)**: `tldr calls` output does not yet expose the resolution rung —
   emit `rung: null` per matched edge with a `rung_supported: false` flag in the report (m3's provenance
   field will fill this). Do NOT hack rung detection.
7. **Report**: `--out report.json` machine-readable {schema: harness.v1, binary_sha, corpus_commit,
   per_case[], aggregates{}} + a compact human table to stdout. Deterministic ordering.
8. **CLI**: `python3 continuum/benchmark/run_truth.py [--binary path] [--filter substring] [--out path]`
   documented in benchmark README (append a section).

## Acceptance (run it for real; put results in your report)
- Full run over all 134 cases completes; no crashes; runtime + per-case timeout stats reported.
- Filter run (`--filter direct_call`) works.
- Report validates as JSON; aggregates present for python.
- Numbers are whatever they are — do NOT tune matching to flatter tldr. If recall on pycg cases is low,
  that IS the measurement (they cover dynamic features tldr doesn't claim yet).

## HARD CONSTRAINTS
- Only continuum/benchmark/** (run_truth.py, README section, optionally schemas/harness.schema.json).
- Stdlib-only python3. No cargo, no crates/, no check_parity.py. Leave UNCOMMITTED.
- Matching semantics DOCUMENTED in DESIGN.md (append a "Scoring" section) — the honesty of these numbers
  is the whole point of m2; when in doubt score AGAINST tldr and note the ambiguity.

## WHEN DONE report worker_done with
(1) files changed, (2) the matching/scoring rules as implemented (short), (3) full-run aggregate numbers
(python suite vs pycg vendored, P/R/F1), (4) runtime, (5) any cases skipped + why, (6) confirmation nothing
outside continuum/benchmark/.
