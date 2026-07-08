# Worker Brief — VAL-020a (m2-benchmark-harness): benchmark corpus design + Python vertical slice

Repo: `/Users/cosimo/Desktop/PatchWork/tldr-code` (cd there for EVERY command). `implement` archetype.
Report `worker_done`. NO source-code (crates/) edits — everything lands under `continuum/benchmark/`.
No parity gate involved (disjoint paths). This is part 1 of assertion VAL-020.

## Context (read these first)
- `continuum/autonomous/precision-program-v1/plan.md` — m2 rationale (absolute precision/recall per language
  per cascade rung; replaces the differential gate's never-worse-only signal).
- `continuum/autonomous/tldr-correctness-audit/CORRECTNESS.md` — the 32 defect classes; each class becomes
  checklist cases.
- `continuum/autonomous/tldr-correctness-audit/GROUND-TRUTH-DESIGN.md` + `RESEARCH-arxiv.md` — prior design
  notes (PyCG/CATS/HeaderGen research).
- Contract text for VAL-020/021 in `continuum/autonomous/precision-program-v1/contract.json`.

## Deliverables (all under continuum/benchmark/)
1. **DESIGN.md** — the corpus + harness architecture:
   - Directory layout: `suites/<language>/<feature>/` micro-cases (CATS-style), `vendored/pycg/` (upstream
     micro-benchmarks, license preserved), `repos/` manifest-driven real-repo truth sets (no vendored repo
     source — manifest pins {git url, commit sha}; corpora live in ~/.tldr-audit/corpora when shared).
   - **Truth-edge schema** (JSON): {src_file, src_func, src_line?, dst_file, dst_func, dst_line?,
     kind: call|method|constructor, provenance: {source: manual|lsp-callHierarchy|runtime-trace|vendored-pycg,
     tool+version?, harvested_at}, confidence_note?}. Schema must carry PROVENANCE ON EVERY EDGE (contract
     requirement) and be forward-compatible with m3's tier model (T0/T1/T2 + staleness).
   - Case format for micro-suites: each case = source files + `truth.json` (expected edges) +
     `meta.json` {language, feature, defect_class (CORRECTNESS.md id where applicable), negative_edges?
     (edges that must NOT be reported — for precision measurement)}.
   - Harness interface sketch (implemented in VAL-021, not now): run `tldr calls --format json` per case,
     match against truth.json, emit per-language/per-command/per-rung precision+recall.
2. **PyCG vendored suite**: fetch the PyCG micro-benchmark suite (github.com/vitsalis/PyCG benchmarks —
   if network fetch fails, document the fallback and construct the equivalent minimal set from its published
   case taxonomy). Convert each case to the case format above (source + truth.json). Preserve upstream
   LICENSE + provenance (source=vendored-pycg).
3. **Python CATS-style suite**: hand-written micro-cases under `suites/python/` covering AT MINIMUM the
   Python-relevant defect classes from CORRECTNESS.md + the resolver features: direct call, import alias,
   from-import, relative import, class method, inherited method, constructor, receiver-type flow,
   nested module dotted call, same-name disambiguation, builtin-shadowing (a project `dict()` — ties to
   VAL-011's test), decorator wrapping, HOF/callback (EXPECTED-UNRESOLVED case: truth marks it undecidable —
   negative edge). Each case tiny (2-4 files), truth.json hand-verified — you ARE the ground truth here,
   so read your own emitted edges skeptically before writing truth.
4. **README.md** — how to add a language suite, how to add a real-repo truth set, schema reference.

## Sanity check (not the full harness)
A throwaway check that `~/.cargo/bin/tldr calls <case-dir> --format json` produces parseable edges for at
least 3 of your Python cases (so the case format is provably consumable). Note results in your report.
Do NOT build the scoring harness (that is VAL-021).

## HARD CONSTRAINTS
- Everything under `continuum/benchmark/`. NO crates/ edits, NO cargo build/test, NO check_parity.py.
- Real PyCG upstream content requires its LICENSE alongside; every vendored case marked source=vendored-pycg.
- Leave UNCOMMITTED. `git status` under continuum/benchmark/ only.

## WHEN DONE report worker_done with
(1) file tree summary (counts per dir), (2) the truth-edge schema as finalized, (3) PyCG vendoring outcome
(fetched vs reconstructed + case count), (4) Python suite case count + which defect classes covered,
(5) the 3-case tldr-consumability sanity result, (6) confirmation nothing outside continuum/benchmark/.
