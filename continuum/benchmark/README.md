# tldr Ground-Truth Benchmark

This directory contains the m2 benchmark corpus. It has two Python sources of truth today: vendored PyCG micro-benchmarks and hand-written CATS-style cases for tldr resolver defect classes.

## Add a language suite

Create `suites/LANGUAGE/FEATURE/CASE`. Keep each case tiny, add the source files, then add `truth.json` using `schemas/truth.schema.json` and `meta.json` with the feature, entrypoints, defect class, and any `negative_edges` needed for precision. Every truth edge and negative edge must carry provenance.

## Add a real-repo truth set

Do not vendor repository source into this tree. Add a manifest under `repos/` pinning the git URL and commit, then place truth data beside the manifest and let the future harness materialize sources under `$HOME/.tldr-audit/corpora`.

## Schema reference

`truth.json` uses `truth.v1`: each edge has `src_file`, `src_func`, `src_line`, `dst_file`, `dst_func`, `dst_line`, `kind`, and `provenance`. `meta.json` can define `negative_edges` for false-positive checks and `expected_unresolved` entries for known undecidable cases.

## Current corpus

- `vendored/pycg/cases/`: upstream PyCG micro-benchmark call graphs converted into `truth.v1`; Apache-2.0 `LICENCE` preserved.
- `suites/python/`: hand-written Python micro-cases covering direct calls, import forms, receiver and class resolution, constructors, same-name disambiguation, builtin shadowing, decorators, local scope collisions, `@overload` cohesion behavior, and an expected-unresolved higher-order callback.

VAL-021 will implement scoring. For now, a smoke check is enough: `~/.cargo/bin/tldr calls CASE_DIR --format json` should produce parseable JSON for representative cases.

## Run the Truth Harness

Run the full corpus:

```bash
python3 continuum/benchmark/run_truth.py --out continuum/benchmark/report.json
```

Run a substring-filtered slice:

```bash
python3 continuum/benchmark/run_truth.py --filter direct_call --out /tmp/tldr-truth-direct-call.json
```

Options are `--binary` for the `tldr` executable path, `--timeout` for the per-case timeout in seconds, `--filter` for case id/path/metadata substring matching, and `--out` for the machine-readable report. The report schema is `harness.v1`; it includes per-case results and aggregates by language, suite group, suite family, defect class, and command.

Scoring uses normalized edge keys (`src_file`, `src_func`, `dst_file`, `dst_func`). Extra reported edges outside truth coverage are `unscored`; false positives are limited to explicit negative-edge matches and wrong-owner contradictions for a covered call. Rung attribution is not available in current `tldr calls` output, so reports set `rung_supported: false`.
