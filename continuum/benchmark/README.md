# tldr Ground-Truth Benchmark

This directory contains the m2 benchmark corpus. It includes vendored PyCG micro-benchmarks, hand-written CATS-style suites, and sampled real-repo LSP truth sets.

## Add a language suite

Create `suites/LANGUAGE/FEATURE/CASE`. Keep each case tiny, add the source files, then add `truth.json` using `schemas/truth.schema.json` and `meta.json` with the feature, entrypoints, defect class, and any `negative_edges` needed for precision. Every truth edge and negative edge must carry provenance.

## Add a real-repo truth set

Do not vendor repository source into this tree. Add the language/repo to `languages.json`, place or refresh the source checkout under `$HOME/.tldr-audit/corpora`, then run `harvest_lsp.py` to produce the source-free manifest, metadata, truth, raw LSP cache, and harvest report under `repos/`.

## Schema reference

`truth.json` uses `truth.v1`: each edge has `src_file`, `src_func`, `src_line`, `dst_file`, `dst_func`, `dst_line`, `kind`, and `provenance`. `meta.json` can define `negative_edges` for false-positive checks and `expected_unresolved` entries for known undecidable cases.

## Current corpus

- `vendored/pycg/cases/`: upstream PyCG micro-benchmark call graphs converted into `truth.v1`; Apache-2.0 `LICENCE` preserved.
- `suites/python/`: 15 hand-written Python micro-cases covering direct calls, import forms, receiver and class resolution, constructors, same-name disambiguation, builtin shadowing, decorators, local scope collisions, `@overload` cohesion behavior, and an expected-unresolved higher-order callback.
- `suites/typescript/`: 12 hand-written TypeScript micro-cases covering relative imports, index files, type-only import distinction, class and inherited methods, constructors, same-name disambiguation, builtin-name shadowing, dynamic import as expected-unresolved, and await/generic member calls.
- `suites/go/`: 12 hand-written Go micro-cases covering package imports and aliases, receiver methods, interface dispatch as expected-unresolved, factory construction, same-name packages, builtin-name shadowing, embedded inherited methods, reflection as expected-unresolved, and index-expression receivers.
- `suites/rust/`: 12 hand-written Rust micro-cases covering module and `crate::` paths, `use` aliases, inherent impls, trait methods, dyn trait dispatch as expected-unresolved, out-of-line impls, constructors, same-name modules, std/prelude shadowing, and associated functions.
- `suites/java/`: 12 hand-written Java micro-cases covering package and static imports, class methods, inherited and overridden methods, constructors, overload arity, same-name packages, stdlib-name shadowing, reflection as expected-unresolved, and interface dispatch as expected-unresolved.
- `repos/`: sampled real-repo truth sets for configured Python, TypeScript, Go, Rust, and Java corpora, with raw LSP responses and skip reasons captured in `harvest_report.json`.

For smoke checks, `~/.cargo/bin/tldr calls CASE_DIR --format json` should produce parseable JSON for representative cases.

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

## CI Scoring

Use one command to score an existing `tldr` binary:

```bash
python3 continuum/benchmark/run_truth.py --binary <path> --out report.json
```

On 2026-07-08, the full corpus run over micro-suites plus real-repo truth sets completed in 7.167 seconds on this machine, well below the 15-minute CI warning threshold. Scoring is a no-network operation: it reads committed benchmark fixtures and the already-present real-repo corpus paths recorded in manifests; language servers, package managers, and network access are only needed when harvesting or refreshing truth, not when running `run_truth.py`.

Exit code `0` means the harness validated inputs, completed discovery, and wrote the report. Exit code `2` means harness setup or validation failed, including an empty `--filter` result; individual `tldr` timeouts, nonzero exits, or JSON parse failures are recorded as skipped case results in `report.json` and do not by themselves make the process fail.
