# tldr Ground-Truth Benchmark Design

This directory is the m2 ground-truth corpus for measuring absolute precision and recall of `tldr calls` and later command or rung variants. It is fixture data only; VAL-021 owns the scoring harness implementation.

## Directory layout

```text
continuum/benchmark/
  DESIGN.md
  README.md
  languages.json
  harvest_lsp.py
  schemas/truth.schema.json
  suites/LANGUAGE/FEATURE/CASE/
    source files
    truth.json
    meta.json
  vendored/pycg/
    LICENCE
    UPSTREAM.md
    cases/CATEGORY/CASE/
      upstream source files
      upstream README.md when present
      original_callgraph.json
      truth.json
      meta.json
  repos/
    README.md
    harvest_report.json
    REPO/
      manifest.json
      meta.json
      truth.json
      raw/
```

`suites/LANGUAGE/FEATURE/CASE` contains CATS-style micro-cases: tiny projects with one behavior under test. `vendored/pycg/` contains the upstream PyCG micro-benchmark suite converted into the same case format with its Apache-2.0 license preserved. `repos/` contains manifest-driven real-repo sampled truth sets; real repository sources are not vendored here and are referenced from `$HOME/.tldr-audit/corpora`.

## Truth edge schema

The canonical schema is `schemas/truth.schema.json`. Each `truth.json` has:

```json
{
  "schema_version": "truth.v1",
  "case_id": "suites/python/direct_call/basic_direct",
  "language": "python",
  "edge_model": "static-callgraph",
  "notes": "Human-readable source audit note.",
  "edges": [
    {
      "src_file": "main.py",
      "src_func": "main.run",
      "src_line": null,
      "dst_file": "main.py",
      "dst_func": "main.helper",
      "dst_line": null,
      "kind": "call",
      "provenance": {
        "source": "manual",
        "tool": "human-audited-source",
        "version": "VAL-020a",
        "harvested_at": "2026-07-08",
        "tier": "T0",
        "staleness": "source-local; update only when case source changes"
      }
    }
  ]
}
```

Every edge must carry its own `provenance`. Allowed provenance sources are `manual`, `lsp-callHierarchy`, `runtime-trace`, and `vendored-pycg`. The schema is forward-compatible with the m3 tier model by allowing `tier` values `T0`, `T1`, and `T2`, plus staleness notes and optional content hashes.

Edge fields are `src_file`, `src_func`, optional `src_line`, `dst_file`, `dst_func`, optional `dst_line`, `kind` (`call`, `method`, or `constructor`), and `provenance`. `confidence_note` is available for source-audit nuance without weakening the provenance requirement.

## Case format

A micro-case directory contains source files, `truth.json`, and `meta.json`. `meta.json` is harness-facing metadata with `case_id`, `language`, `feature`, `defect_class`, `description`, `entrypoints`, and optional `negative_edges`.

`negative_edges` are precision fixtures: edges a resolver must not report. They use the same provenance-bearing edge shape, plus a `reason`. Cases may also include `expected_unresolved` for currently-undecidable truths, such as higher-order callbacks where the conservative benchmark should not demand recall until value-flow support exists.

## Real-repo truth sets

Real-repo suites live under `repos/` as source-free sampled truth cases. `languages.json` is the registry for language server command, corpus repos, truth source type, and truth quality tier; adding another LSP-backed language should be a registry change rather than a harness code change. `harvest_lsp.py` reads that registry, samples call sites deterministically by sorted path/declaration/call-site order, calls LSP `prepareCallHierarchy` and `outgoingCalls`, and writes `manifest.json`, `meta.json`, `truth.json`, cached raw LSP responses under `raw/`, and a top-level `harvest_report.json`.

Each repo `manifest.json` pins the corpus path, corpus commit, language, LSP command/version, truth files, and truth quality tier. The source checkout belongs in `$HOME/.tldr-audit/corpora/NAME`, keeping benchmark data small and reviewable.

## Harness interface sketch

VAL-021 should iterate cases, run `tldr calls CASE_DIR --format json`, normalize reported edges to this schema, and compare against `truth.json` plus `meta.json` negative edges. The output should include per-language, per-command, and per-rung precision and recall, with separate counts for matched truth edges, missed truth edges, reported negative edges, unexpected extras, and `expected_unresolved` exclusions. The harness should accept a case root, an optional language filter, and a JSON output path; it should not mutate case fixtures.

## Scoring

`run_truth.py` implements `harness.v2` scoring. The schema is backward-compatible with the `harness.v1` count and metric fields, but adds command-scoped results for `definition`, `impact`, and `dead`. `tldr calls` is scored for the full corpus; `definition`, `impact`, and `dead` are scored only on micro-suites because sampled real-repo truth is incomplete and would make impact/dead recall unsound.

For `calls`, the comparable edge key is `src_file`, `src_func`, `dst_file`, and `dst_func`; line numbers are ignored. Path separators are normalized to `/`, and Python module prefixes derived from each edge file are stripped from function names, so `main.run` in truth can match `run` from the current `tldr` JSON output.

A true positive is an exact normalized edge match. A false negative is a truth edge that is absent from the normalized reported edge set. A reported edge is a false positive only when it matches a `negative_edges` entry or when it contradicts a covered call by using the same source file/function and destination leaf name with the wrong owner file/function. Reported edges outside truth coverage are counted as `unscored` and excluded from precision rather than treated as false positives by default.

Expected-unresolved entries are converted into forbidden edges for scoring. Reporting the expected-unresolved `missing_edge` is a false positive; not reporting it is a true negative. Current `tldr calls` output does not expose the resolution rung, so every matched or reported edge in the harness report carries `rung: null` and the top-level report has `rung_supported: false`.

For `definition`, the harness derives a query position for each truth edge by locating the destination identifier inside the source function body. It runs `tldr definition FILE LINE COLUMN --project CASE_DIR --format json`, with line numbers 1-indexed and columns 0-indexed to match the CLI contract. A correct result returns `dst_file`, and also `dst_line` when the truth edge provides one; a wrong source location counts as both a false positive and a false negative.

VAL-032 command honesty is scored against default, non-approximate output. For `definition.v2`, a declined T2-only result is treated as no definitive location returned; `approximate_definitions` are recorded in the command output but are not scored as correct definitions unless a future benchmark explicitly opts into `--approximate`.

For `impact`, the harness groups truth edges by destination and runs `tldr impact <dst_func> CASE_DIR --file <dst_file> --format json`. The `--file` filter is the qualification mechanism for same-name collisions. Expected callers are the truth sources that point at that destination; extra reported callers are false positives and missed truth callers are false negatives. `impact.v2` `approximate_callers` are excluded from default scoring; an opt-in `--approximate` benchmark mode would score them as normal callers.

For `dead`, the harness indexes source definitions from the micro-case source and treats functions as expected-dead when they appear in no truth edge as a destination and are not a truth-graph root. If `meta.json` grows an explicit `entry_points` list, those values are used as roots; the existing `entrypoints` field remains a source-file list and is not treated as dead-code root metadata. `tldr dead` is run with the derived root names; reporting a reachable function dead is a false positive, and failing to report an expected-dead function is a false negative. `dead.v2` `possibly_dead` entries are weak-evidence/default-decline output and are not counted as reported dead unless a future benchmark explicitly opts into `--approximate`.
