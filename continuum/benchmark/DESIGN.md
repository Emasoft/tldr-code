# tldr Ground-Truth Benchmark Design

This directory is the m2 ground-truth corpus for measuring absolute precision and recall of `tldr calls` and later command or rung variants. It is fixture data only; VAL-021 owns the scoring harness implementation.

## Directory layout

```text
continuum/benchmark/
  DESIGN.md
  README.md
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
```

`suites/LANGUAGE/FEATURE/CASE` contains CATS-style micro-cases: tiny projects with one behavior under test. `vendored/pycg/` contains the upstream PyCG micro-benchmark suite converted into the same case format with its Apache-2.0 license preserved. `repos/` is reserved for manifest-driven real-repo truth sets; real repository sources are not vendored here and should be checked out into a shared cache such as `$HOME/.tldr-audit/corpora` by a future harness.

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

Real-repo suites live under `repos/` as manifests only. A manifest pins `name`, `language`, `git_url`, `commit`, `checkout_subdir`, `truth_files`, and optional corpus cache hints. The source checkout belongs in `$HOME/.tldr-audit/corpora/NAME/COMMIT` so benchmark data remains small and reviewable.

## Harness interface sketch

VAL-021 should iterate cases, run `tldr calls CASE_DIR --format json`, normalize reported edges to this schema, and compare against `truth.json` plus `meta.json` negative edges. The output should include per-language, per-command, and per-rung precision and recall, with separate counts for matched truth edges, missed truth edges, reported negative edges, unexpected extras, and `expected_unresolved` exclusions. The harness should accept a case root, an optional language filter, and a JSON output path; it should not mutate case fixtures.
