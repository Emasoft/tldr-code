# Real-Repo Truth Sets

This directory is intentionally source-free. Each repo directory is a sampled LSP truth case whose source checkout remains in `$HOME/.tldr-audit/corpora`.

```json
{
  "schema_version": "repo-truth-manifest.v1",
  "name": "example-project",
  "language": "python",
  "corpus_path": "$HOME/.tldr-audit/corpora/example-project",
  "commit_sha": "0123456789abcdef0123456789abcdef01234567",
  "truth_files": ["truth.json"]
}
```

`truth.json` uses `truth.v1` and every harvested edge has `lsp-callHierarchy` provenance. `meta.json` records deterministic sampling details, `truth_quality_tier`, `truth_source_type`, LSP errors, skip reasons when applicable, and spot checks for accepted edges. `raw/` caches the LSP JSON-RPC responses used to build the truth set, and `harvest_report.json` summarizes all repo harvest outcomes plus the Flask runtime-trace attempt.
