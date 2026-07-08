# Real-Repo Truth Set Manifests

This directory is intentionally source-free. A future manifest should pin a real repository without copying it here:

```json
{
  "schema_version": "repo-truth-manifest.v1",
  "name": "example-project",
  "language": "python",
  "git_url": "https://example.invalid/org/project.git",
  "commit": "0123456789abcdef0123456789abcdef01234567",
  "checkout_subdir": ".",
  "corpus_cache": "$HOME/.tldr-audit/corpora/example-project/0123456789abcdef0123456789abcdef01234567",
  "truth_files": ["truth.json"]
}
```

The VAL-021 harness should materialize sources in the cache, then load truth edges from this directory.
