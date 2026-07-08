# Benchmark Baseline

Measured on 2026-07-08, this is the corpus-backed replacement for the earlier audit shorthand that `tldr calls` was roughly 80% correct. The full `harness.v2` run produced combined command-result P/R/F1 = 0.689/0.294/0.413 across 739 command results, but the meaningful baseline is command-scoped: calls covers the full corpus, while definition/impact/dead cover micro-suites only.

## Provenance

- Corpus commit: `f20cc75976992f1dd2c705c7ae99569e3df6769c`.
- Scored checkout: `f20cc75`.
- Binary: `/Users/cosimo/.cargo/bin/tldr`.
- Binary version: `tldr 0.4.1`.
- Binary SHA-256: `998ca698926405ee3fa51c021d01be4daa77bbec4efde7ee2dd50c8f95848cff`.
- Command: `python3 continuum/benchmark/run_truth.py --binary "$HOME/.cargo/bin/tldr" --out continuum/benchmark/report.json`.
- Report: `continuum/benchmark/report.json` (`harness.v2`).
- Runtime: 14.827 seconds wall time.
- Case scope: 193 discovered cases; 182 micro-cases receive definition/impact/dead scoring.
- Result scope: 739 command result rows.
- Skips: none.

## Truth-Case Review

The flagged `suites/python/class_method/inherited_method` fixture was corrected before this baseline to the documented definer convention. Its truth points at `Base.run` in `base.py`, and the fixture source defines `run` on `Base` instead of modeling an inherited call as `Child.run` in `child.py`.

The remaining hand-written inheritance, promotion, and override cases were swept for the same receiver-class-vs-definer issue. One case was fixed in the corpus history, and no other hand-written case needed a definer-convention change: TypeScript, Java, and Go inherited/promoted fixtures already point at the defining type, while override fixtures intentionally point at the overriding method and use negative edges where the base method would be wrong.

## Calls: Hand-Written Micro-Suites

| Language | Truth tier | Cases | TP | FN | FP | Unscored | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Python | T1 | 15 | 14 | 3 | 0 | 3 | 1.000 | 0.824 | 0.903 |
| TypeScript | T1 | 12 | 10 | 2 | 1 | 0 | 0.909 | 0.833 | 0.870 |
| Go | T1 | 12 | 12 | 3 | 0 | 1 | 1.000 | 0.800 | 0.889 |
| Rust | T1 | 12 | 8 | 4 | 0 | 0 | 1.000 | 0.667 | 0.800 |
| Java | T1 | 12 | 7 | 4 | 1 | 3 | 0.875 | 0.636 | 0.737 |

## Calls: PyCG Dynamic Suite

| Suite | Truth tier | Cases | TP | FN | FP | Unscored | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PyCG vendored Python micro-benchmarks | T1 | 119 | 14 | 250 | 2 | 29 | 0.875 | 0.053 | 0.100 |

## Calls: Real-Repo Truth Sets

| Language | Truth tier | Cases | Truth edges | TP | FN | FP | Unscored | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Python repos | T1, T2 | 3 | 303 | 17 | 286 | 2 | 1024 | 0.895 | 0.056 | 0.106 |
| TypeScript repos | T1 | 2 | 15 | 0 | 15 | 11 | 924 | 0.000 | 0.000 | - |
| Go repos | T1 | 2 | 205 | 98 | 107 | 56 | 2186 | 0.636 | 0.478 | 0.546 |
| Rust repos | T1 | 2 | 0 | 0 | 0 | 0 | 9227 | - | - | - |
| Java repos | T1 | 2 | 94 | 0 | 94 | 0 | 3249 | - | 0.000 | - |

## Definition: Micro-Suites

| Language | Cases | TP | FN | FP | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Python | 134 | 192 | 89 | 3 | 0.985 | 0.683 | 0.807 |
| TypeScript | 12 | 11 | 1 | 1 | 0.917 | 0.917 | 0.917 |
| Go | 12 | 15 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Rust | 12 | 11 | 1 | 0 | 1.000 | 0.917 | 0.957 |
| Java | 12 | 11 | 0 | 0 | 1.000 | 1.000 | 1.000 |

Definition queries are derived by locating the destination identifier in the source function span and running `tldr definition FILE LINE COLUMN --project CASE_DIR --format json`. Returned locations must match `dst_file`, and `dst_line` when present.

## Impact: Micro-Suites

| Language | Cases | TP | FN | FP | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Python | 134 | 32 | 249 | 136 | 0.190 | 0.114 | 0.143 |
| TypeScript | 12 | 10 | 2 | 1 | 0.909 | 0.833 | 0.870 |
| Go | 12 | 12 | 3 | 1 | 0.923 | 0.800 | 0.857 |
| Rust | 12 | 8 | 4 | 0 | 1.000 | 0.667 | 0.800 |
| Java | 12 | 7 | 4 | 1 | 0.875 | 0.636 | 0.737 |

Impact queries group truth by destination and run `tldr impact <dst_func> CASE_DIR --file <dst_file> --format json`. The `--file` filter is used as the same-name collision qualifier.

## Dead: Micro-Suites

| Language | Cases | TP | FN | FP | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Python | 134 | 1 | 36 | 3 | 0.250 | 0.027 | 0.049 |
| TypeScript | 12 | 1 | 4 | 2 | 0.333 | 0.200 | 0.250 |
| Go | 12 | 0 | 3 | 0 | - | 0.000 | - |
| Rust | 12 | 0 | 10 | 0 | - | 0.000 | - |
| Java | 12 | 1 | 5 | 1 | 0.500 | 0.167 | 0.250 |

Expected-dead is derived from source definitions: a function is expected dead when it appears in no truth edge as `dst` and is not a truth-graph root. The existing `entrypoints` metadata field is a source-file list; only a future explicit `entry_points` field overrides dead roots.

## Real-Repo Detail

| Repo | Truth tier | Cases | Truth edges | TP | FN | FP | Unscored | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `repos/python-flask` | T1, T2 | 2 | 234 | 7 | 227 | 1 | 314 | 0.875 | 0.030 | 0.058 |
| `repos/python-requests` | T1 | 1 | 69 | 10 | 59 | 1 | 710 | 0.909 | 0.145 | 0.250 |
| `repos/typescript-axios` | T1 | 1 | 2 | 0 | 2 | 0 | 835 | - | 0.000 | - |
| `repos/typescript-nest` | T1 | 1 | 13 | 0 | 13 | 11 | 89 | 0.000 | 0.000 | - |
| `repos/go-gin` | T1 | 1 | 138 | 72 | 66 | 50 | 2125 | 0.590 | 0.522 | 0.554 |
| `repos/go-httprouter` | T1 | 1 | 67 | 26 | 41 | 6 | 61 | 0.812 | 0.388 | 0.525 |
| `repos/rust-clap` | T1 | 1 | 0 | 0 | 0 | 0 | 6812 | - | - | - |
| `repos/rust-ripgrep` | T1 | 1 | 0 | 0 | 0 | 0 | 2415 | - | - | - |
| `repos/java-petclinic` | T1 | 1 | 0 | 0 | 0 | 0 | 205 | - | - | - |
| `repos/java-retrofit` | T1 | 1 | 94 | 0 | 94 | 0 | 3044 | - | 0.000 | - |

## Known Gaps

Micro-suite calls misses keep the m3 resolver work concrete: Python builtin-shadow and relative-import fixtures still miss truth edges, while TypeScript dynamic import and Java interface dispatch each produce a forbidden edge in cases where the benchmark asks the resolver to decline rather than guess. Those false positives are deliberate pressure tests for confidence gating, not fixtures to tune around.

The PyCG row remains the m5/m6 motivation. Calls precision stays high on the few dynamic edges reported, but 5.3% recall and 10.0% F1 show that higher-order, decorator, builtin, and value-flow-heavy Python cases remain mostly below the current static resolver floor; impact is similarly low for Python at 0.190/0.114/0.143.

Dead-code scoring is now the sharpest decline-not-guess signal. Across micro-suites, dead recall is near zero for Python, Go, Rust, TypeScript, and Java; the reported-dead false positives in Python, TypeScript, and Java are reachable according to the truth graph.

The real-repo rows should not be mixed into the micro-suite score. They are sampled T1/T2 LSP or runtime-trace truth sets with much wider project context: Go currently has the strongest real-repo calls F1 at 0.546, Python has high precision but very low recall, Java Retrofit has zero recall against its harvested edges, and TypeScript Nest shows wrong-owner contradictions that need language-specific ownership cleanup.

Rust real-repo truth is still pending upstream harvest quality. The two Rust repo entries currently carry zero truth edges and therefore only record unscored `tldr` output; they should not be read as a Rust real-repo accuracy measurement until the rust-analyzer harvest produces non-empty truth.
