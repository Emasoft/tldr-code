# Benchmark Baseline

Measured on 2026-07-08, this is the corpus-backed replacement for the earlier audit shorthand that `tldr calls` was roughly 80% correct. The headline full-corpus score is P/R/F1 = 0.711/0.190/0.300 across 193 cases, but the useful baseline is split by suite type because hand-written micro-cases, PyCG dynamic cases, and real-repo harvested truth answer different questions.

## Provenance

- Corpus commit: `a04a8392db7b0a90728b54e3f41cbc6aacde8995`.
- Scored checkout: `a04a839` era benchmark corpus.
- Binary: `/Users/cosimo/.cargo/bin/tldr`.
- Binary version: `tldr 0.4.1`.
- Binary SHA-256: `998ca698926405ee3fa51c021d01be4daa77bbec4efde7ee2dd50c8f95848cff`.
- Command: `python3 continuum/benchmark/run_truth.py --binary "$HOME/.cargo/bin/tldr" --out continuum/benchmark/report.json`.
- Report: `continuum/benchmark/report.json` (`harness.v1`).
- Runtime: 7.167 seconds wall time; 6.988 seconds summed case duration in the report.
- Skips: none.

## Truth-Case Review

The flagged `suites/python/class_method/inherited_method` fixture was corrected to the documented definer convention. Its truth now points at `Base.run` in `base.py`, and the fixture source defines `run` on `Base` instead of modeling an inherited call as `Child.run` in `child.py`.

I swept the remaining hand-written inheritance, promotion, and override cases for the same receiver-class-vs-definer issue. One case was fixed, and no other hand-written case needed a definer-convention change: TypeScript, Java, and Go inherited/promoted fixtures already point at the defining type, while override fixtures intentionally point at the overriding method and use negative edges where the base method would be wrong.

## Hand-Written Micro-Suites

| Language | Truth tier | Cases | TP | FN | FP | Unscored | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Python | T1 | 15 | 14 | 3 | 0 | 3 | 1.000 | 0.824 | 0.903 |
| TypeScript | T1 | 12 | 10 | 2 | 1 | 0 | 0.909 | 0.833 | 0.870 |
| Go | T1 | 12 | 12 | 3 | 0 | 1 | 1.000 | 0.800 | 0.889 |
| Rust | T1 | 12 | 8 | 4 | 0 | 0 | 1.000 | 0.667 | 0.800 |
| Java | T1 | 12 | 7 | 4 | 1 | 3 | 0.875 | 0.636 | 0.737 |

## PyCG Dynamic Suite

| Suite | Truth tier | Cases | TP | FN | FP | Unscored | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PyCG vendored Python micro-benchmarks | T1 | 119 | 14 | 250 | 2 | 29 | 0.875 | 0.053 | 0.100 |

## Real-Repo Truth Sets

| Language | Truth tier | Cases | Truth edges | TP | FN | FP | Unscored | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Python repos | T1, T2 | 3 | 303 | 17 | 286 | 2 | 1024 | 0.895 | 0.056 | 0.106 |
| TypeScript repos | T1 | 2 | 15 | 0 | 15 | 11 | 924 | 0.000 | 0.000 | - |
| Go repos | T1 | 2 | 205 | 98 | 107 | 56 | 2186 | 0.636 | 0.478 | 0.546 |
| Rust repos | T1 | 2 | 0 | 0 | 0 | 0 | 9227 | - | - | - |
| Java repos | T1 | 2 | 94 | 0 | 94 | 0 | 3249 | - | 0.000 | - |

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

Micro-suite misses keep the m3 resolver work concrete: Python builtin-shadow and relative-import fixtures still miss truth edges, while TypeScript dynamic import and Java interface dispatch each produce a forbidden edge in cases where the benchmark asks the resolver to decline rather than guess. Those false positives are deliberate pressure tests for confidence gating, not fixtures to tune around.

The PyCG row is the m5/m6 motivation. Precision stays high on the few dynamic edges reported, but 5.3% recall and 10.0% F1 show that higher-order, decorator, builtin, and value-flow-heavy Python cases remain mostly below the current static resolver floor.

The real-repo rows should not be mixed into the micro-suite score. They are sampled T1/T2 LSP or runtime-trace truth sets with much wider project context: Go currently has the strongest real-repo F1 at 0.546, Python has high precision but very low recall, Java Retrofit has zero recall against its harvested edges, and TypeScript Nest shows wrong-owner contradictions that need language-specific ownership cleanup.

Rust real-repo truth is still pending upstream harvest quality. The two Rust repo entries currently carry zero truth edges and therefore only record unscored `tldr` output; they should not be read as a Rust real-repo accuracy measurement until the rust-analyzer harvest produces non-empty truth.
