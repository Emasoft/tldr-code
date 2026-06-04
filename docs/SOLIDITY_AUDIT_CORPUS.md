# v0.5.0 SOL-012 — Solidity Audit Corpus

## Canonical Solidity Audit Corpus

**Source:** [OpenZeppelin/openzeppelin-contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) at tag **v5.0.2**
**Local clone path:** `/tmp/repos/solidity-openzeppelin/`
**Audit subset:** `contracts/token/ERC20/` (13 .sol files, 1,429 LOC)

```sh
git clone --depth 1 --branch v5.0.2 \
  https://github.com/OpenZeppelin/openzeppelin-contracts.git \
  /tmp/repos/solidity-openzeppelin
```

This corpus is the canonical Solidity test bed for v0.5.0 audits. The
ERC20 subset was chosen because it exercises custom errors, contract
inheritance, NatSpec, libraries (`SafeERC20`), payable functions, low-level
calls, modifier invocations, and the EIP-2612 permit pattern.

## Audit Outputs

Audit cells, JSON output, and markdown report live OUTSIDE the repo at:

- `/tmp/audit_phase22/solidity/cells/*.json` — raw per-cell outputs (50+ cells)
- `/tmp/audit_phase22/solidity/iter-1-solidity-audit.md` — markdown report
- `/tmp/audit_phase22/solidity/SOL-012-audit.json` — structured machine-readable report

These artefacts are intentionally not committed — they are reproducible from
the corpus + `tldr` binary at the SOL-012 commit hash.

## SOL-012 Convergence Result

**72% convergence** on the OpenZeppelin ERC20 corpus across 47 cells:

- 28 commands work correctly on Solidity
- 14 commands are partial (work but emit incomplete data — e.g. missing field, missing rule)
- 5 commands are broken on Solidity (interface, clones, contracts, vuln-without-`--lang`, cohesion)

17 mechanical TODOs filed for follow-up phases SOL-013 through SOL-016.
4 design-judgement TODOs filed for SOL-017 (api-check rules, pattern
detectors, solhint integration, coupling-via-inheritance).

See `/tmp/audit_phase22/solidity/iter-1-solidity-audit.md` for the full
gap inventory and prioritised cluster list.

## Build Fix Required for Compile

SOL-001 added `Language::Solidity` but missed a downstream non-exhaustive
match arm in `crates/tldr-core/src/semantic/chunker.rs` (only compiled
under `--features semantic`). Without this fix, `cargo install --path
crates/tldr-cli --features semantic` fails with:

```
error[E0004]: non-exhaustive patterns: `types::Language::Solidity` not covered
   --> crates/tldr-core/src/semantic/chunker.rs:429
```

Fix: route `Language::Solidity` through the existing generic-AST-splitter
arm alongside C, Cpp, Kotlin, Swift, Php, Lua, Luau, Ocaml, Elixir, Scala,
CSharp, Ruby. This is correct routing because Solidity function bodies are
recognised by `is_chunkable_function_kind` via the `function_definition`
node kind — no bespoke chunker arm is needed.

This 1-line fix is part of the SOL-012 commit.

## Smoke Gate Status

All 14 Solidity test suites pass (141 tests):

```
solidity_foundation_v1   5 passed
solidity_schema_v1      11 passed
solidity_extract_v1     10 passed
solidity_structure_v1    8 passed
solidity_callgraph_v1   11 passed
solidity_cfg_v1          7 passed
solidity_surface_v1      3 passed
solidity_dfg_ssa_v1      9 passed
solidity_deps_v1         7 passed
solidity_metrics_v1     21 passed
solidity_test_recognizer_v1  16 passed
solidity_natspec_v1     17 passed
solidity_vuln_v1         6 passed
solidity_inheritance_v1 10 passed
```

`cargo test --release -p tldr-core --lib`: **4812 passed**, 0 failed.

Phase-prompt smoke gate: 16 of 18 target test suites pass.
m048_deps_stdlib_wiring_v1 (9 failures in kotlin/ruby/scala/ocaml/php/swift/lua/csharp/js
stdlib detection) and m112_surface_garbage_v1 (3 swift surface failures) are
pre-existing on HEAD — these tests live in `tldr-cli/tests/` and exercise
deps/surface code paths completely disjoint from the 1-line chunker.rs
fix in this commit. They are tracked separately and not blocking SOL-012.
