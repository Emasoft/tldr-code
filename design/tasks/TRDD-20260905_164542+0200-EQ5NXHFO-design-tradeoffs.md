---
trdd-id: EQ5NXHFO
title: Resolve intentional-but-undocumented design tradeoffs surfaced by the scan
column: planned
created: 2026-09-05T16:45:42+0200
updated: 2026-09-05T21:33:13+0200
current-owner: codebase-scan-2026-09-05
task-type: refactor
min-approval-requirement: user
labels: [scan-2026-09-05, design]
---

# Resolve intentional-but-undocumented design tradeoffs surfaced by the scan

## Why
The scan found 17 spots that read like bugs out of context but are plausibly deliberate
approximations (soundness-over-precision choices, archived/placeholder code, conservative
heuristics). A same-file fix cannot resolve these because the "right" behavior depends on a
maintainer decision about intended scope, not on a local logic error.

## What
For each item, decide: keep as documented tradeoff (add a comment explaining why), tighten the
implementation to match its own doc/test claims, or remove the dead/placeholder code entirely.
Affected crates: `crates/tldr-cli`, `crates/tldr-core`, `crates/tldr-mcp`.

- crates/tldr-cli/src/commands/archived/behavioral.rs:1609 — `purity_classification` can never return "pure" even though the module's own unit test `test_analyze_pure_function` (line 3110) asserts it does for a trivial `def add(a, b): return a + b`
- crates/tldr-cli/src/commands/archived/behavioral.rs:2210 — `detect_side_effects` (and its use from `analyze_function_generic`) only recognizes Python-specific tree-sitter node kinds (`global_statement`, `assignment`/`augmented_assignment` with an `attribute` left-hand side keyed on `self`), so for every non-Python language routed through the generic path, global-write and attribute-write side effects are silently never detected — only the generic `call`-name-based checks (I/O ops, impure calls, collection mutations) still work.
- crates/tldr-cli/src/commands/archived/bounds.rs:583 — The catch-all arm of `analyze_stmt` only looks one level down for direct `assignment`/`augmented_assignment` children of an unhandled statement kind (e.g. `match_expression`, `switch_statement`, `try_statement`); it never recurses into their nested blocks, so assignments/branches inside those unhandled constructs are silently skipped by the interval analysis
- crates/tldr-cli/src/commands/archived/bounds.rs:993 — Modulo interval `%` always returns `[0, right.hi-1]` when the divisor is positive, which is only correct for languages whose `%` yields a non-negative result (e.g. Python); for C/Java/Rust/Go truncated-division semantics the true dividend can be negative and the real result range includes negative values, so the analyzer can under-approximate and miss a real bound violation
- crates/tldr-cli/src/commands/archived/mutability.rs:130 — `IMMUTABLE_ALTERNATIVES` constant is defined but never referenced anywhere in the file
- crates/tldr-cli/src/commands/contracts/specs.rs:1504 — `is_go_t_failure_method` includes `Log`/`Logf`/`Skip`/`Skipf`/`Skipped`, which are not failure signals, but the set is reused as the trigger for "this `if` block is a Go test assertion"
- crates/tldr-cli/src/commands/daemon/daemon.rs:1098-1106 — `handle_notify`'s reindex-threshold path clears the dirty-file set without actually re-indexing anything
- crates/tldr-cli/src/commands/impact.rs:107 — --type-aware flag documented as enabled but only sets a zeroed placeholder TypeResolutionStats, never doing real type resolution
- crates/tldr-cli/src/commands/remaining/diff.rs:3486 — `collect_source_files_recursive` walks directories with no protection against a symlink cycle and no exclusion of VCS/build directories (`.git`, `target`, `node_modules`, `__pycache__`, etc.)
- crates/tldr-cli/src/commands/remaining/types.rs:402 — Duplicate test module: `mod tests` (line 402) and `mod unit_types_tests` (line 1700) both define near-identical tests (test_output_format_serialization, test_severity_ordering, test_location_serialization, test_todo_report_serialization, test_todo_item_builder, test_secure_report_serialization)
- crates/tldr-core/src/analysis/change_impact_tests.rs:1-1277 — Entire file is placeholder tests: every #[test] is #[ignore]-annotated and its body is a bare todo!() after commented-out assertions
- crates/tldr-core/src/callgraph/languages/typescript.rs:590 — method calls with a nested member-expression receiver (`a.b.method()`) are silently dropped, not just simplified
- crates/tldr-core/src/contracts/python.rs:100 — `ApiSurface { .. files_skipped: 0, warnings: Vec::new() }` sets fields that do not exist on `contracts::types::ApiSurface`
- crates/tldr-core/src/diagnostics/tests.rs:1 — Whole file is a spec-driven test scaffold with many `#[ignore]` tests bodied only by `todo!(...)`
- crates/tldr-core/src/semantic/cache.rs:117 — `CacheConfig.max_size_mb` is stored but never enforced (no size-based eviction anywhere in `EmbeddingCache`)
- crates/tldr-core/tests/bench_patterns_security_multilang.rs:2184 — test_inheritance_report_scan_time asserts `scan_time_ms < 60_000`, which is true for virtually any real run and only guards against an absurd 60s stall
- crates/tldr-mcp/src/tools/security.rs:167 — handle_secure silently treats a scan Err as 0 issues in the score

## Acceptance
- [ ] Each finding above has an owner decision recorded (keep-and-document / fix / remove)
- [ ] Kept tradeoffs carry an inline comment stating the limitation and why
- [ ] No test asserts behavior the implementation contradicts
- [ ] `cargo test` passes after any behavior change

## Findings

- crates/tldr-cli/src/commands/archived/behavioral.rs:1609 — `purity_classification` can never return "pure" even though the module's own unit test `test_analyze_pure_function` (line 3110) asserts it does for a trivial `def add(a, b): return a + b`
- crates/tldr-cli/src/commands/archived/behavioral.rs:2210 — `detect_side_effects` (and its use from `analyze_function_generic`) only recognizes Python-specific tree-sitter node kinds (`global_statement`, `assignment`/`augmented_assignment` with an `attribute` left-hand side keyed on `self`), so for every non-Python language routed through the generic path, global-write and attribute-write side effects are silently never detected — only the generic `call`-name-based checks (I/O ops, impure calls, collection mutations) still work.
- crates/tldr-cli/src/commands/archived/bounds.rs:583 — The catch-all arm of `analyze_stmt` only looks one level down for direct `assignment`/`augmented_assignment` children of an unhandled statement kind (e.g. `match_expression`, `switch_statement`, `try_statement`); it never recurses into their nested blocks, so assignments/branches inside those unhandled constructs are silently skipped by the interval analysis
- crates/tldr-cli/src/commands/archived/bounds.rs:993 — Modulo interval `%` always returns `[0, right.hi-1]` when the divisor is positive, which is only correct for languages whose `%` yields a non-negative result (e.g. Python); for C/Java/Rust/Go truncated-division semantics the true dividend can be negative and the real result range includes negative values, so the analyzer can under-approximate and miss a real bound violation
- crates/tldr-cli/src/commands/archived/mutability.rs:130 — `IMMUTABLE_ALTERNATIVES` constant is defined but never referenced anywhere in the file
- crates/tldr-cli/src/commands/contracts/specs.rs:1504 — `is_go_t_failure_method` includes `Log`/`Logf`/`Skip`/`Skipf`/`Skipped`, which are not failure signals, but the set is reused as the trigger for "this `if` block is a Go test assertion"
- crates/tldr-cli/src/commands/daemon/daemon.rs:1098-1106 — `handle_notify`'s reindex-threshold path clears the dirty-file set without actually re-indexing anything
- crates/tldr-cli/src/commands/impact.rs:107 — --type-aware flag documented as enabled but only sets a zeroed placeholder TypeResolutionStats, never doing real type resolution
- crates/tldr-cli/src/commands/remaining/diff.rs:3486 — `collect_source_files_recursive` walks directories with no protection against a symlink cycle and no exclusion of VCS/build directories (`.git`, `target`, `node_modules`, `__pycache__`, etc.)
- crates/tldr-cli/src/commands/remaining/types.rs:402 — Duplicate test module: `mod tests` (line 402) and `mod unit_types_tests` (line 1700) both define near-identical tests (test_output_format_serialization, test_severity_ordering, test_location_serialization, test_todo_report_serialization, test_todo_item_builder, test_secure_report_serialization)
- crates/tldr-core/src/analysis/change_impact_tests.rs:1-1277 — Entire file is placeholder tests: every #[test] is #[ignore]-annotated and its body is a bare todo!() after commented-out assertions
- crates/tldr-core/src/callgraph/languages/typescript.rs:590 — method calls with a nested member-expression receiver (`a.b.method()`) are silently dropped, not just simplified
- crates/tldr-core/src/contracts/python.rs:100 — `ApiSurface { .. files_skipped: 0, warnings: Vec::new() }` sets fields that do not exist on `contracts::types::ApiSurface`
- crates/tldr-core/src/diagnostics/tests.rs:1 — Whole file is a spec-driven test scaffold with many `#[ignore]` tests bodied only by `todo!(...)`
- crates/tldr-core/src/semantic/cache.rs:117 — `CacheConfig.max_size_mb` is stored but never enforced (no size-based eviction anywhere in `EmbeddingCache`)
- crates/tldr-core/tests/bench_patterns_security_multilang.rs:2184 — test_inheritance_report_scan_time asserts `scan_time_ms < 60_000`, which is true for virtually any real run and only guards against an absurd 60s stall
- crates/tldr-mcp/src/tools/security.rs:167 — handle_secure silently treats a scan Err as 0 issues in the score

## Approval log

- 2026-09-05T21:33:13+0200 — APPROVED by the session Claude under the user's 2026-09-05 directive to decide from verified facts and implement what is good. Work is authorized; no push.
