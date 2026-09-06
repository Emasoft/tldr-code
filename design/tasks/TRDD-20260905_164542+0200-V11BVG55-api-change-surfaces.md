---
trdd-id: V11BVG55
title: Retire or fix dead/misleading public API surfaces flagged by the scan
column: planned
created: 2026-09-05T16:45:42+0200
updated: 2026-09-06T04:12:00+0200
current-owner: codebase-scan-2026-09-05
task-type: refactor
min-approval-requirement: user
labels: [scan-2026-09-05, api_change]
---

# Retire or fix dead/misleading public API surfaces flagged by the scan

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-06

- **`tldr-core` IS A PUBLISHED CRATE.** Verified against the crates.io sparse index
  (`https://index.crates.io/tl/dr/tldr-core`): 13 versions, `0.1.0` through `0.4.0`. Upstream is
  `parcadei/tldr-code`. THIS FORK is `0.4.1-fork.1`, which is NOT on crates.io — so a change here
  reaches crates.io consumers only if it is merged upstream.
- **Consequence, and it invalidates a finding rather than resolving it:** "dead code" on this card
  was concluded from an in-repo caller search. That heuristic is INVALID for a `pub` item in a
  published library — the whole point of a `pub` export is callers you cannot grep. Zero in-repo
  callers is the NORMAL state of a public utility, not evidence it is dead.
- Exactly **2 of the 17** items are affected, and both are fully publicly reachable (verified,
  not inferred — every link in each chain checked):
  - `hubs.rs:311` — `pub fn with_composite` in `pub mod hubs` (analysis/mod.rs:40) in
    `pub mod analysis` (lib.rs:56) ⇒ `tldr_core::analysis::hubs::HubScore::with_composite`.
  - `ast_utils.rs:1138` — `pub fn verify_call_in_statement` in `pub mod ast_utils`
    (security/mod.rs:11) in `pub mod security` (lib.rs:147).
- **VERDICT for those 2: fix the doc, KEEP the API.** Each finding is really two claims bolted
  together, one false and one true. "It is dead" is false (above). "Its doc contradicts /
  overstates its body" is true and is the actual defect — hubs' doc advertises PageRank and
  betweenness while the body always sets both to `None`. Fixing the doc is non-breaking and
  removes the real harm; removing the function would be a breaking change to a published API in
  order to delete code that costs nothing.
- The **other 15 items are unaffected** by any of this — wrong classification, missing validation,
  hardcoded values, tautological tests, misleading docs are real defects whether or not anything
  external calls them. Publication status is not a defence for them.
- **CORRECTION — the encoding module is NOT on this card.** TRDD-7X459MTO's STATE block routes
  its "wire in or retire `pub mod encoding`" follow-up here, and the handoff repeated that. Both
  are wrong: none of the 17 items below mention `encoding`. That decision has NO card. It also
  inherits the reasoning above — `pub mod encoding` (lib.rs:45) is published public API, so its
  zero in-repo callers do not make it dead, and RETIRE is not the cheap cleanup it looked like.
- Housekeeping: `## What` and `## Findings` below carry the SAME 17 lines, duplicated verbatim.
  Collapse to one list when this card is next worked.

## Why
A codebase scan (2026-09-05) found 17 sites where a public flag, exported helper, or public-facing
doc comment is dead, duplicated, or misleading. Each fix would change a public signature, an
exported behavior, or a documented contract, so it could not be applied as a same-file, in-batch
fix during the scan — it needs an owner decision on whether to remove, deprecate, or actually wire
up the surface.

## What
Review each item below and decide: implement the missing behavior, remove the dead/unused surface,
or fix the misleading doc comment, in `crates/tldr-cli` and `crates/tldr-core`. Every finding names
its exact file:line.

- crates/tldr-cli/src/commands/contracts/specs.rs:6 — Doc comment claims T08 (AST stack overflow) is mitigated by `check_ast_depth()`, but several genuinely recursive AST walkers never call it
- crates/tldr-cli/src/commands/daemon/ipc.rs:58 — compute_socket_path is fully re-implemented in both ipc.rs and pid.rs with byte-identical logic (hash+format), instead of ipc.rs calling pid::compute_socket_path (which it could, since it already imports pid::compute_hash)
- crates/tldr-cli/src/commands/similar.rs:44-45 — `--include-self` CLI flag is declared but never read anywhere in the file
- crates/tldr-cli/tests/med_cleanup_bundle_v1.rs:190 — m15_churn_text_suppress_warning_string_present asserts a tautology, not real formatter behaviour
- crates/tldr-core/src/alias/constraints.rs:379-424 — `process_param_instruction`/`parse_mutable_default` (TIGER-7) misattributes a mutable-default allocation site to every parameter of a multi-parameter function, not just the one with the default
- crates/tldr-core/src/alias/solver.rs:529 — transitive_closure silently caps at MAX_ITERATIONS with no signal of incompleteness
- crates/tldr-core/src/analysis/hubs.rs:311 — HubScore::with_composite is dead code and its doc comment ("Used when composite is computed with additional measures (PageRank, betweenness)") contradicts its body, which always sets pagerank/betweenness to None
- crates/tldr-core/src/callgraph/import_resolver.rs:644 — parse_all() cannot parse multi-line `__all__ = [...]` lists
- crates/tldr-core/src/callgraph/languages/php.rs:340 — self::/static:: calls always classified CallType::Static, never Intra
- crates/tldr-core/src/dataflow/octagon/operations.rs:100 — `widen`/`widen_with_thresholds` do not validate `old.n_vars() == new.n_vars()` before indexing, unlike `join`/`meet`/`is_included` which return `None` on mismatch
- crates/tldr-core/src/dfg/reaching.rs:1241 — compute_reaching_definitions_rpo and compute_reaching_definitions_bitvec do not resolve overlapping-block definition ownership
- crates/tldr-core/src/dfg/reaching.rs:710 — ReachingDefsStats.iterations is hardcoded to 0 with a `// TODO: Track iterations` comment even though the sibling compute_reaching_definitions_rpo already computes a real iteration count
- crates/tldr-core/src/quality/similarity.rs:459 — complexity always hardcoded to 1, making the 0.2-weighted complexity-similarity term constant (always 1.0) for every pair
- crates/tldr-core/src/security/ast_utils.rs:1124 — `verify_call_in_statement` is dead code whose doc overstates its behavior
- crates/tldr-core/src/ssa/memory.rs:59 — MemorySsa.def_use maps each memory version to a list containing copies of that same version, not real use-location info
- crates/tldr-core/src/wrappers/base.rs:61 — doc comment claims safe_call "never panics" but it does not catch_unwind the closure
- crates/tldr-core/tests/ssa_tests.rs:399 — minimal_ssa_has_def_use_chains computes _ssa and asserts nothing ("just verify it exists")

## Acceptance
- [ ] Each finding above has an owner decision recorded (fix / remove / document-as-is)
- [ ] No public flag or exported helper remains both unused and undocumented as such
- [ ] Doc comments no longer contradict the code they describe
- [ ] `cargo test` passes after any behavior change

## Findings

- crates/tldr-cli/src/commands/contracts/specs.rs:6 — Doc comment claims T08 (AST stack overflow) is mitigated by `check_ast_depth()`, but several genuinely recursive AST walkers never call it
- crates/tldr-cli/src/commands/daemon/ipc.rs:58 — compute_socket_path is fully re-implemented in both ipc.rs and pid.rs with byte-identical logic (hash+format), instead of ipc.rs calling pid::compute_socket_path (which it could, since it already imports pid::compute_hash)
- crates/tldr-cli/src/commands/similar.rs:44-45 — `--include-self` CLI flag is declared but never read anywhere in the file
- crates/tldr-cli/tests/med_cleanup_bundle_v1.rs:190 — m15_churn_text_suppress_warning_string_present asserts a tautology, not real formatter behaviour
- crates/tldr-core/src/alias/constraints.rs:379-424 — `process_param_instruction`/`parse_mutable_default` (TIGER-7) misattributes a mutable-default allocation site to every parameter of a multi-parameter function, not just the one with the default
- crates/tldr-core/src/alias/solver.rs:529 — transitive_closure silently caps at MAX_ITERATIONS with no signal of incompleteness
- crates/tldr-core/src/analysis/hubs.rs:311 — HubScore::with_composite is dead code and its doc comment ("Used when composite is computed with additional measures (PageRank, betweenness)") contradicts its body, which always sets pagerank/betweenness to None
- crates/tldr-core/src/callgraph/import_resolver.rs:644 — parse_all() cannot parse multi-line `__all__ = [...]` lists
- crates/tldr-core/src/callgraph/languages/php.rs:340 — self::/static:: calls always classified CallType::Static, never Intra
- crates/tldr-core/src/dataflow/octagon/operations.rs:100 — `widen`/`widen_with_thresholds` do not validate `old.n_vars() == new.n_vars()` before indexing, unlike `join`/`meet`/`is_included` which return `None` on mismatch
- crates/tldr-core/src/dfg/reaching.rs:1241 — compute_reaching_definitions_rpo and compute_reaching_definitions_bitvec do not resolve overlapping-block definition ownership
- crates/tldr-core/src/dfg/reaching.rs:710 — ReachingDefsStats.iterations is hardcoded to 0 with a `// TODO: Track iterations` comment even though the sibling compute_reaching_definitions_rpo already computes a real iteration count
- crates/tldr-core/src/quality/similarity.rs:459 — complexity always hardcoded to 1, making the 0.2-weighted complexity-similarity term constant (always 1.0) for every pair
- crates/tldr-core/src/security/ast_utils.rs:1124 — `verify_call_in_statement` is dead code whose doc overstates its behavior
- crates/tldr-core/src/ssa/memory.rs:59 — MemorySsa.def_use maps each memory version to a list containing copies of that same version, not real use-location info
- crates/tldr-core/src/wrappers/base.rs:61 — doc comment claims safe_call "never panics" but it does not catch_unwind the closure
- crates/tldr-core/tests/ssa_tests.rs:399 — minimal_ssa_has_def_use_chains computes _ssa and asserts nothing ("just verify it exists")

## Approval log

- 2026-09-05T21:33:13+0200 — APPROVED by the session Claude under the user's 2026-09-05 directive to decide from verified facts and implement what is good. Work is authorized; no push.
