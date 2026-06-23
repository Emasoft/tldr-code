# RC4 — intraprocedural CFG over-segmentation + whole-function flat scope (nested fns)

**Cluster:** reaching-defs (analysis[0]); related to available / slice / chop (CFG consumers)
**Classification:** design-fork. A LOW-RISK MITIGATION was implemented in fix-R7 (see below);
the PRINCIPLED direction (per-nested-function sub-CFG + CFG-builder fix for sequential
let-in / `?` expressions) remains a deliberate design decision for the maintainer.

## Problem (two sub-issues)

### 4a — sequential-binding CFG over-segmentation -> spurious "possible"
For a tiny OCaml fn `let c = Queue.take p.list in validate_and_return p c`, the CFG emits ~10
blocks and splits line 124 across blocks. `detect_uninitialized`'s no-def-path worklist
(`reaching.rs` `has_undefined_path`, the `blocks_with_def` "largest-block" assignment) then
finds a spurious path that bypasses `c`'s def — even though `build_def_use_chains` correctly
links `c@123 -> use@124`. Result: `c` flagged `possible` (Bug 12). Same shape for Rust
`value` after a `?` early-return (Bug 17): `let value = digits.parse()...?` then `Ok(value)` —
the `?` splits the statement and the no-def worklist disagrees with the use-def chain, so
`value` is reported `possible`.

This is observable LIVE after fix-R7: `rust-ripgrep human.rs parse_human_readable_size` now
reports a single residual `value` (down from 19 total FPs) — purely this CFG sub-issue.

### 4b — nested functions flattened into one CFG / flat scope
The analysis flattens every nested function/lambda into the OUTER function's single CFG
(block 0), and `detect_uninitialized` only treats the OUTER signature line (min def line) as
pre-initialized parameters. Inner-function parameters on later lines are therefore neither
pre-initialized nor reachable across the flattened blocks (TS-axios `mergeConfig` -> 16
`possible` FPs for inner-fn params `a`/`b`; Python-requests `should_bypass_proxies` -> nested
`def get_proxy(key)` with body read of `key`).

Both sub-issues are PRE-EXISTING (min-def-line param auto-detection `reaching.rs`
`build_reaching_defs_report_with_params` is byte-identical baseline->HEAD).

## What fix-R7 DID implement (the reaudit's recommended low-risk mitigation, 4b-ii)

The reaudit recommends, for 4b: "(ii) collect ALL parameter definitions from EVERY nested
function / lambda into the pre-initialized set." fix-R7 implements a precise, AST-driven
version of this, tagging micro-scoped binders so the uninit detector treats them as
pre-initialized (`crates/tldr-core/src/dfg/reaching.rs detect_uninitialized`, which now adds
any `VarRefContext::ClosureParam | ComprehensionScope` def name to `pre_initialized`):

- Rust closure params `|a, &b|`  -> `process_rust_closure` (tagged `ClosureParam`).
- Python comprehension binders `[x for x in ...]` -> `process_python_comprehension`
  (tagged `ComprehensionScope`).
- Python nested `def` name + params, and `lambda` params -> `process_python_nested_function`
  / `process_python_lambda` (name as plain def; params tagged `ClosureParam`).
- C#/Java C-style `for (int i = 0; ...)` init binder -> `process_for_init_declaration`
  (tagged, because the `for(...)` header line is itself over-segmented into overlapping
  blocks — a 4a manifestation for loop variables).

These killed the closure/comprehension/nested-fn/for-init FPs (Python should_bypass_proxies
30->3, Rust b/e gone, C#/Java for-init gone) with low risk: the only downside is slight
OVER-suppression — a genuinely-uninitialized inner LOCAL that shares a name with an inner
PARAM/binder could be masked. That trade-off is exactly what the reaudit flagged as acceptable
for mitigation (ii).

## What remains a design-fork (NOT implemented)

1. **4a CFG-builder fix.** The principled fix is to stop over-segmenting sequential
   `let ... in ...` / `?`-expression / single-line binding statements so a def and its
   same-statement use land in ONE block, OR to gate the `possible` verdict on agreement with
   `build_def_use_chains` (when the chain already proves a def reaches a use on the analyzed
   paths, do not independently re-derive an "undefined path" from the over-segmented blocks).
   The CFG builder (`crate::cfg`) feeds EVERY L3–L5 command (available, slice, chop, taint),
   so changing block granularity is high blast radius and must be a deliberate decision.
   Residual symptom after fix-R7: Rust `value` `possible` on `?`-early-return.

2. **4b principled per-nested-function scope.** Build a sub-CFG per nested function/lambda,
   each with its own params pre-initialized and its own block set, instead of flattening into
   the outer CFG. This is the correct model (and would also fix TS/JS `mergeConfig`, which the
   fix-R7 Python-only mitigation does not touch — TS/JS use their own classifier path). It is
   a structural change to `get_dfg_context` / CFG construction -> high blast radius.

## Options for the remaining work

| Option | Scope | Risk | Notes |
|---|---|---|---|
| 4a-(i) gate `possible` on use-def-chain agreement | `detect_uninitialized` only | low-med | localized; fixes Rust `value`/OCaml `c` without touching CFG |
| 4a-(ii) fix CFG builder block granularity | `crate::cfg` | HIGH | most correct; re-baselines ALL L3–L5 goldens |
| 4b-(i) per-nested-fn sub-CFG | `get_dfg_context` + CFG | HIGH | correct; also fixes TS/JS nested-fn |
| 4b-(ii) param pre-init mitigation | DONE in fix-R7 | low | implemented for Rust/Python/C#/Java |

## Recommendation

- Take **4a-(i)** next (gate `possible` on use-def-chain agreement) — it is localized to
  `detect_uninitialized`, eliminates the residual `value`/`c` `possible` FPs, and carries no
  CFG blast radius. Re-baseline only reaching_tests.
- Treat **4a-(ii)** and **4b-(i)** as the principled long-term direction, scheduled as a
  dedicated CFG/scope change with full L3–L5 golden re-baseline (NOT inside a closeout pass).
  Extend the fix-R7 param-tagging mitigation to TS/JS nested fns as a stopgap if axios-style
  FPs need to drop before then.

## Pointers
- `crates/tldr-core/src/dfg/reaching.rs`: `detect_uninitialized` (`has_undefined_path`
  worklist, `blocks_with_def` largest-block assignment, pre_initialized seeding),
  `build_reaching_defs_report_with_params` (min-def-line param auto-detect).
- `crates/tldr-core/src/dfg/extractor.rs`: `process_rust_closure`,
  `process_python_comprehension`, `process_python_nested_function`, `process_python_lambda`,
  `process_for_init_declaration` (the fix-R7 mitigations).
- `crate::cfg` (CFG builder): the source of the block over-segmentation.
