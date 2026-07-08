# Worker Brief — VAL-012 (m1-language-policy): replace is_python_style with policy.module_alias_style

Repo: `/Users/cosimo/Desktop/PatchWork/tldr-code` (cd there for EVERY command). `implement` archetype, TDD.
Report `worker_done`. BEHAVIOR-PRESERVING refactor of the calls index — parity gate MUST be 0-delta (iron rule).
Depends on VAL-010 (language_policy.rs) + VAL-011 (policy consult pattern) — both on HEAD when you run.

## Goal
Retire the module-name SHAPE heuristic `is_python_style` (the root cause of the reverted W2-29 failure) in
favor of the per-language `policy_for(lang).module_alias_style` DATA. After this, whether a language gets a
bare-suffix alias is an explicit per-language decision, not an accident of module-string shape.

## Sites to change (BOTH, so the logic isn't left duplicated)
1. **`crates/tldr-core/src/callgraph/builder_v2.rs:835-872`** (authoritative): the
   ```rust
   let is_python_style = !module.starts_with("./") && !module.starts_with("crate::") && !module.contains('/');
   ```
   block and its three uses (simple_module derivation + the two alias-insert guards).
2. **`crates/tldr-core/src/bin/callgraph_resolution_stats.rs:74-95`**: the same logic copy-pasted in the
   stats binary. Apply the identical policy-based replacement so the two never diverge again.

## Replacement (primary design)
```rust
let dotted_alias = policy_for(lang).module_alias_style == AliasStyle::DottedSuffix; // lang: see below
let simple_module = if dotted_alias {
    module.split('.').next_back().unwrap_or(&module)
} else {
    &module
};
if dotted_alias && simple_module != module.as_str() && /* existing first-writer guard unchanged */ { ... }
```
- The language here comes from `config.language` (a STRING) — reuse the SAME `Language::from_str` route
  VAL-011 used (`language_policy_builtins` precedent; a small shared private helper or a parsed-once local
  is fine). On unknown language string: `dotted_alias = false` (no alias — matches shape-check behavior for
  the pathological unknown case where module strings are typically paths; note it in your report).
- Do NOT change: the `simple_module != module` guard, the first-writer-wins `.get(...).map(...)` guard,
  the qualified `Class.method` twin block's structure, or insertion order. ONLY the predicate swaps.

## Why this should be 0-delta (and what to do if it is not)
The alias insert only fires when `simple_module != module` — i.e. the module string CONTAINS A DOT. So the
swap diverges from the old shape check only for: (a) dot-containing module strings in a `None` language
(e.g. a hypothetical `a.b/c`), or (b) `./`-, `crate::`-, or `/`-containing strings in a `DottedSuffix`
language. VAL-010's table was derived to make both empty in practice. The 38-repo gate is the arbiter.
**If the orchestrator's gate reports ANY delta, you will NOT tinker heuristics back in** — the orchestrator
will send you the delta list and either the policy VALUE for a language gets corrected (data fix) or the
step escalates. Your job is the clean swap.

## TDD (failing first)
Add a test pinning the alias semantics through the policy (co-locate with builder_v2 tests):
(a) Python `pkg/helper.py` (module `pkg.helper`): a cross-file call `helper.fn()` resolvable via the bare
    alias still resolves (DottedSuffix languages keep the alias).
(b) TypeScript/Rust-style module (`./utils` / `crate::utils`): no bare-suffix alias registered (None
    languages never had one — pin that staying true).
RED first by asserting against a deliberately-wrong intermediate if needed, GREEN after the swap.
Run the targeted test, then FULL core lib suite: `env TLDR_NO_DAEMON=1 cargo test -p tldr-core --lib`.
Also `cargo build --bin callgraph_resolution_stats 2>&1 | tail -2` must compile clean (site 2).

## HARD CONSTRAINTS
- Edit ONLY: `builder_v2.rs` + `bin/callgraph_resolution_stats.rs` (+ named separate test file if needed).
  NO regex, NO clippy `#[allow(...)]`. builder_v2's alias-insert structure preserved (predicate swap only).
- Leave UNCOMMITTED. Do NOT stage/codesign/install/run check_parity.py — orchestrator owns
  build+codesign+CANARY+full-gate+commit (this is a HIGH isolation-risk change per BRIEF-CHECKLIST §3).
- `git diff --name-only` must show ONLY the intended files; revert fmt spillover via `git checkout-index`.

## WHEN DONE report worker_done with
(1) files changed, (2) the exact predicate swap at both sites (before/after snippet), (3) how you obtained
`lang` from `config.language`, (4) test names + RED→GREEN, (5) full core-lib pass count + stats-bin compile,
(6) diff is only intended files.
