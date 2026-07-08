# Worker Brief — VAL-011 (m1-language-policy): route the PYTHON_BUILTINS denylist through policy.builtins

Repo: `/Users/cosimo/Desktop/PatchWork/tldr-code` (cd there for EVERY command). `implement` archetype, TDD.
Report `worker_done`. This is a BEHAVIOR-PRESERVING refactor of a calls-touching path → the parity gate
MUST be 0-delta (iron rule). Depends on VAL-010 (language_policy.rs already exists on HEAD by the time you run).

## Goal
Retire the direct `PYTHON_BUILTINS` + explicit `language == "python"` consult in the callgraph builder,
replacing it with the LanguagePolicy table so the Python-specific denylist becomes DATA (policy.builtins),
not a hardcoded language branch. Exactly reproduce current behavior.

## The ONE site to change
`crates/tldr-core/src/callgraph/builder_v2.rs:319-323`:
```rust
CallSiteResolution::Resolved(target) => {
    if builder_context.resolution_context.language.eq_ignore_ascii_case("python")
        && PYTHON_BUILTINS.contains(&target.name.as_str())
    {
        continue;
    }
    result.resolved.push((call_site.clone(), target));
}
```
Replace with a policy consult:
```rust
CallSiteResolution::Resolved(target) => {
    if language_policy_builtins(builder_context.resolution_context.language)
        .contains(&target.name.as_str())
    {
        continue;
    }
    result.resolved.push((call_site.clone(), target));
}
```
where you obtain `policy.builtins` for the current language. `resolution_context.language` is a STRING (see
its `.eq_ignore_ascii_case(...)` use). You must map that string → `crate::types::Language` → `policy_for(lang).builtins`.
- Find the existing string→Language conversion (grep `impl.*Language`, `from_str`, `from_extension`,
  `Language::from`, or a `fn detect_language`/`parse` helper). REUSE it — do NOT invent a new mapping.
- If the string does NOT map to a known Language, treat builtins as EMPTY (`&[]`) — identical to the current
  non-Python path. (A tiny private helper `fn language_policy_builtins(lang_str: &str) -> &'static [&'static str]`
  in builder_v2.rs that does the string→Language→policy.builtins lookup, returning `&[]` on unknown, is fine.)

## Why this is 0-delta
policy.builtins is PYTHON_BUILTINS for Python and `&[]` for every other language (VAL-010). So:
- Python: `policy.builtins.contains(name)` == the old `"python" && PYTHON_BUILTINS.contains(name)`. Identical.
- Non-Python: empty slice → `.contains()` always false == the old language-gate short-circuit. Identical.

## OUT OF SCOPE (do NOT touch — flag only)
- `dfg/extractor.rs:805` PYTHON_BUILTINS use is a DIFFERENT mechanism (a per-language value-identifier seed
  inside an explicit `match Language::{Go=>GO_BUILTINS, Python=>PYTHON_BUILTINS, Rust=>RUST_PRELUDE,...}`).
  It is ALREADY language-partitioned (not the is_python_style bug class). Leave it. Consolidating the
  duplicated const (types.rs:22 vs dfg/extractor.rs:7192) into policy is a LATER step — just note it.
- The `PYTHON_BUILTINS` const definition in callgraph/types.rs stays (policy.builtins references it).

## TDD (failing first)
There is likely an existing test near builder_v2.rs:1369 ("PYTHON_BUILTINS denylist applies only to Python").
Add/extend a test that pins BOTH: (a) a Python call to a builtin-named symbol (e.g. `dict(...)`) is still
dropped (not a project edge), and (b) a NON-Python (e.g. lua or rust) call to a same-spelled `dict`-named
project function IS kept as an edge (proving the denylist does not leak cross-language via the policy).
RED before the refactor if you first (temporarily) route through a wrong mapping — else assert the behavior
holds after. Run `env TLDR_NO_DAEMON=1 cargo test -p tldr-core --lib` (targeted test + full suite).

## HARD CONSTRAINTS
- Edit ONLY `crates/tldr-core/src/callgraph/builder_v2.rs` (+ the test, if it lives in a separate file, name it
  in your report). AST/data only, NO regex. No clippy `#[allow(...)]`.
- Leave UNCOMMITTED. Do NOT stage/codesign/install/run check_parity.py — orchestrator owns build+codesign+gate+commit.
- `git diff --name-only` must show ONLY builder_v2.rs (+ test file if separate). Revert fmt spillover via `git checkout-index`.

## WHEN DONE report worker_done with
(1) files changed, (2) the exact string→Language mapping helper you reused (path + name), (3) test name(s) +
RED→GREEN, (4) full core-lib pass count, (5) diff is only the intended file(s), (6) confirmation dfg/extractor.rs
and the const definitions were NOT touched.
