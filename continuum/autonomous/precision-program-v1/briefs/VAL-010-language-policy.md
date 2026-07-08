# Worker Brief — VAL-010 (m1-language-policy): create the LanguagePolicy table

Repo: `/Users/cosimo/Desktop/PatchWork/tldr-code` (cd there for EVERY command). Rust, tree-sitter.
`implement` archetype. TDD. Report `worker_done`. This step is ADDITIVE (a new module nothing consumes yet)
so it MUST be 0-delta on the parity gate by construction.

## Goal
Introduce a single per-language policy table so the scattered module-name shape/name heuristics
(`PYTHON_BUILTINS`, `is_python_style`) can be retired in later steps (VAL-011/012). This step ONLY creates
the table + its exhaustiveness test. Do NOT wire it into any consumer yet (that is VAL-011/012).

## Create `crates/tldr-core/src/language_policy.rs` (new top-level module)
Register it in `crates/tldr-core/src/lib.rs` (`pub mod language_policy;` — match the existing module
declaration style). Top-level (not under callgraph/) because both `callgraph` and `dfg` will consume it.

### Struct + enum
```rust
/// How a language's module string yields a bare-suffix alias in the func index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasStyle {
    /// Dotted or bare module name with NO `./`, `crate::`, or `/` — the last dot-segment is
    /// ALSO indexed as a bare alias (e.g. Python `pkg.helper` -> `helper`). This reproduces the
    /// current `is_python_style` == true branch.
    DottedSuffix,
    /// No bare-suffix alias (TS/JS `./foo`, Rust `crate::foo`, Go `foo/bar`). Reproduces
    /// `is_python_style` == false.
    None,
}

/// Per-language policy: the single source of truth that replaces scattered shape/name heuristics.
#[derive(Debug, Clone, Copy)]
pub struct LanguagePolicy {
    /// Builtin type/exception/function names that must NOT be treated as project constructors.
    /// Non-empty ONLY where the language actually has such a denylist today (Python). Empty slice elsewhere.
    pub builtins: &'static [&'static str],
    /// Whether the module string gets a bare dot-suffix alias in the func index.
    pub module_alias_style: AliasStyle,
    /// The module path separator this language uses in its `path_to_module` output.
    pub path_separator: &'static str,
    /// Whether module paths are dotted (a.b.c) as opposed to slashed/`::`/relative.
    pub dotted_module_paths: bool,
}

pub fn policy_for(language: crate::types::Language) -> LanguagePolicy { /* explicit match, see below */ }
```

### Populating the table — CORRECTNESS METHOD (do NOT guess)
For EACH of the 19 `Language` variants, set `module_alias_style` to match what `is_python_style`
CURRENTLY evaluates to for that language's module strings. `is_python_style` (builder_v2.rs:835) is:
```rust
!module.starts_with("./") && !module.starts_with("crate::") && !module.contains('/')
```
where `module = path_to_module(path, language)`. So: READ each `path_to_module_<lang>` helper in
`crates/tldr-core/src/callgraph/module_path.rs` (python@186, typescript@215, go@242, rust@251, java@413,
kotlin@417, scala@421, and the rest — grep `fn path_to_module`), determine the output format, and set:
- `AliasStyle::None` if that language's module string starts with `./` or `crate::` or contains `/`
  (known so far: TypeScript, JavaScript → `./`; Rust → `crate::`; Go → `/`. VERIFY each by reading the helper).
- `AliasStyle::DottedSuffix` otherwise (Python and the dotted/bare-name languages).
Set `dotted_module_paths` and `path_separator` consistently with the same reading (`.` for dotted langs,
`/` for Go-style, `::` for Rust, etc.). If a language's format is genuinely mixed/uncertain, choose the value
that matches the CURRENT `is_python_style` result and add a `// VERIFY@VAL-012` comment — VAL-012's 0-delta
gate is the final arbiter.

### builtins
- Python → reference the EXISTING const `crate::callgraph::types::PYTHON_BUILTINS` (do NOT copy/duplicate the
  list; re-export or reference it so there is ONE source). Every other language → `&[]`.
- (Note for your report, do not fix here: PYTHON_BUILTINS is currently duplicated in
  callgraph/types.rs:22 AND dfg/extractor.rs:7192 — flag it; consolidation is VAL-011's concern.)

## TDD (failing first)
Add a test in `language_policy.rs`: a `match` over EVERY `Language` variant (no `_ =>` wildcard) asserting
`policy_for(lang)` returns the expected explicit row — this both documents the table and FAILS TO COMPILE if a
new language is ever added without a policy entry (exhaustiveness). Add a second test asserting Python.builtins
is non-empty and (e.g.) TypeScript.builtins is empty and TypeScript.module_alias_style == None while
Python.module_alias_style == DottedSuffix. RED before the module exists, GREEN after.
Run: `env TLDR_NO_DAEMON=1 cargo test -p tldr-core --lib language_policy` then the full core lib suite.

## HARD CONSTRAINTS
- Edit ONLY: new file `crates/tldr-core/src/language_policy.rs` + `crates/tldr-core/src/lib.rs` (module decl).
  AST/data only, NO regex. No consumer wiring (that is VAL-011/012) — so the parity gate MUST be 0-delta.
- No clippy suppressions (`#[allow(...)]`). If clippy flags the new unused-until-VAL-011 policy, make items
  `pub` (they are public API for the next steps) rather than allow-dead-code.
- Leave changes UNCOMMITTED. Do NOT stage/codesign/install/run check_parity.py — orchestrator owns
  build+codesign+gate+commit. `git diff --name-only` must show ONLY the two files.

## WHEN DONE report worker_done with
(1) files changed, (2) the per-language `module_alias_style` table you produced with the path_to_module
evidence for each (esp. which langs are None vs DottedSuffix and why), (3) test names + RED→GREEN,
(4) full core-lib pass count, (5) diff is only the 2 files, (6) the PYTHON_BUILTINS-duplication note.
