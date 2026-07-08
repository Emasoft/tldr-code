# Worker Brief — VAL-013-FIX (m1-language-policy): policy-gate the 7 mechanical BUG-CLASS findings

Repo: `/Users/cosimo/Desktop/PatchWork/tldr-code` (cd there for EVERY command). `implement` archetype, TDD.
Report `worker_done`. BEHAVIOR-PRESERVING intent — parity gate MUST be 0-delta (iron rule). HIGH isolation-risk
(canary + full gate on orchestrator side). Input: the audit at
`continuum/autonomous/precision-program-v1/reports/VAL-013-audit.md` (findings #1-5, #7, #8).

## Pattern (identical to committed VAL-012 — reuse its helper)
`module_uses_dotted_alias(&language)` (builder_v2.rs, from VAL-012) is the canonical predicate:
`Language::from_str` → `policy_for(lang).module_alias_style == AliasStyle::DottedSuffix`, unknown → false.
If a target file can't see the builder_v2 private helper, move/copy the ONE-LINER into a shared home
(`language_policy.rs` as `pub fn module_uses_dotted_alias(lang_str: &str) -> bool`) and have builder_v2 +
stats bin + your new sites all call THAT (single source; builder_v2's private copy is then removed).

## The 7 sites (each: gate the bare-suffix alias/probe with the policy predicate; change NOTHING else)
1. **builder_v2.rs:178 + 199** (`build_indices_parallel` fn + Class.method twin): same swap VAL-012 did in the
   live loop. NOTE: its returned indices are DISCARDED on the main path (builder_v2.rs:756) — this is a
   consistency fix for tests/external callers; expect literally 0 behavioral delta.
2. **module_index.rs:384**: the GENERIC `simple_module_name(module)` alias registered before the
   `match self.language` arms. Gate it: only register when `module_uses_dotted_alias(&self.language)`.
   Do NOT touch the language-specific alias arms at 390-559.
3. **resolution.rs:826-region** (direct import-map fallback): the `simple_module = module_path.split('.')
   .next_back()` probe (used ~884-892). Gate the simple-module PROBE with the policy predicate (the
   `language` is available in `resolve_call`'s context — trace how it reaches this block; if it needs a
   parameter thread, keep the thread minimal). Keep every other probe (exact, extension-stripped, bare
   relative, full-module) untouched and in order.
4. **resolution.rs:2224-region** (`resolve_module_import_receiver`): same — gate the `simple_module` probe at
   ~2238-2247 with the policy predicate; the full-module probe at ~2229 and the reexport fallback stay as-is.
   `context.language` is available in `ReceiverLookupContext`.
5. **resolver.rs:61** (legacy `ModuleResolver::index_file` alias): gate with the policy predicate using
   `self.language` (set via `with_language`).
6. **resolver.rs:204-210** (legacy `resolve_function` bare-suffix fallback): same gate.
7. **resolution.rs:757-region** (dynamic-import substring): wrap
   `target.contains("__import__") || target.contains("importlib")` so it only fires for Python
   (`language == "python"` — the string is right there; an explicit language check is correct here, this is
   a Python-name test not an alias-style question). TS/JS `target == "import"` guard at ~761 unchanged.

## WHY 0-delta is expected
Read-side probes (#3,#4,#6) query alias keys that — post-VAL-012 — only EXIST for DottedSuffix languages, so
gating the probe for None-languages turns dead lookups into skipped lookups. Write-side (#1 discarded, #2
generic ModuleIndex alias, #5 legacy) mirror the VAL-012 argument: divergence only for dot-containing module
strings in None-languages. The 38-repo gate is the arbiter. If the orchestrator's gate reports deltas you
will receive the list — no heuristic tinkering; policy values are the only tunable.

## TDD (failing first)
One focused test per REPRESENTATIVE mechanism (not all 7): (a) ModuleIndex: a None-language (TS) module does
NOT get the generic bare-suffix alias, a DottedSuffix language (Python) does; (b) legacy ModuleResolver: same
pair through `index_file`/`resolve_function`; (c) resolution.rs:757: a non-Python target named e.g.
`importlib_shim` RESOLVES (is not forced unresolved), while Python `importlib.import_module` still warns.
RED→GREEN each. Then FULL suites: `env TLDR_NO_DAEMON=1 cargo test -p tldr-core --lib` and
`cargo build --bin callgraph_resolution_stats`.

## HARD CONSTRAINTS
- Edit ONLY: builder_v2.rs, module_index.rs, resolution.rs, resolver.rs, language_policy.rs (if you relocate
  the helper), bin/callgraph_resolution_stats.rs (only if the helper moves) + test code. NO regex, NO clippy
  `#[allow]`. Alias/probe ORDER and first-writer guards unchanged — predicate gating only.
- Findings #6 (capitalized-receiver, resolution.rs:2357), #9, #10, #11 are OUT OF SCOPE (documented-deferred
  to m3) — do NOT touch them.
- Leave UNCOMMITTED. No stage/codesign/install/check_parity.py. `git diff --name-only` = only intended files.

## WHEN DONE report worker_done with
(1) files changed, (2) per-site one-line before/after, (3) where the shared helper lives now, (4) test names
+ RED→GREEN, (5) full core-lib pass count + stats-bin compile, (6) confirmation #6/#9/#10/#11 untouched.
