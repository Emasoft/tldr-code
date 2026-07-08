# Worker Brief — VAL-013 (m1-language-policy): shape-heuristic audit

Repo: `/Users/cosimo/Desktop/PatchWork/tldr-code` (cd there for EVERY command). **`review` archetype** —
audit the codebase coldly against the contract; evidence only. Read-only EXCEPT the single report file you
write. Report `worker_done`.

## Mission
W1-3 (`PYTHON_BUILTINS` without a language guard) and W2-29 (`is_python_style` shape heuristic) were the
SAME bug class: a language-specific mechanism applied cross-language via a name/shape test. VAL-011/012
killed those two instances. Your job: find any REMAINING instance in `crates/tldr-core/src/` before a user
does. For every finding, classify it — do NOT fix anything.

## Classification (exactly one per finding)
- **BUG-CLASS**: name/shape predicate that changes cross-language behavior with NO language guard
  (the is_python_style class). These become VAL-013 follow-up fixes.
- **PARTITIONED-SAFE**: inside an explicit `language == ...` / `Language::X` match arm, or the consuming
  code path is provably single-language. Cite the guard line.
- **DOCUMENTED-SAFE**: shape test with cross-language reach that is nonetheless correct-by-design
  (e.g. checks a structural property all languages share). Requires a written WHY.

## Mandatory checklist (from the contract — audit each explicitly)
1. `resolve_capitalized_receiver` — `crates/tldr-core/src/callgraph/resolution.rs:2350` (capitalized-name
   ergo class-receiver guess: which languages does it fire for? is `language` consulted?).
2. `module_matches` — `crates/tldr-core/src/analysis/importers.rs:199` (it takes `language: Language` —
   verify every arm actually partitions, no shared fallthrough shape test).
3. Every `starts_with` / `ends_with` / `contains` applied to a MODULE NAME, PATH-AS-MODULE, or SYMBOL NAME
   in `callgraph/` (builder_v2.rs, resolution.rs, module_path.rs, type_aware_resolver.rs, imports).
4. `is_builtin_method_name` + `is_stdlib_type` (resolution.rs:1410/1361) — builtin/stdlib NAME lists: which
   languages consult them? Python-only names leaking into other langs' resolution?
5. `constructor_method_candidates` (resolution.rs:131) + `receiver_is_type_spelling` (resolution.rs:2057) +
   `is_colon_receiver` (resolution.rs:2117) — spelling-based receiver classification.
6. `bare_class_name` (resolution.rs:1628) and any `split('.')`/`split("::")` suffix-taking on qualified names.
7. Sweep the rest: `grep -n "starts_with\|ends_with\|\.contains(" crates/tldr-core/src/callgraph/*.rs` and
   triage every hit that tests a NAME (not a language tag, not a filesystem path for I/O).

## Method (per finding — claim-verification discipline)
READ the function and at least one CALLER before classifying. Record: file:line, the predicate, which
languages can reach it (trace the call path), classification, and for BUG-CLASS a one-line additive-fix
sketch (which LanguagePolicy field would replace it). Grep hits alone are hypotheses, not findings.

## Output (the ONLY file you write)
`continuum/autonomous/precision-program-v1/reports/VAL-013-audit.md` — a table:
`# | file:line | predicate | reachable langs | classification | evidence (guard line / caller trace) | fix sketch (BUG-CLASS only)`
plus a SUMMARY block: counts per classification and a verdict line:
`BUG-CLASS instances found: N` (N=0 means the class is extinct after VAL-011/012).

## HARD CONSTRAINTS
- READ-ONLY on all source. Write ONLY the report file. NO code edits, NO tests, NO cargo commands needed
  (this is static reading). Do NOT run check_parity.py.
- Classify against BEHAVIOR you traced, not names/comments. If uncertain between PARTITIONED-SAFE and
  BUG-CLASS, mark BUG-CLASS?-UNCERTAIN with what you'd need to confirm — do not silently downgrade.

## WHEN DONE report worker_done with
(1) the report path, (2) total findings + counts per classification, (3) the BUG-CLASS list (file:line +
one-liner each) or "none", (4) confirmation you wrote nothing but the report.
