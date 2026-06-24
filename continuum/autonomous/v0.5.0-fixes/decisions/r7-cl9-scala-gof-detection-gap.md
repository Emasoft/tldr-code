# R7 cluster[9] design-fork: Scala GoF design-pattern detection gap

**Cluster:** [9] patterns-smells
**File:** `crates/tldr-core/src/patterns/languages/scala.rs`
**Classification:** design-fork (from reaudit-rootcause.json analysis[9])
**Bug:** #226 (scala-zio) — two halves
**Status:** star_imports half FIXED; GoF-detection half DEFERRED (Option B documented)

## Two distinct halves

The audit finding #226 conflates two separable issues in `scala.rs`:

1. **`star_imports` always "none"** — `detect_import` only pushed the whole
   import text into `absolute_imports` and never inspected the trailing
   `._` wildcard, so a repo with hundreds of `import zio._` reported
   `star_imports: none`. This half is a **fixable-root-cause**.

2. **No GoF design-pattern detection** — `ScalaSemantics` never calls
   `design_patterns.push_pattern`, so Scala companion-object Singletons,
   `apply`-method Factories, and sealed-trait ADTs are never surfaced.
   This half is a **design-fork**.

## star_imports — FIXED (this campaign)

`detect_import` now detects the AST node kind `namespace_wildcard` (the
tree-sitter-scala representation of the trailing `._`) and pushes an
`Evidence` into `import_patterns.star_imports`. A SELECTIVE brace import
(`import x.{a, b}` -> `namespace_selectors`) is deliberately NOT counted,
because it imports named members, not a wildcard. Char-tests:
`scala_wildcard_import_registers_star_imports` (wildcard -> star) and
`scala_selective_brace_import_is_not_star` (brace -> not star) in
`crates/tldr-core/tests/pack_patterns_lib_v1.rs`.

## GoF detection — design-fork

### Option A — implement a Scala GoF detector
Mirror `solidity.rs`/`php.rs`: detect companion `object` + `apply` =
Factory/Singleton, `sealed trait` + `case class` family = ADT/Visitor,
etc., via tree-sitter node kinds.

Trade-off: substantial net-new per-language work. Critically, the SAME gap
exists for Kotlin, C++, C, Ruby, Swift, and Lua (only Solidity, PHP, and
OCaml-functor are implemented). Implementing Scala alone makes the
`patterns_by_language` design-pattern accounting MORE asymmetric across
languages and interacts with the #224 metadata reconciliation. A correct
treatment is a cross-language design-pattern initiative, not a one-language
patch bolted on during a closeout fix wave.

### Option B — declare GoF detection intentionally scoped, document it
Keep design-pattern detection limited to the currently implemented
languages (Solidity, PHP, OCaml) and document that idiom-category patterns
(naming, imports, error-handling, etc.) are the supported Scala output.

Trade-off: honest and low-risk, but leaves Scala's `design_patterns`
array empty.

## Decision: Option B for this wave (GoF deferred), star_imports fixed

Rationale:
- The star_imports half is a clean root-cause fix and is shipped now.
- A Scala-only GoF detector would be incomplete relative to the six OTHER
  languages with the same gap, and would distort cross-language
  `patterns_by_language` counts right after #224 was reconciled. Per the
  build-complete mandate, the correct scope is "all GoF-less languages"
  as a deliberate, separately-planned initiative — not a single-language
  carve-out during closeout.
- No accuracy DEFECT remains from this decision: the absence of Scala GoF
  patterns is a known coverage boundary, not a false positive/negative
  against emitted output. (Contrast the star_imports half, which WAS a
  defect against observable wildcard imports and is fixed.)

## Follow-up (out of this wave's scope)

A cross-language GoF design-pattern initiative covering Scala, Kotlin,
C++, C, Ruby, Swift, and Lua, with consistent `patterns_by_language`
accounting. Tracked as the natural extension of pack-patterns-v1.

## Blast radius

star_imports change: Scala-only, additive (`import_patterns` command +
`patterns`). No GoF code was added, so `patterns_by_language.scala` and the
`design_patterns` array are unchanged in shape — the #224 reconciliation
holds.
