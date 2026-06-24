# R7 cluster[9] design-fork: PHP Factory name-only heuristic

**Cluster:** [9] patterns-smells
**File:** `crates/tldr-core/src/patterns/languages/php.rs`
**Classification:** design-fork (from reaudit-rootcause.json analysis[9])
**Bugs:** #150 / #158 (php-symfony-console)
**Status:** RESOLVED — Option A implemented (precision over name-only recall)

## Problem

The PHP Factory detector matched purely on method NAME prefix
(`create*` / `make* `/ `build*` / `new*`) via `is_factory_method_name`,
with a non-abstract / non-`constructs_new` else-branch that emitted
"class `X` exposes a factory method `Y`" on a pure name match. This
produced false positives on methods that are named like a factory but do
NOT construct an object:

- `OutputStyle.newLine()` returns `void` (writes a newline)
- `ProgressBar.buildLine()` returns `string` (builds a display line)
- `Client.buildUri()` returns `UriInterface` (transforms an input URI; no
  `new`)

Verified live on php-symfony-console: 10 Factory hits, of which the
name-only branch fired for `ReStructuredTextDescriptor`, `ProgressBar`
(buildLine), `TerminalInputHelper`, `SymfonyStyle` — all semantically weak.

## Options considered

### Option A — precision (require evidence of construction)
Drop the pure name-only "exposes a factory method" branch. A class is a
Factory only when:
- it has a method that actually constructs an object (`constructs_new`
  via an `object_creation_expression` in the body), OR
- it declares an `abstract` factory method (the Abstract Factory pattern —
  construction is delegated to a concrete subclass and is genuinely a
  factory contract), OR
- the class is named `*Factory` AND has a `constructs_new` method
  (existing branch, unchanged).

Trade-off: eliminates `newLine`/`buildLine`/`buildUri` FPs. May miss a
factory that delegates ALL construction to a helper (no `new` in its own
body, not abstract, not `*Factory`-named) — but such a method is
indistinguishable from a transformer by name alone, so flagging it was a
guess, not a detection.

### Option B — keep recall, relabel
Keep the name match but lower confidence and reword the evidence to
"method named like a factory (unverified)". Trade-off: retains recall but
the findings stay semantically weak; a consumer cannot trust them.

### Option C — Option A + return-type-is-class signal
Extend Option A so the non-abstract branch ALSO fires when the method's
declared return type is a class/interface (`named_type`), not a
scalar/void (`primitive_type`). Trade-off: `buildUri(): UriInterface`
returns a class type but does NOT construct it (it transforms an input),
so this would STILL flag `buildUri` — re-introducing one of the three
documented FPs. Rejected for that reason.

## Decision: Option A

The audit treats these as accuracy defects, and the project mandate
(AST-driven, root-cause, no name/substring heuristics for structure)
favours precision grounded in actual construction over name-pattern
recall. Construction is observable in the AST
(`object_creation_expression`); a factory-ish NAME is not evidence. Abstract
factory methods are kept because the abstract declaration IS the factory
contract.

The return-type-class signal (Option C) was rejected specifically because
`buildUri(): UriInterface` proves return-type alone cannot distinguish a
factory from a transformer.

## Implementation

In `PhpSemantics::detect_class`, the Factory emission keeps three precise
triggers and drops the name-only else-branch:
1. `factory_method.is_abstract`  -> "declares an abstract factory method"
2. `factory_method.constructs_new` -> "builds instances via `new`"
3. `class_named_factory && any constructs_new` -> "(named *Factory)
   constructs instances via `new`" (pre-existing, unchanged)

A factory-named method with neither `abstract` nor `constructs_new` no
longer emits a Factory pattern.

Legitimate `...::create() { return new X(); }` factories
(`RequestException.create`, `CurlFactory.create`, `HandlerStack.create`)
go through trigger #2 and are unaffected.

## Blast radius

PHP-only (`php.rs` Factory detection in `patterns`). No other language and
no other command consume this branch. Char-tests added in
`crates/tldr-core/tests/pack_patterns_lib_v1.rs`:
`php_factory_requires_construction_not_just_name` (FP guard) and
`php_factory_detects_constructs_new` (recall guard for real factories).
