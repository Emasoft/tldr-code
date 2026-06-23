# RC7 — invariants trace-typer defaults unresolved values to `string`; Rust optionality renders `is Some` for non-Option returns

**Cluster:** invariants-specs (analysis[7]); command: invariants (feeds verify's invariants pathway)
**Classification:** research-needed -> filed as fork. NOT implemented in this closeout.
**File/fn:** `crates/tldr-cli/src/commands/contracts/invariants.rs` : `observed_value_from_json` (~L681), `non_null_expression` (~L416), `lang_type_word` (~L264); fed by specs' `try_eval_literal` (`crates/.../specs.rs` ~L1073) which records raw argument TEXT.

## Problem (two coupled facets)

### Facet 1 — default-to-string (the research-needed core)
The invariants engine is a Daikon-lite trace miner with NO runtime traces and NO
signature typing. When a test passes a VARIABLE (`$lines`, `$expected`) or any
non-int/bool/null literal, the spec records the literal's SOURCE TEXT;
`observed_value_from_json` maps a JSON string -> `ObservedValue::String` -> type
`string` (or the language's string spelling). So nearly every
object/array/Result argument is typed `string`.

Live: IDX 152 `php-guzzle` `isHostInNoProxy(string, array): bool` -> all params
typed `string` (the `array` arg is a variable, recorded as text -> String).
23/25 PHP type-invariants say `string`.

This cannot be fixed without one of:
- **(a)** intra-test reaching-definitions (resolve `$lines = [...]; f($lines)` so
  the array literal types the arg), or
- **(b)** borrowing the SOURCE function SIGNATURE from the contracts type engine
  (`types.rs`) to type params/returns instead of trace literals.

Both are real dataflow/coupling changes, which is why the analysis marked RC7
**research-needed**, not mechanical.

### Facet 2 — Rust `is Some` for every non-null return (the "isolated" sub-issue)
`non_null_expression(Rust, _)` unconditionally returns `"{var} is Some"`
(L436). The `infer_non_null_invariant` fires whenever NO `None` value was
observed (L1183). But:
- The `ObservedValue` lattice has NO Option/Result discrimination. A Rust
  `Result<T,E>` return asserted via `assert_eq!(get_id(), Ok(7))` arrives as
  `ObservedValue::String("Ok(7)")` (because `try_eval_literal_inner`'s
  `call_expression` arm falls to the raw-text default, `specs.rs` ~L1192), so it
  is BOTH mis-typed `&str` AND rendered `is Some` (should be `is Ok`).
- Worse, a plain non-Option Rust return (e.g. `i64`) ALSO gets `result is Some`
  even though it is not an `Option` at all — the NonNull invariant is a
  Python-centric "value present" notion that does not map onto Rust's
  by-default-non-nullable values.

## Why NOT a mechanical one-liner (no-guessing)

A symptom-level patch ("if Rust, say `is Ok`") would be a GUESS — most Rust
returns are neither Option nor Result, and the lattice carries no evidence to
choose. The correct, AST-driven fix recognizes the constructor at the spec-
extraction boundary: when `try_eval_literal_inner` sees a `call_expression`
whose callee identifier is `Ok`/`Err`/`Some`/`None` (or the bare `None`
identifier), emit a STRUCTURED optionality marker (a new lattice element, e.g.
`ObservedValue::Optionish{kind}`), thread it through the specs->invariants JSON
bridge, and have `non_null_expression` render `is Ok`/`is Err`/`is Some`
accordingly — and SUPPRESS the NonNull invariant entirely for plain values with
no optionality evidence. That is a lattice + bridge + rendering change across
`specs.rs` and `invariants.rs`, not an isolated edit.

## Attribution

PRE-EXISTING mechanism (`observed_value_from_json` default-to-string + variable-
name recording). Campaign `4a762e1` FIXED the orthogonal Python-idiom leak
(Java/C#/Kotlin no longer show `str`/`NoneType`/`is not None` — the T2
`lang_type_word`/`non_null_expression` matrices, confirmed by the bug reports'
own "FIXED" notes). The default-to-string typing and the Rust `is Some`-for-
Result gaps were never addressed by the campaign.

## Options

| Option | Scope | Risk | Effect |
|---|---|---|---|
| **A — intra-test reaching-defs** | Add a lightweight reaching-definition pass over the test function so `x = <literal>; f(x)` types `x` by the literal. | adds a dataflow pass to the shared spec extractor | Types array/object args correctly (fixes most PHP/Kotlin/Rust string-default cases). |
| **B — borrow signature types** | Type params/returns from the contracts type printer (`types.rs`) instead of trace literals. | couples invariants to the contracts type engine | Most accurate types; abandons pure Daikon-lite trace semantics. |
| **C — Rust optionality lattice** | Recognize `Ok`/`Err`/`Some`/`None` ctors at `try_eval_literal` (AST-driven), add an `Optionish` lattice element, render `is Ok`/`is Err`/`is Some`, and suppress NonNull for plain non-Option values. | lattice + JSON-bridge + rendering change | Fixes the Rust Some/Ok defect AND stops over-claiming `is Some` on non-Option returns. |

## Blast radius

`observed_value_from_json` + the type/non_null inference feed ALL invariants
output. B couples invariants to `types.rs`. A/C add a dataflow/lattice change to
the spec extractor used by BOTH specs and invariants. Medium-high. (The T2
matrices are already pinned by tests; C changes the Rust NonNull rendering and
must re-baseline any Rust invariants goldens.)

## Recommendation

Pursue **C** first (it is the bounded, AST-driven, no-guessing fix for the named
Rust defect and removes the over-claim), then **A** for the broader default-to-
string typing (highest corpus-wide impact, keeps Daikon-lite semantics). Reserve
**B** only if signature-accurate typing becomes a product requirement. Filed as a
fork because all three are genuine dataflow/typing-architecture changes — exactly
the "syntactic call-scrapers with no link to the type system" root the analysis
called out — and must be designed coherently rather than guessed per-symptom.

## Pointers
- `crates/tldr-cli/src/commands/contracts/invariants.rs`: `observed_value_from_json`
  (~L681), `non_null_expression` (~L416), `lang_type_word` (~L264),
  `infer_non_null_invariant` (~L1172), `infer_type_invariant` (~L1137).
- `crates/tldr-cli/src/commands/contracts/specs.rs`: `try_eval_literal_inner`
  raw-text `_` default (~L1192) — the AST recognition point for Option/Result
  ctors (Option C).
- Signature typing source (Option B): `crates/tldr-cli/src/commands/contracts/types.rs`.
