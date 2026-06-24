# R7 cluster[9] cross-cluster spillover: complexity.rs + extract.rs roots

**Cluster:** [9] patterns-smells
**Classification:** fixable-root-cause, but the ROOT lives OUTSIDE this
cluster's editable files (`complexity.rs`, `extract.rs`).
**Status:** NOT fixed in this cluster — root files belong to other clusters
(`Edit ONLY your file(s)` constraint). Documented for the orchestrator.

This cluster's editable files are the patterns detector
(`patterns/**` + `types/patterns.rs`) and `quality/smells.rs`. Three
analysis[9] root causes have their TRUE root in files owned by other
clusters and were intentionally left untouched here.

---

## 1. #19/#35/#138 — complexity name-keyed map collides same-name overloads

**Root file:** `crates/tldr-core/src/metrics/complexity.rs`
(`calculate_all_complexities_from_tree`, L167: `results.insert(name,
metrics)` — `HashMap<String, ComplexityMetrics>`).

**Mechanism:** the map is keyed by bare function NAME, so C++'s five
`ShallowEqual` overloads (and C# `CalculateSize`, OCaml same-name clauses)
overwrite each other; only the last-visited metric survives. The smells
loop then iterates every same-named `FunctionInfo` and looks up the single
shared metric, emitting it at each distinct line (tinyxml2: 5x cyclo 11).

**Why not fixed here:** the consumer in MY file
(`smells.rs::maybe_add_long_method_smell`) does
`complexity_map.get(&func.name)`. The only way to make the smells
attribution line-accurate is to key complexity by `(name, line)` — which
requires changing `complexity.rs`'s public map signature and every other
consumer (`complexity`/`cognitive`/`halstead`/`debt`/`health`/`todo`).
That file is the complexity cluster's; the orchestrator noted complexity
was handled in R7 wave 1 (commit a6db7af). Wave 1 fixed cyclomatic/cognitive
COUNTING logic but did NOT change the name-keyed `insert` collision
(verified: complexity.rs:167 still `results.insert(name, metrics)`).

**No symptom-patch applied.** Re-deriving a parallel line-aware complexity
map inside smells.rs would duplicate complexity.rs's traversal and risk
drift — a symptom workaround, which the constitution forbids. The correct
fix is the `(name,line)` (or `(name,start_row)`) key in complexity.rs.

**Recommended owner:** complexity cluster. Change `results` to
`HashMap<(String,u32),ComplexityMetrics>` keyed by `(name, start_row)`;
update `smells.rs::maybe_add_long_method_smell` to look up by
`(func.name, func.line_number)`. (The smells-side one-line lookup change is
trivial once the map is line-aware; I will make it the moment the map API
is line-aware, but cannot land it unilaterally without editing
complexity.rs.)

---

## 2. #73 — Go long_parameter_list counts named return values as params

**Root file:** `crates/tldr-core/src/ast/extract.rs` (Go function
extraction, ~L3000-3084 — `func.params` ingests the named-result tuple).

**Mechanism:** for `func (...) TrySet(value, field, tagValue, opt) (isSet
bool, err error)`, the extractor populates `func.params` with BOTH the 4
real params AND the 2 named results, so smells reports 6 params (verified
live: TrySet flagged "6 parameters", source has 4).

**Why not fixed here:** the over-count originates in `extract.rs`'s
`FunctionInfo.params` population. `smells.rs::maybe_add_long_parameter_smell`
faithfully reports `func.params.len()`; truncating it in smells would be a
guess (smells cannot know which entries are named returns). `extract.rs` is
the structure cluster's file (commit f8b7514). Fixing it there also
corrects `structure`/`calls`/every FunctionInfo consumer.

**Recommended owner:** structure/extract cluster. Populate Go `func.params`
from ONLY the first `parameter_list` child, excluding the result tuple
(the result is already read separately for `return_type`).

---

## 3. #84 — JS expression-methods invisible to smells/complexity

**Root file:** `crates/tldr-core/src/ast/extract.rs` (JS extraction —
does not lift `obj.method = function(){}` / `proto.x = ()=>{}`
assignment-expressions into `module_info.functions`/`methods`).

**Mechanism:** js-express `application.js` defines 16 methods as
`app.handle = function(){}` style assignment expressions; `extract_file`
never surfaces them, so smells/health/debt/todo only see the top-level
`sendfile`.

**Why not fixed here:** this is an extractor-coverage gap in `extract.rs`
(structure cluster). smells.rs consumes whatever `extract_file` returns; it
cannot synthesise functions the extractor omitted.

**Recommended owner:** structure/extract cluster. Recognise
`assignment_expression` where RHS is `function_expression`/`arrow_function`
and LHS is a `member_expression`, lifting them into
`module_info.functions`/`methods` with the LHS property name and correct
line. Note: this re-baselines many JS outputs (higher impact) and should be
staged with broad JS corpora.

---

## 4. #206 residual — Scala `case object` / sealed marker as lazy_element

**Root file:** `crates/tldr-core/src/ast/extract.rs` (Scala class
extraction does not record the declaration FLAVOR — `case object` vs
`class` vs sealed marker — in `ClassInfo`).

**Status of the ORIGINAL #206 bug:** FIXED in this cluster. The audit
finding was that `Stack.scala:24` (a class WITH 17 methods) was reported
`lazy_element 0/0` because smells used a broken `count_class_members`
walker instead of the canonical member counts. After re-pointing
`detect_lazy_elements_with_path`/`detect_data_classes_with_path` to
`extract_file`, `Stack` (and Rust `Arg`, Solidity `RoleData`) are correct:
`Stack` no longer appears as lazy_element (verified live on scala-zio).

**Residual (NOT the original bug):** zio has ~260 `case object`s and sealed
marker classes that GENUINELY have 0 methods / 0 fields (e.g.
`case object RingBufferPow2Type extends BenchQueueType("...")`). The
canonical extractor now reports these accurately as 0/0, and lazy_element
flags them. A Scala `case object` is an idiomatic ADT-variant / enum-like
singleton, not a "lazy class that doesn't justify itself", so flagging it
is noisy — but it is a SEPARATE concern from the audited #206 defect (which
was about members-bearing classes mis-counted as empty).

**Why not fixed here:** distinguishing a `case object` / sealed marker from
an ordinary empty class requires the declaration flavor, which `ClassInfo`
does not carry (`kind=None` for all Scala classes; `bases` is shared by
case objects and ordinary classes alike, so it is not a reliable
discriminator). Adding a Scala declaration-flavor field is `extract.rs`
work (structure cluster). Inventing a name/text heuristic in smells.rs
would violate the AST-driven, root-cause mandate.

**Recommended owner:** structure/extract cluster — record Scala
declaration flavor (`case object` / `object` / `sealed`) on `ClassInfo`,
then smells.rs can exempt case-objects / sealed-markers from lazy_element
in one line. (smells.rs follow-up once the flavor exists: `if class.kind
== Some("case_object") { continue }`.)

## Summary

| Bug | Root file | Owner cluster | smells.rs follow-up once root fixed |
|-----|-----------|---------------|-------------------------------------|
| #19/#35/#138 | complexity.rs | complexity | look up complexity by `(name,line)` |
| #73 | extract.rs (Go) | structure | none (params become correct upstream) |
| #84 | extract.rs (JS) | structure | none (functions appear upstream) |
| #206 residual | extract.rs (Scala) | structure | exempt case-object/sealed from lazy |

The original #206 defect (members-bearing class reported 0/0) IS fixed in
this cluster; only the case-object-is-noisy residual needs the upstream
declaration-flavor field.

All three were verified live and are real defects; none was patched at the
symptom in this cluster to avoid masking the upstream root (per
ROOT-CAUSE-not-symptom).
