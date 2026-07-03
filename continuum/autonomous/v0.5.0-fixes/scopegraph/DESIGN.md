# DESIGN — Scope-Graph Name Resolution for Lua/Luau (`self:method` vs lexical-local)

Author: architect (lead)
Created: 2026-07-02
Status: PLAN — ready for staged implementation
Scope gate: **lua + luau only**; the other 15 languages MUST be byte-for-byte unchanged.
Safety invariant: **NEVER-WORSE** (changes prune, never add wrong keys); every stage re-passes the 37-repo differential gate.

---

## 1. Problem

`tldr`'s cross-file call-graph resolver keys functions in a **flat `(module, name) -> Vec<FuncEntry>` index** (`FuncIndex`, `types.rs:659`). This is a Lisp-1 namespace collapse: a member/method reference and a lexical-variable reference share one keyspace. Concretely, a Lua/Luau colon call

```lua
self:setState(...)
```

can bind to a **same-file lexical local closure** named `setState` instead of the inherited `Component:setState` (defined in another file). The wrong local is frequently **split-declared**:

```lua
local setState                       -- bare declaration (no initializer)
function Foo:init()
    setState = function(...)         -- later assignment, in a NESTED scope
        return self:setState(...)
    end
end
```

VERIFIED live (report 6, binary v0.4.1) at `luau-roact/src/Component.spec/{render,shouldUpdate,didUpdate}.spec.lua`: **5 wrong `method` edges** — `init->setState`, `setState->setState` self-loops — bind the local closure. ~20 genuine same-file and cross-file colon-method edges into `Component.lua` must stay correct.

### 1.1 Root cause (VERIFIED at source)

- `lua.rs:790-841` (`variable_declaration` branch) tags `is_lexical_local = true` ONLY when a **single statement** carries both the `variable_list` name AND a `function_definition` initializer (`local x = function ... end`). A **bare** `local setState` has `has_function == false` and emits **nothing**.
- The later `setState = function ... end` falls into `lua.rs:843-853` (`assignment_statement` branch), which unconditionally emits `FuncDef::function(name, ...)` with `is_lexical_local == false` — identical to a global function or a table-field assignment. The extractor has **no cross-statement / block-scope memory**, so the split declaration is structurally invisible. This is exactly prior failed fix (3).
- `luau.rs:987-991` is strictly worse: it tags **even the single-statement** `local foo = function()` as plain `FuncDef::function` (never `lexical_local`). The Luau frontend has **zero** `is_lexical_local` coverage.

### 1.2 The correct-shaped primitive already exists

- `FuncDef.is_lexical_local` (`cross_file_types.rs:338`) + `FuncDef::lexical_local` ctor (`:388`), propagated to `FuncEntry.is_lexical_local` via `with_lexical_local` at `builder_v2.rs:160` and `:806`.
- It is consulted at **exactly three colon-call-gated sites** in `resolution.rs`, all reached only when `is_colon_receiver(...)` (lua/luau colon spelling, `:1850`) is true:
  1. `resolve_self_receiver_in_current_file` (`:1901`)
  2. `resolve_local_fuzzy_match` (`:2417`)
  3. `resolve_global_fuzzy_match` (`:2596`)
  Each calls `colon_target_is_lexical_local(entry)` (`:1869`, a one-line `entry.is_lexical_local`) and **prunes** the candidate. This is already documented and gate-proven as monotone-negative: a real colon method (`is_lexical_local == false`) is retained.

**The architecture is already the right shape (prune-only, two definer classes). The only defect is that `is_lexical_local` is under-populated.** The fix is a lexical-scope pass that populates it correctly — NOT a new resolution engine.

### 1.3 Prior failed fixes (MUST NOT repeat)

| # | Attempt | Why it failed |
|---|---------|---------------|
| 1 | positive `is_method` + `class_name` attribution | cross-class same-name collisions, 700+ edge blast |
| 2 | language `lua -> luau` redetection | repo-wide reparse regression |
| 3 | `is_lexical_local` **emission-time** tag | cannot see split `local` decl + later assignment |

Our approach is **subtractive** (never re-attributes `class_name`), **per-handler** (no language redetection), and **block-scope-resolved** (not single-node emission) — directly avoiding all three.

---

## 2. Approach decision

Three candidate mechanisms were evaluated (all six research reports converge):

### Option A — Adopt the `stack-graphs` Rust crate (github/stack-graphs 0.14.1, MIT/Apache-2.0)
Replaces the flat `FuncIndex` resolver with a partial-path-stitching engine + partial-path DB (maintainers call the rusqlite backend "slow in practice", issue #306). It is the canonical realization of the exact namespace separation we need, but adopting it: (i) forks the resolver into two engines (stack-graphs for lua, `FuncIndex` for 15 langs); (ii) re-derives **every edge** through a new substrate — a direct, global threat to the 37-repo differential gate at every stage; (iii) requires a hand-authored `.tsg` per language (none exists for Lua/Luau); (iv) upsets the daemon perf budget. **Disproportionate to one resolution bug. REJECT (keep as correctness oracle only).**

### Option B — Author a Lua/Luau `.tsg` on `tree-sitter-stack-graphs`
Still pulls in the whole stitching engine AND adds a thousands-of-lines DSL (GitHub's TS `.tsg` ≈ 6k lines) to spec `:` vs `.`, metatables/`setmetatable`, closures, Roact `:extend`, and split decl+assign — a second resolution path for lua/luau only. **Over-engineering + fork risk. REJECT.**

### Option C — Bespoke minimal per-file lexical-scope layer over the existing `FuncIndex` (CHOSEN)
Reproduce stack-graphs' load-bearing principle — *member-access references and lexical-variable references are distinct reachability paths; a lexical local is structurally unreachable from a member-call lookup* — **inside the existing resolver** using the live `is_lexical_local` primitive. Two structural ideas are lifted (design only, not code):

1. **GUARD:MEMBER separation** → tldr already has it: colon-call sites (`is_colon_receiver`, AST-detected `receiver:method`) prune `is_lexical_local` candidates. We do not add it; we make it *effective* by populating the flag.
2. **Declaration-anchored binding** (the `.tsg` `variable_declarator` stanza creates the binding at the `local NAME` decl regardless of any initializer) → we anchor `is_lexical_local` to the `local NAME` **declaration** via a block-scope pass, not to the `NAME = function` assignment. This is precisely what defeats split decl+assign.

**Rationale (effort / risk / perf / never-worse / blast radius):**

| Criterion | Option C |
|-----------|----------|
| Effort | Low–moderate: a block-scope pass in `lua.rs`/`luau.rs`; core milestones touch **no** shared resolution code. |
| Risk | Lowest: reuses the 3 already-proven, gate-passing prune sites unchanged for the core fix. |
| Perf | One extra AST pass per lua/luau file during extraction (no new parse); daemon-cacheable; zero cost for 15 langs. |
| Never-worse | Intrinsic: the flag is read ONLY on the lua/luau colon path and only ever prunes. Non-colon and non-lua/luau edges cannot change. |
| 15-lang isolation | Total: changes live in `lua.rs`/`luau.rs` `extract_definitions`; every other handler emits `is_lexical_local == false` exactly as today. |

**DECISION: Option C.** Stack graphs / scope-graph theory (ESOP15 path well-formedness, Scopes-as-Types associated scopes, Stack Graphs file-incrementality) are cited as the correctness/monotonicity authority and used to validate gate diffs — not vendored.

---

## 3. Architecture & data structures

### 3.1 Where the scope knowledge lives

`is_lexical_local` is a property of the **definition** (does an enclosing block `local`-declare this name?). The **reference site does not change** whether a definition is a lexical local. Therefore the core fix computes the flag **at extraction time** and consumes it via the existing prune sites — **no** `FileIR` schema change, **no** `ResolutionContext` field, **no** `call_line` threading are required for the primary deliverable. (Those are introduced only in the optional hardening milestones M3/M4, and only if a reference-site-dependent decision genuinely needs them.)

### 3.2 `LexicalScopeTree` (extractor-local helper, NOT persisted for M1/M2)

A private helper shared by `lua.rs` and `luau.rs` (new module `languages/lua_scope.rs`, or private fns in each handler with a shared node-kind map). It models Lua/Luau block nesting by **line-range containment**, reusing the proven `enclosing_class_for_call` technique (`resolution.rs:205`, smallest-span-wins), so **no byte-offset infrastructure is needed** — `FuncDef`/nodes already expose 1-indexed `line`/`end_line`.

```
struct BlockScope {
    start_line: u32,       // scope-opening node start (1-indexed)
    end_line:   u32,       // scope-opening node end
    // names introduced by `local`/`local function`/params/for-vars in THIS block,
    // each with the decl line (for Lua's after-declaration visibility rule)
    locals: Vec<(String /*name*/, u32 /*decl_line*/)>,
}

struct LexicalScopeTree { blocks: Vec<BlockScope> }   // one per file, all scopes flat

impl LexicalScopeTree {
    // True iff `name` is bound by a `local` in some block whose [start,end] contains
    // `at_line`, with decl_line <= at_line (after-declaration visibility). Nested
    // scopes resolve to an ANCESTOR block automatically (a wider block also contains
    // at_line). This is what catches render.spec.lua: `local setState`@107 in the
    // `it(...)` body [104..138] dominates `setState = function`@109 nested in Foo:init.
    fn binds_local(&self, name: &str, at_line: u32) -> bool { ... }
}
```

**Pass 1 (collect):** walk the tree once; at each **scope-opening node** open a `BlockScope` with its line range; record every **binding-introducing** name into the nearest enclosing block.
**Pass 2 (classify):** the existing `extract_definitions` walk; when it emits a `FuncDef` from an `assignment_statement` whose LHS is a **bare identifier** `NAME` at line `L`, set `is_lexical_local = true` iff `tree.binds_local(NAME, L)`. `local x = function` (single-statement) keeps its existing lexical tag; `function T:m`, `function T.m`, `M.f = function`, and global `function f` stay `false`.

All classification is **pure tree-sitter node-kind/field inspection** (AST-driven mandate; no regex, no name hardcoding — the fix must generalize beyond the literal name `setState`, per report 6's 19 corpus split-decl sites).

### 3.3 Optional persistence (M3/M4 only)

If hardening needs reference-site scope info, persist `FileIR.lexical_scopes: Vec<BlockScope>` with `#[serde(default, skip_serializing_if = "Vec::is_empty")]` (empty for all 15 other langs; **no `IR_VERSION` bump**, mirroring the `is_lexical_local` / `VarType.scope` additive idiom), thread it into `ResolutionContext` as a borrowed field, and thread `call_site.line` into `resolve_call_with_receiver` (available at `builder_v2.rs:622` and `:656`).

---

## 4. Per-language scope rules (lua + luau)

Anchor node names to **tree-sitter-lua 0.2.0** (the grammar that parses BOTH the `luau-roact` `.lua` corpus — where the 5 bugs live — and the `lua` handler). Provide a **parallel node-name map** for **tree-sitter-luau 1.2.0** (the `.luau` conformance corpus). Node names verified against the current `lua.rs`/`luau.rs` extractors (`function_declaration`, `variable_declaration`, `assignment_statement`, `variable_list`, `expression_list`, `function_definition`, `dot_index_expression`, `method_index_expression`, `identifier`).

### A. Scope-opening nodes (each opens a nested block scope)
- `chunk` / program — the FILE top scope; also the implicit vararg function body. **File-level `local setState` is a LEXICAL local** — the actual bug case.
- `function_declaration` body, `function_definition` body (anonymous `function ... end`, e.g. the `it(...)` / `createSpy(...)` callbacks).
- `do_statement`, `while_statement` body, `for_statement` body, `if_statement`/`elseif`/`else` bodies, `repeat_statement` (quirk: the `until` condition still sees body locals — model the repeat scope to span through `until`).

### B. Binding-introducing nodes (add name(s) to the current block)
- `variable_declaration` with `local`: every `variable_list` identifier — **including bare `local setState` with no initializer**. Visibility begins at the first statement AFTER the decl (Lua manual 3.5) → enforce `decl_line <= at_line`.
- `function_declaration` with a leading `local` token (tree-sitter-lua aliases `local function f` to `function_declaration`): binds `name` **before** the body (recursion). Disambiguate local-vs-global by **leading-token inspection** (`local` child) + name-field kind — NOT by node kind alone.
- `parameters`: each param identifier. Plus a synthesized implicit `self` binding when the enclosing `function_declaration` name is a `method_index_expression` (`function T:m`).
- `for_numeric_clause` / `for_generic_clause`: loop vars, scoped to the loop body.
- (Luau) `const` contextual keyword: treat like `local`. Type annotations (`x: T`) add no bindings; the annotation `:` lives inside `parameters`/`variable_declaration`, structurally distinct from `method_index_expression`'s method `:` — no collision.

### C. Two namespaces (distinct reachability — the GUARD:MEMBER analog)
- **LEXICAL** (bare identifiers): `function_call` `name == identifier`; identifier-as-value. Resolves up the block chain -> file/module -> global.
- **MEMBER** (qualified): `dot_index_expression{table, field}` (`a.b`) and `method_index_expression{table, method}` (`a:b`). Resolves via the receiver's class/type; **LEXICAL locals are unreachable here** (the existing colon prune).

### D. Definition classification (sets `is_lexical_local`)
| Form | `is_lexical_local` |
|------|--------------------|
| `function f` (name=identifier, no `local`) | false (module/global) |
| `local function f` (identifier + `local` token) | **true** |
| `function T.m` (name=`dot_index_expression`) | false (member, no self) |
| `function T:m` (name=`method_index_expression`) | false (member, +implicit self) |
| `local f = function ... end` (single-stmt) | **true** (already handled in lua.rs; ADD to luau.rs) |
| `local f` … `f = function ... end` (SPLIT) | **true** ← classify by `binds_local(f, assign_line)` (THE FIX) |
| `M.f = function` (LHS=`dot_index_expression`) | false (member) |

### E. Resolution of `self:setState()` (unchanged path; now correctly gated)
1. Target is `method_index_expression` → MEMBER namespace; `is_colon_receiver` true.
2. `self`/`this`/`cls`/`Self` receiver → `resolve_self_receiver_in_current_file` / fuzzy fallbacks.
3. The wrong same-file `setState` def now carries `is_lexical_local == true` → **pruned** at all 3 sites → falls through to class/base lookup (M4) or declines.

### F. Monotonic fallback (never-worse valve)
The prune only fires when `colon_call == true`. A plain-identifier call (`setState({})`, category d) never consults the flag, so same-file closures remain reachable to plain calls. If the member-restricted lookup yields zero candidates, resolution declines (emits no edge) rather than binding the local — the gate then sees a REMOVED wrong edge, never an ADDED wrong one.

---

## 5. Integration points

| Concern | Location | Milestone |
|---------|----------|-----------|
| Block-scope pass + split-decl classification (Lua) | `languages/lua.rs` `extract_definitions` (`:745`) + new `LexicalScopeTree` helper | M1 |
| Same pass + simple-case gap (Luau) | `languages/luau.rs` `extract_definitions` (`:871`) | M2 |
| Flag propagation (unchanged) | `builder_v2.rs:160`, `:806` `with_lexical_local` | — |
| Colon-call prune sites (unchanged for M1/M2) | `resolution.rs:1901`, `:2417`, `:2596` | — |
| Mirror direction: plain-call prefers lexical/plain over same-file colon-method | `resolution.rs` `pick_disambiguated_entry` (`:2123`), `resolve_intra_call` (`builder_v2.rs:441`) | M3 |
| Positive cross-file re-resolution `self:setState -> Component:setState` | luau/lua class-table `:extend` modeling (built on `d.6`, `luau.rs:880-1000`), `resolve_method_in_bases` | M4 |
| Optional persistence + `call_line` threading | `FileIR.lexical_scopes`, `ResolutionContext`, `resolve_call_with_receiver` sig | M3/M4 (only if needed) |

**Core deliverable (fix the 5, keep the ~20) is achieved by M1+M2 with ZERO shared-resolution-code changes.**

---

## 6. Milestones (M0..M4)

Each milestone: rebuild (`cargo build --release`), **re-`codesign --force --sign - <binary>`** (per OPS memory: skipping this SIGKILLs the binary), install, then run the differential gate. A stage passes only when the gate prints `PARITY: PASS` with an owner-pinned allowlist of exactly the intended deltas.

### M0 — Baseline + RED acceptance tests (no source change)
- **Goal:** Reproduce the bug through the REAL `extract_definitions -> FileIR -> resolve` pipeline (the existing cl-7 tests hand-build `FuncIndex` and cannot exercise the split-decl parse). Capture/confirm the gate baseline.
- **Touches:** new tests in `crates/tldr-core/src/callgraph/languages/lua.rs` (+ luau) and/or a pipeline test module; `feature1/scopegraph_expected.json` allowlist scaffold. **No `crates/*/src` analysis code.**
- **Gate expectation:** `PARITY: PASS`, **0 delta** (current == baseline; no source change).
- **Acceptance:** new pipeline test that feeds the exact `local setState` / `setState = function() return self:setState(...) end` shape through `extract_definitions` **FAILS** (RED) — proving the split-decl is reproduced end-to-end. Cluster `luau-setstate` cell reads `still_buggy`.

### M1 — Lua block-scoped lexical pass (fixes the 5 setState)
- **Goal:** Correctly tag `is_lexical_local` for split-decl (and all bare-`local`) closures in the **Lua** handler; the 3 existing prune sites then decline the 5 wrong bindings.
- **Touches:** `languages/lua.rs` (add `LexicalScopeTree` + pass; classify `assignment_statement` LHS via `binds_local`), new unit + pipeline tests. **`resolution.rs` unchanged.**
- **Gate expectation:** `PARITY: PASS`. Deltas confined to `luau-roact` (parsed as `lua`): the 5 wrong `method` edges REMOVED (+ any consequential removals), **all owner-pinned in `scopegraph_expected.json` as `type:removed`**. `flips_on_unique_name == 0`, `removed_unreviewed == 0`, `added_unreviewed == 0`. MUST-KEEP set (Sec 7) intact. Cluster `luau-setstate`: `still_buggy -> fixed` (or `improved`). The 8 latent split-decl closures (report 6) get tagged but produce **no edge delta** (no colliding base method today).
- **Acceptance:** Sec 7 edges 1–21, 31 (lua-parsed subset).

### M2 — Luau parity port (completeness)
- **Goal:** Port the identical pass to the **Luau** handler, which today has ZERO `is_lexical_local` coverage (even the single-statement case). Verify tree-sitter-luau 1.2.0 node names via the parallel map.
- **Touches:** `languages/luau.rs` (`extract_definitions` `:871`; fix `:987-991` simple-case gap + add split-decl), tests.
- **Gate expectation:** `PARITY: PASS`. Deltas confined to `.luau` repos (`luau` conformance): any newly-tagged closures' colon edges removed, owner-pinned. `asserttriple->magnitude` (classes.luau block method, `is_lexical_local==false`) **preserved**. 0 flips_on_unique, 0 unreviewed.
- **Acceptance:** Sec 7 edge 31; luau-conformance split-decl closures no longer bound by colon calls; simple-case parity with lua.

> **After M2 the primary spec is COMPLETE: the 5 setState over-binds are fixed, the ~20 correct edges are kept, monotone/never-worse, gate-green, lua/luau-only.** M3–M4 extend to same-root-cause latent cases and are each independently gated — hold the milestone (do not ship) if it cannot pass cleanly.

### M3 — Mirror direction: plain-call scope-kind preference (hardening)
- **Goal:** Fix the `calls.luau` `deep`/`a.deep` collision (report 6 edges 39–40): a PLAIN identifier call must prefer a lexical/plain candidate over a same-file colon-method; today `pick_disambiguated_entry` is file-match-only and binds the wrong method.
- **Touches:** `resolution.rs` `pick_disambiguated_entry` (`:2123`) + `resolve_intra_call` (`builder_v2.rs:441`) to consult `call_type` + `is_lexical_local`/`is_method` symmetrically. If reference-site scope is needed, introduce `FileIR.lexical_scopes` + `call_line` threading (Sec 3.3).
- **Gate expectation:** `PARITY: PASS`. `calls.luau` `deep->deep` (currently `deep->a.deep`) flip + `a.deep->a.deep` added, owner-pinned. **0 regressions on the M1/M2 kept sets** (edges 6–10 category-d plain calls MUST stay). This touches shared `pick_disambiguated_entry` (all langs) — the cardinality-1 fast path guarantees file-unique-key languages are byte-for-byte identical; verify with the full 37-repo gate.
- **Acceptance:** edges 39–40; edges 6–10 unchanged.

### M4 — Positive cross-file re-resolution (completeness)
- **Goal:** Turn the 5 declined `self:setState` from "removed" into the CORRECT cross-file edge to `Component.lua:setState` by climbing the class/`:extend` chain (Roact copy-`extend` single-level; luvit `Object:extend` prototype chain). Builds on `d.6` luau class-table modeling + `resolve_method_in_bases`.
- **Touches:** `languages/luau.rs`/`lua.rs` class modeling (`register_*_class`, `*_extend_base`), `resolution.rs` base-climb.
- **Gate expectation:** `PARITY: PASS`. The 5 edges become `type:added` into `Component.lua` (owner-pinned `dst_file`), replacing the M1 `removed` allowlist entries. 0 flips_on_unique. Also targets report-6 edge 41 (`net.lua self:on -> core.lua:on`) as a same-root-cause follow-on.
- **Acceptance:** edges 1–5 resolve to `Component.lua:setState`; edge 41.

---

## 7. Acceptance-edge test set (corpus-grounded, binary-verifiable)

Verify with `env TLDR_NO_DAEMON=1 tldr calls <dir> --format json` under `/Users/cosimo/.tldr-audit/corpora/<repo>`.

**MUST-FIX (currently wrong same-file `method` edges; post-fix = decline [M1] OR `Component.lua:setState` [M4] — never the local closure):**
1. `luau-roact` didUpdate.spec.lua `init->setState`
2. didUpdate.spec.lua `setState->setState` (self-loop)
3. render.spec.lua `setState->setState` (self-loop)
4. shouldUpdate.spec.lua `init->setState`
5. shouldUpdate.spec.lua `setState->setState` (self-loop)

**MUST-KEEP — plain-call reachability to same-file closures (category d, never-worse):**
6. render.spec.lua `<module>->setState` [intra]
7. shouldUpdate.spec.lua `<module>->setState` [intra]
8. didUpdate.spec.lua `<module>->setState` [intra]
9. willUpdate.spec.lua `<module>->setComponentState` [intra]
10. setState.spec.lua `<module>->setComponentState` [intra]

**MUST-KEEP — Component.lua genuine same-file colon methods (11 edges):**
11–21: `__mount->{__getDerivedState,__update,__validateProps,render}`, `__resolveUpdate->render`, `__update->{__getDerivedState,__resolveUpdate,__validateProps}`, `__validateProps->getElementTraceback`, `setState->{__getDerivedState,__update}`.

**MUST-KEEP — cross-file colon methods into Component.lua (9 edges):**
22–30: context.spec.lua `captureAllContext->__getContext`, `init->__addContext`, `init->__getContext`; getElementTraceback.spec.lua `init->getElementTraceback`; RobloxRenderer.spec.lua `init->__addContext`, `init->__getContext`; createContext.lua `init->__addContext`, `init->__getContext`; createReconciler.lua `unmountVirtualNode->__unmount`.

**MUST-KEEP — other regression guards:**
31. `luau` classes.luau `asserttriple->magnitude` [method]
32. Binding.lua `<module>->getValue` [method]
33. SingleEventManager.lua `connectEvent->_connect`
34. SingleEventManager.lua `connectPropertyChange->_connect`
35–37. `lua-luvit` net.lua `listen/onListen/onRead -> core.lua:emit`

**MUST-STAY-ABSENT (negative — do not manufacture false edges):**
38. Component.lua internals MUST NOT gain edges to `shouldUpdate/willUpdate/didUpdate/willUnmount` (undefined lifecycle hooks; 0 edges today).

**STRETCH (M3/M4; do NOT gate the primary fix on these):**
39. `calls.luau` `deep->deep` (currently `deep->a.deep`)
40. `calls.luau` `a.deep->a.deep` (currently dropped)
41. `net.lua` `self:on -> core.lua:on` (currently 0 edges; needs class-hierarchy walk)

---

## 8. Never-worse rollout strategy

1. **Read-site containment:** `is_lexical_local` is consulted ONLY under `colon_call &&` at the 3 sites, and `colon_call` is `matches!(language, "lua"|"luau") && exact "{receiver}:{bare}" spelling`. No non-lua/luau language and no non-colon call can reach the flag. Tagging more defs lexical is therefore invisible to all other resolution.
2. **Prune-only:** every consulting site *drops* a candidate; none adds a key. Adding label structure can only remove regex-illegal (member->lexical) paths — the ESOP15 monotonicity result. A name unique to one definer keeps its single legal path and still resolves (name-match preserved).
3. **15-lang isolation:** all M1/M2 code is inside `lua.rs`/`luau.rs` `extract_definitions`; every other handler's `FuncDef` defaults `is_lexical_local == false`, unchanged. `#[serde(default, skip_serializing_if)]` keeps cached IR/JSON byte-for-byte identical for them (no `IR_VERSION` bump).
4. **Gate-guarded stages:** each milestone rebuilds + codesigns + re-runs `check_parity.py` over the 37/38 corpus repos. FAIL channels (a flip / b added / c posctl / d removed / hard-error) must be clean or owner-pinned. Intended deltas are declared in `scopegraph_expected.json` with required `dst_file` owner pinning, so a future owner-flip re-trips the gate.
5. **Monotone stage ordering:** M1 (lua, direct 5-edge fix) → M2 (luau parity) deliver the spec with no shared-code risk. M3 (shared `pick_disambiguated_entry`) and M4 (base-climb) are higher-risk and last; each is independently gate-gated and **held** (not shipped) if it cannot pass — the product still ships at M2.
6. **Positive control:** the constructor-typed-receiver posctl cluster cell must stay `correct` at every stage (rule c).
7. **No `cargo publish`** without explicit user authorization regardless of gate verdict (memory).

---

## 9. How this fixes the 5 setState AND keeps the ~20

**Fixes the 5:** At `render/shouldUpdate/didUpdate.spec.lua`, `local setState` (e.g. render.spec.lua:107) is a bare decl in the `it(...)` callback body [104..138]; `setState = function(...) return self:setState(...) end` (line 109) is nested in `Foo:init()`. M1's `LexicalScopeTree.binds_local("setState", 109)` finds the ancestor `local setState`@107 (block contains 109, 107<=109) → the assignment's `FuncDef` is tagged `is_lexical_local = true`. The `self:setState(...)` colon call (`is_colon_receiver == true`) now hits the prune at `resolve_self_receiver_in_current_file` / the fuzzy fallbacks → the local closure is declined → the 5 wrong `method` edges disappear (M1: removed/declined; M4: re-pointed to `Component.lua:setState`). The fix is name-agnostic (tags `setComponentState`, `getParentStateCallback`, etc. too), matching report 6's 19 corpus split-decl sites.

**Keeps the ~20:**
- **Genuine colon methods** (`function Component:__mount`, `:setState`, `:__getContext`, …) are `method_index_expression` `function_declaration`s — never a bare-`local`-declared identifier — so `binds_local` never tags them; `is_lexical_local == false`; they bind exactly as today (edges 11–30).
- **Plain-call reachability** (`setState({})`, `setComponentState(...)`) are NOT colon calls; the prune is gated behind `colon_call`, so these intra edges are untouched (edges 6–10).
- **Block methods** (`function magnitude(self)` in classes.luau) are plain `function_declaration`s, not `local`, so `is_lexical_local == false` → `asserttriple->magnitude` preserved (edge 31).
- **Cross-file unique-name colon methods** (`self:emit -> core.lua:emit`) go through the fuzzy fallbacks which retain non-lexical candidates → edges 35–37 preserved.
- **Negative:** undefined lifecycle hooks stay 0-edge (edge 38); the fix only removes wrong bindings, never adds.

The differential gate is the mechanical proof: after each stage it shows ONLY the owner-pinned intended deltas and `PARITY: PASS`, with the MUST-KEEP set present and `flips_on_unique_name == 0`.

---

## 10. Risks & mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Over-pruning: a def wrongly tagged lexical removes a correct colon edge | Med | Prune fires only on colon calls to a bare-`local`-bound name; a genuine colon method is never bare-local; gate MUST-KEEP set (11–31) + `flips_on_unique_name==0` catch any over-prune. |
| tree-sitter-luau 1.2.0 node-name divergence from lua 0.2.0 | Med | M2 ships a parallel node-name map; unit tests parse real `.luau` fixtures through `extract_definitions`; verify `method_index_expression`/`variable_declaration` equivalents before wiring. |
| Nested-scope miss (assignment resolves to wrong ancestor block) | Med | Line-range containment resolves to ANY enclosing block (ancestor-safe); the render.spec.lua nested case is a pinned pipeline test (M0 RED → M1 GREEN). |
| Shared `pick_disambiguated_entry` change (M3) perturbs other langs | High | Cardinality-1 fast path keeps file-unique-key langs byte-identical; full 37-repo gate + hold-if-fail; M3 is optional to the core spec. |
| Baseline contains the 5 wrong edges → removals need review | Low | Expected: allowlist as `type:removed` with `dst_file` after review; `removed_audit` documents each. |
| Corpus rot / `/tmp` corruption inflating deltas | Med | Corpora pinned at `~/.tldr-audit/corpora` (memory); run gate with `TLDR_NO_DAEMON=1`; 3× stable-intersection capture already jitter-proofs. |
| Binary SIGKILL after rebuild | Med | `codesign --force --sign - <binary>` after every build (OPS memory) before running the gate. |
| Daemon serves stale IR after schema touch (M3/M4 only) | Low | Additive `#[serde(default, skip_serializing_if)]`, no `IR_VERSION` bump; empty `lexical_scopes` for 15 langs; `TLDR_NO_DAEMON=1` for gate runs. |
| Performance regression on large repos | Low | One extra AST pass per lua/luau file, no reparse; O(blocks) line-range table; zero cost for other 15 langs. |

---

## 11. Open questions
- M4 re-resolution vs decline: is turning the 5 into `Component.lua:setState` edges required for "keep the 15", or is decline sufficient? (Report 6: decline OR resolve both satisfy MUST-FIX; M1 decline is the safe floor, M4 is the completeness ceiling.)
- Should `LexicalScopeTree` be persisted on `FileIR` proactively (VarType precedent, enables M3/M4 without re-plumbing) vs kept extractor-local until a milestone needs it (smaller M1/M2 surface)? Recommendation: extractor-local for M1/M2; persist at M3 only if a reference-site query is required.
