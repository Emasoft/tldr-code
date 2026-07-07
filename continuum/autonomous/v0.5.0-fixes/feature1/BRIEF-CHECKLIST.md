# Calls-Touching Brief Checklist (precision-program-v1 iron-rule discipline)

Fill this out BEFORE dispatching any worker whose fix can affect the `calls` graph
(builder_v2.rs, resolution.rs, type_aware_resolver.rs, path_to_module, importers, or anything
feeding func_index/class_index/ModuleImports). Born from the W1-3 and W2-29 failures — both were a
Python-specific mechanism applied cross-language via a name/shape heuristic with no language guard.

## 1. MECHANISM PRE-VERIFICATION (orchestrator reads the code FIRST)
- [ ] I READ how the mechanism the fix touches is computed. It is (circle one):
      **language-partitioned** (explicit `language == "..."` / `Language::X` guard)  —OR—
      **shape/name heuristic** (`module.starts_with`, `.contains('.')`, `is_python_style`,
      capitalized-receiver, builtin-name lists, etc.) that happens to be true for several languages.
- [ ] If shape/name heuristic: I listed EVERY language for which it fires (not just the target one).
      A "lua-only" or "python-only" fix on such a mechanism is a cross-language change in disguise.

## 2. ADDITIVE-ONLY on shared mechanisms
- [ ] The fix ADDS a higher-priority resolution path / guard. It does NOT remove, gate, or repoint an
      existing shared path. (Every additive fix in the campaign passed; the one subtractive fix, W2-29,
      leaked and flipped and was reverted.)
- [ ] If the fix cannot be expressed additively (some existing edge must move/disappear), the brief
      instructs the worker to STOP and escalate via decision_gate — never ship the subtractive change.

## 3. ISOLATION-RISK FLAG
- [ ] Risk = HIGH if the mechanism is a shape/name heuristic OR the fix touches index population /
      resolution ordering. Risk = LOW if language-partitioned AND command-local (e.g. inheritance-only,
      references-only) with no `calls` reachability.
- [ ] HIGH-risk fixes MUST run the canary smoke-gate (§4). LOW-risk fixes may skip straight to the full gate.

## 4. CANARY SMOKE-GATE (HIGH-risk only, before the full 8-min gate)
- [ ] Orchestrator runs: `bash canary_smoke_gate.sh "<target-language repos>"`
      (auto-adds rust/kotlin/cpp/python canaries — the exact langs the reverted W2-29 broke).
- [ ] ANY delta on a canary = leak → ABORT + redesign. Only a clean canary earns the full gate.

## 5. WORKER CONSTRAINTS (paste into every brief)
- [ ] Edit ONLY the named file(s) + the test; AST-only, NO regex on source.
- [ ] Failing-first TDD; then full `env TLDR_NO_DAEMON=1 cargo test -p tldr-core --lib` (and cli if touched).
- [ ] Leave changes UNCOMMITTED; do NOT stage/codesign/install/run check_parity.py (orchestrator owns
      build+codesign BOTH binaries+canary+full gate+commit).
- [ ] `git diff --name-only` shows ONLY intended file(s); revert fmt spillover via `git checkout-index`.
- [ ] Report worker_done with: files changed, root cause, test name + RED→GREEN, full-suite pass count,
      clean-diff confirmation.

## 6. ORCHESTRATOR GATE (§gate_one_fix.sh)
- [ ] `bash gate_one_fix.sh "<allowed files csv>" [--calls]` → PASS requires
      `flips_on_unique_name==0 && removed_unreviewed==0`.
- [ ] Restored-correct net-new edges: reviewed (verify leaf/owner + 0 target-lang-mismatch) → allowlisted
      in expected_deltas.json → re-gate PASS → commit. Else REVERT (worker via `git checkout-index`).
