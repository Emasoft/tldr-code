# tldr — Product Decisions (owner: user, captured 2026-07-06)

## D1 — Positioning: AI-AGENTS-FIRST
tldr's primary consumer is **AI agents**, not humans. Agents cannot sanity-check a
confident wrong answer, so **honesty is the #1 priority.**
- Consequence: the **honesty layer** (P1 — confidence field `certain/likely/guess` +
  decline-don't-guess on `dead`/`impact`/`definition`) is pulled FORWARD in priority.
- Consequence: every correctness fix in this campaign should prefer **decline over guess**
  on genuinely-ambiguous cases (the "stop lying" half), consistent with the triage.

## D2 — NEW FEATURE (backlog): emit LINE NUMBERS in output
For agent speed: include `file:line` (and where useful `:col`) on emitted symbols/edges so
an agent can jump straight to the code and read it itself instead of re-searching.
- Rationale: agents read faster with a direct pointer; complements the honesty layer
  (a "guess" edge the agent can immediately go verify at the cited line).
- Slot: fold into the honesty/output-format work (same output-schema pass as the
  confidence field). NOT part of the current 14-fix correctness campaign — logged for after.
- Scope note: many commands already carry spans internally (structure/definition); this is
  about surfacing them consistently across `calls`/`impact`/`references` output.

## D3 — Gate policy for the campaign
- Restored-correct edges (e.g. W1-3's builtin-in-non-Python restorations) are **allowlisted
  per-fix** (reviewed, generated from the gate verdict — never hand-written).
- The gate **baseline is regenerated ONCE, at campaign completion** (P0-2), so future
  never-worse checks compare against a CORRECT reference. The per-fix allowlist entries are
  temporary scaffolding until that regen.

## D4 — Process gap to close (P0-2, after the fixes)
The differential gate can only catch REGRESSIONS, not PRE-EXISTING bugs (its baseline was
captured from a buggy binary). Institutionalize the **two-round correctness audit** as a
standing, per-release ground-truth check, and track a **correctness %** KPI per language.

## D5 — W2-29 DEFERRED (documented deferral; precision-program-v1 VAL-003) — 2026-07-07
The W2-29 additive redesign was attempted (one timeboxed worker pass, Codex) and **found there is
no clean additive fix to make.** The investigation is the finding:
- The prior SUBTRACTIVE attempt (removing the `builder_v2.rs` bare-suffix alias for lua) was reverted:
  it removed 11 real non-lua edges (rust/kotlin/cpp) and caused 3 within-lua `flips_on_unique_name`.
- The additive path was to make the already-higher-priority full-dotted lookup (path A in
  `resolve_module_import_receiver`, resolution.rs:2229) *match* for lua. But it **already matches**:
  Codex verified `ModuleImports` stores `U -> a.util` and `path_to_module`/ModuleIndex canonicalize
  relative `a/util.lua` to key `a.util`, so `local U=require("a.util"); U.helper()` already resolves to
  the correct full-dotted owner on HEAD. The exact reproduction fixture is **green with no code change**.
- Therefore the residual W2-29 "defect" only manifests as **differential-gate FLIPS on the Roblox
  corpus** — cases where the bare alias currently binds owner X and full-dotted would bind owner Y, with
  **no static way to decide which is correct without ground truth.** That is a Bucket-A (undecidable)
  case, not a Bucket-B plumbing fix.
- **Disposition:** deferred to **m2 (benchmark harness → ground-truth to adjudicate X vs Y)** and
  **m4 (scope-substrate → principled cross-module same-name resolution)**. **CLEAN DEFERRAL — zero code
  change:** the reproduction test was validated (green on HEAD, proving path A already matches for
  relative requires) then removed; the worker left the tree byte-clean and builder_v2.rs untouched.
  This D5 entry is the guard-of-record against a naive re-attempt of the reverted subtractive approach.
  (Re-adding the green regression test as a permanent guard is an optional follow-up for m1/m4.)
- **Net for m0:** campaign closes at **13 fixes committed + 1 documented-deferred (W2-29)**, not 14 shipped edits.
