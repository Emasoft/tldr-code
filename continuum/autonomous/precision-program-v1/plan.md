# tldr Precision Program v1 — Plan

Date: 2026-07-07 · Repo: /Users/cosimo/Desktop/PatchWork/tldr-code · Contract: contract.json (11 milestones, 43 assertions)

## Mission

Take tldr from "~80% correct with no confidence signal" to the tool the research says nobody ships:
**measured, confidence-graded, decline-not-guess resolution + cross-file dataflow, delivered at a token budget.**
The strategic argument (research session `code-intel-unbundling`): the commodity code-graph layer is occupied
(Graphify: 7/7 of the old gap spec, but name-matching-shallow — skips cross-file method calls entirely — and
dataflow-blind). The moat is resolution soundness + dataflow depth. This program builds the moat.

Source documents (read together):
- `continuum/autonomous/tldr-correctness-audit/{PLAN.md, GROUND-TRUTH-DESIGN.md, RESOLVER-TRIAGE-DECISION.md, RESEARCH-arxiv.md, reports/CORRECTNESS.md}`
- 2026-07-07 resolver-campaign handoff (12/14 fixes @ f34cd03; W2-29 root cause; tracks A–D)
- Research syntheses: `~/.opc-dev/opc/continuum/research/code-intel-unbundling/findings.md` and
  `~/.opc-dev/opc/continuum/research/sound-resolution-dataflow/findings.md`

## Confidence model (threads every milestone — PLAN.md convention, extended)

| Tier | Source | Trust |
|------|--------|-------|
| T0 | harvested: LSP callHierarchy · bytecode/IR · runtime trace | ground truth (when fresh) |
| T1 | scope-graph resolution · flow-sensitive type inference · signature index | high |
| T2 | tree-sitter name/arity heuristics (today's default) | low — must be LABELED |
| T2-llm-candidate | bind-or-reject LLM adjudication of unresolved sites | candidate — never acted on by decline-mode commands |

Extension over PLAN.md (from research H-105): every edge also carries **staleness**
(source content-hash + generated-at). Stale T0 is DEMOTED below fresh T1/T2 — a stale-precise edge
silently outranking a fresh-approximate one is the failure mode of every two-tier system we surveyed.

## Milestones

### m0 — campaign-close (track A) [small]
Close the resolver-precision campaign. Rebuild+install from HEAD first — **the installed binary is the
failed W2-29 build** (VAL-001 exists because gating anything against it poisons every result after).
W2-26 is a straightforward additive relabel. W2-29 per the redesign spec: keep the bare-suffix alias
(it is a cross-language mechanism — C++/Kotlin/Rust resolutions ride it), add a higher-priority lua
dotted-require path; timeboxed, deferral acceptable. Then regenerate the gate baseline (user approval —
VAL-004) folding the W1-3/W2-13 allowlist batches, and check in the discipline (gate wrapper, canary
script, brief-template checklist) so the iron rule survives handoffs.

### m1 — language-policy (track B, narrow) [med]
Kill the W2-29/W1-3 bug class: Python mechanisms applied cross-language via shape heuristics.
`LanguagePolicy` = per-language data table; `PYTHON_BUILTINS` → `policy.builtins`; `is_python_style` →
`policy.module_alias_style`. **Scope discipline: this is a refactor with 0-delta gates, not a platform.**
Do NOT grow it into the full per-language adapter trait yet — that abstraction gets grown in m6/m8 when
the type/dataflow engines demand it (growing it speculatively now = designing it wrong). VAL-013 is the
third-instance audit; known candidates to check: `resolve_capitalized_receiver` (resolution.rs — capitalization
⇒ class is wrong-by-convention in Go/Elixir/OCaml/Rust), `module_matches` (analysis/importers.rs).

### m2 — benchmark-harness [med] ★ before anything precision-claiming
The parity gate proves *never-worse*; it cannot prove *better*. Everything from m3 on claims improvement,
so the absolute harness must exist first. Three truth sources (GROUND-TRUTH-DESIGN.md §3): CATS-style
feature checklists, PyCG micro-benchmarks, real repos with LSP/trace-harvested edges. Measured **per
resolution rung** — that per-rung breakdown is what makes m3's tier mapping honest (we will KNOW T2's
actual precision instead of asserting "low"). VAL-024 sanity-checks the two gates against each other by
replaying the 12 committed fixes.

### m3 — honesty-layer (track C) ★ the launchable feature [med]
Nearly free to compute (the cascade already knows which rung resolved each edge) and the exact gap every
competitor has (research: Graphify's tags binary, Sourcegraph's badges static, nobody declines, nobody
grades). Schema change is breaking → approval gate VAL-030 first. Per-command policy from
GROUND-TRUTH-DESIGN.md §2: precision-critical (`dead`/`impact`/`definition`) DECLINE on T2;
recall-oriented (`calls`/`context`) approximate + label. Line numbers in output ride along (agent-speed).
MCP exposure (VAL-036) is what makes this legible to agent consumers — the actual buyers.
**This milestone + m2's numbers = the public claim: "measured per-edge precision, graded confidence,
declines rather than guesses." Publish both together.**

### m4 — scope-substrate (track D / PLAN phase 3) [larger]
Highest-leverage single move per PLAN.md: extend the FEATURE-1 stack-graph substrate (arXiv:2211.01224)
to Bucket-B defects (cross-module, qualified same-name, out-of-line) AND make it file-incremental +
SQLite-persisted, killing 10k-file cold-index latency. One move = precision (~80→90%+) and scalability.
This is Layer 1; it precedes the type engine because types bind to names — inference built on ambiguous
name resolution inherits the ambiguity. Baseline churn is expected: staged per-language re-baseline with
reviewed diffs (VAL-042), not silent regeneration.

### m5 — signature-index [med] ★ highest-ROI type-engine component
Both research workers independently converged: external/imported **return-type resolution is the single
biggest recall lever** for dynamic-language call graphs (PyCG 0.19 → Jarvis 0.35 recall class of gain).
Standalone value before any inference exists. Additive-only: a new higher-priority resolution path.
Sources: inline annotations (all langs), typeshed (Python), .d.ts (TS), explicit sigs (Go/Rust/Java).

### m6 — type-engine (Layer 2) [large]
The HeaderGen/Jarvis recipe (research H-102: 95.6%p/95.3%r on call edges, no compiler): per-function
flow-sensitive type graphs — assignments, constructors, returns, annotations, strong updates — feeding
receiver resolution. Python first, then TS, then two more, each enabled via LanguagePolicy + a thin
transfer-function adapter and gated on its truth-harness suite (VAL-062 enforces "adapters, not forks").
Bucket-A undecidables are NOT guessed (VAL-061 — honesty policy is load-bearing here). Do NOT chase
Andersen/k-CFA: needs SSA + heap modeling a tree-sitter IR can't give (H-101), and the honest ceiling
(PLAN.md: dynamic recall capped ~65–90%) is stated, not hidden. ML type predictors are rankers, not
drivers (~25% exact-match on user-defined receiver types) — they appear only in m9, if at all.

### m7 — harvest-t0 (PLAN phase 4) [large]
Bucket A's real answer: the compiler/runtime already solved it — harvest, don't re-derive.
LSP callHierarchy first (broadest coverage): opt-in, demand-driven slices, daemon-warm pool
(**never cold per-call** — measured ~10× slower than grep, research H-105), content-hash cached,
reusing the diagnostics shell-out pattern. VAL-071's staleness demotion is the novel piece — design it,
don't improvise it. Bytecode/IR and runtime-trace harvest are tier 2–3 (VAL-073, scoped or explicitly
deferred). Never-worse: harvest absent ⇒ byte-identical output.

### m8 — dataflow-depth [large]
Cross-file slice/taint via the proven recipe (research H-103/H-104, POPL'24 Demanded Summarization —
which ships this exact combination ON tree-sitter): per-function compositional summaries, demand-driven
stitching, per-summary salsa invalidation. Three non-negotiable architecture decisions baked into
assertions: (1) ONE language-agnostic dataflow core + thin adapters (CodeQL InputSig — never 17 forks);
(2) unknown callees default to labeled sound over-approximation (Joern pattern); (3) library semantics
as Models-as-Data files, never hardcoded. Market note (H-104): every incumbent paywalls cross-file
dataflow — tldr giving it away is the differentiated move.

### m9 — llm-residue [med, optional]
For edges static analysis provably can't decide (reflection, duck-typed dispatch, DI). Hard invariants
from research H-106: bind-or-reject only, demand-driven over the existing unresolved list only (TICR:
94.5% reduction in adjudication volume), cached, off by default, and decline-mode commands ignore the
tier entirely. LLM builds context FOR the graph's gaps; it never builds the graph (arXiv:2410.00603).

### m10 — pack-budget [med]
The consumer-facing payoff: `tldr pack <seed> --budget N`. Composes the three currently-isolated
subsystems (semantic/BM25 RRF seeds → confidence-and-centrality-weighted graph expansion → greedy
tokenizer-measured fill). Aider's repomap proves the packing mechanic; tldr's version is
confidence-aware (T2 edges only after higher tiers fit). Depends only on m3 — can be pulled earlier
if delivery pressure demands, at the cost of packing over unimproved edges.

## Dependency graph (milestone level)

```
m0 → m1 ─────────────┐
m0 → m2 → m3 → m4 → m6 → m7
              m3 → m5 ─┘  m6 → m8 → (m9)
              m3 ────────────────→ m10
```
Critical path: **m0 → m2 → m3** (the publishable core), then m4/m5 feed m6.
m1 parallels m2 (disjoint files). m10 floats after m3.

## Worker & gate discipline (carried from the campaign — proven 12/12 additive pass, 1/1 subtractive fail)

- Orchestrator owns: build + codesign BOTH binaries + install + parity gate + truth harness + allowlist review + commit.
- Workers (Orca: kimi/droid/codex): implement + failing-first TDD test + report JSON to `reports/`. Never commit/gate/codesign. `TLDR_NO_DAEMON=1` for tests.
- One-fix-one-gate, sequential in the tree (cargo contention). Iron rule on every calls-touching commit.
- Canary smoke-gate (~1 min) before full gate (~8 min) for language-scoped fixes.
- Mechanism pre-verification before writing any calls-touching brief.
- Additive-only on shared mechanisms — subtractive changes to shared resolution paths are rejected at brief review.
- Max 2 fix rounds per assertion, then escalate; rollback via revert if declined.
- OPS: re-codesign both binaries after every build (macOS SIGKILL); never `git add -A`; verify `git status` shows only intended files; git porcelain reverts blocked by dcg hook (workers use checkout-index).

## Premortem (top risks, mitigations encoded)

1. **Baseline regen hides a regression** (m0/m4): mitigated by VAL-024 (gates cross-check) and reviewed per-language re-baseline diffs (VAL-042).
2. **LanguagePolicy scope creep** (m1): "narrow refactor, 0-delta gate" written into assertions; adapter trait deferred to m6/m8.
3. **Truth corpus is unrepresentative** (m2): three independent truth sources; per-rung breakdown exposes which rung is being flattered.
4. **Decline-not-guess breaks downstream consumers** (m3): approval gate VAL-030 before schema change; `--approximate` escape hatch.
5. **Scope-substrate baseline churn conflated with regressions** (m4): staged per-language re-baseline, each reviewed.
6. **Type engine becomes 17 forks** (m6): VAL-062 requires enablement via LanguagePolicy adapters only.
7. **Stale T0 edges trusted** (m7): VAL-071 demotion rule is an assertion, not a nice-to-have.
8. **W2-29-class leak in any shared-mechanism change**: canary gate + mechanism pre-verification are global invariants in the contract.
9. **Program stalls in refactor phases while the market moves** (strategic — Graphify went 0→79k stars in 3 months): m0–m3 are deliberately small/med; m3+m2 produce the public, publishable claim early. Ship the honesty layer; don't wait for the type engine to talk about the program.

## Definition of done (program level)

All 43 assertions passed or explicitly user-deferred; BENCHMARK-BASELINE.md shows the measured arc
(~80% unlabeled → per-language ≥90-95% precision, graded, declining, with T0 harvest and cross-file
taint available); the honesty layer + benchmark published; every edge in every output carries
{confidence, provenance, staleness}.
