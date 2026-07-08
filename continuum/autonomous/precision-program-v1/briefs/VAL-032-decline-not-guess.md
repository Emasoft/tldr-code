# Worker Brief — VAL-032 (m3-honesty-layer): decline-not-guess for dead / impact / definition

Repo: `/Users/cosimo/Desktop/PatchWork/tldr-code` (cd there for EVERY command). `implement` archetype, TDD.
Report `worker_done` to term_240a1ffa-8d57-44d0-a3f7-d48e784e4c48. HEAD bee7150 (calls.v2 rung/tier landed).

## The asymmetry (get this right — it is the whole assertion)
"Stop acting on T2 guesses" means OPPOSITE conservatisms per command:
- **impact / whatbreaks** (who calls X): a T2 edge INTO X is a guessed caller — a phantom. DEFAULT: exclude
  T2 edges from reported callers; count them separately as `approximate_callers` (listed under a clearly
  separated key with their rung), included in the main list only with `--approximate`. Measured target:
  phantom-caller count on truth cases -> 0.
- **definition**: never return a T2-guessed location as THE definition. If only T2 candidates exist:
  decline — report unresolved with the candidates listed as approximate (again `--approximate` opts in).
- **dead**: INVERSE conservatism. A function is declared dead only if NO edge of ANY tier reaches it AND
  no unresolved call plausibly targets it (name/arity match against the unresolved list from calls.v2).
  T2 edges and unresolved-name matches are LIVENESS evidence (keep-alive), never dismissed. Functions kept
  alive ONLY by weak evidence get reported in a separate `possibly_dead` section with the evidence kind
  (t2-edge-only / unresolved-name-match) — the honest middle ground. Measured target: dead FPs on reachable
  truth-case code -> 0. `--approximate` promotes possibly_dead into dead.

## Mechanism pre-read (verify, then wire)
- impact: `crates/tldr-core/src/analysis/impact.rs` (reverse callgraph; W2-14 touched its enrichment) +
  `whatbreaks` if it shares the path. The rung/tier now rides on `CrossFileCallEdge` (VAL-031) — consume it.
- dead: find the dead-code detection (grep `fn.*dead` in crates/tldr-core/src/) — it consumes the callgraph
  edge set + entry-point heuristics (builder.rs:146 is_entry_point).
- definition: `crates/tldr-cli/src/commands/remaining/definition.rs` — its resolution paths are separate
  from the calls cascade; where it consults callgraph edges use tiers; where it has its own heuristic
  fallbacks classify them conservatively (its own guess-tier == T2 semantics).

## Output contract (additive, versioned like calls.v2)
Each command's JSON gains: `schema` bump, per-item confidence where a claim rests on edges, the separated
approximate/possibly_dead sections, and an `unresolved`/`declined` list with reasons. Human/text output:
mark approximate items clearly (e.g. "(approximate)" suffix / separate section). `--approximate` flag added
to all three commands (default OFF).

## TDD (failing first; use benchmark-style fixtures)
(a) impact: fixture where X has one T1 caller + one capitalized-receiver-guess T2 caller → default output
lists ONLY the T1 caller, T2 under approximate_callers; --approximate merges. (b) definition: only-T2
candidate → declined + candidates listed; T1 available → unchanged. (c) dead: function reached ONLY by a
T2 edge → NOT in dead, IS in possibly_dead(t2-edge-only); function name-matched by an unresolved call →
NOT dead, possibly_dead(unresolved-name-match); truly unreachable function → still dead. RED→GREEN each.
Full suites: core + cli.

## MEASUREMENT (run it yourself, report numbers — VAL-032 acceptance is measured)
After implementation: `python3 continuum/benchmark/run_truth.py --binary target/release/tldr --out /tmp/val032_report.json`
(build release first; TLDR_NO_DAEMON=1). Report before (BENCHMARK-BASELINE.md numbers) vs after for
impact precision + dead FP counts per language, and the RECALL COST of declining (impact/dead recall delta) —
the contract requires the loss quantified, not hidden. If the harness's dead/impact derivations need
updating to consume the new sections (approximate excluded from default scoring, possibly_dead not counted
as dead), make those harness updates + document in DESIGN.md Scoring.

## HARD CONSTRAINTS
- calls/context output UNCHANGED (that is VAL-033's surface — only dead/impact/whatbreaks/definition here).
- The callgraph BUILD is untouched — you consume tiers, never change resolution (parity gate must stay
  byte-identical; orchestrator verifies).
- NO regex, NO clippy #[allow]. Leave UNCOMMITTED. List every changed file in your report.

## WHEN DONE report worker_done with
(1) files changed, (2) per-command semantics as implemented (one line each), (3) test names RED→GREEN,
(4) suite counts, (5) MEASURED before/after: impact P (esp. python 0.190 baseline), dead FP count, recall
deltas, (6) any harness/DESIGN.md scoring updates.
