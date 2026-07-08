# Worker Brief — VAL-020c (m2-benchmark-harness): real-repo truth sets via LSP callHierarchy

Repo: `/Users/cosimo/Desktop/PatchWork/tldr-code` (cd there for EVERY command). `implement` archetype.
Report `worker_done`. Everything under `continuum/benchmark/` — no crates/, no cargo, no parity gate.

## Goal (contract VAL-020c)
Ground-truth call edges for **>=2 real repos per priority language** (python, typescript, go, rust, java),
harvested via **LSP callHierarchy**, plus **runtime traces for Python**. Every edge carries truth.v1
provenance (source: lsp-callHierarchy | runtime-trace, tool+version, harvested_at).

## Design: SAMPLED truth sets (not whole-repo)
Whole-repo truth is intractable and unnecessary. Per repo: sample **40-60 call sites** deterministically
(seeded by file path sort — NO random()), harvest the LSP's outgoing-calls answer for each enclosing
function, and store as a truth set scoped to exactly those call sites. The harness scores recall/precision
ONLY over sampled sites (report already supports per-case scoping — each repo sample = one "case" with
`meta.json {sampling: {method, seed, n}}`). Spot-check >=5 edges per repo BY READING THE SOURCE before
accepting the harvest — the LSP is near-truth, not gospel (note any LSP errors you find).

## Repos (already cloned in ~/.tldr-audit/corpora — do NOT re-clone; reference by manifest)
python: python-flask, python-requests · typescript: typescript-axios, typescript-nest ·
go: go-gin, go-httprouter · rust: rust-ripgrep, rust-clap · java: java-petclinic, java-retrofit
Manifest per repo under `continuum/benchmark/repos/<repo>/manifest.json` {corpus_path, commit_sha (read
via git -C <corpus> rev-parse HEAD), language} + `truth.json` (sampled edges) + `meta.json`.

## Step 0 — TOOL INVENTORY (do this FIRST, report before heavy work)
Check availability: pyright/pylsp/jedi-language-server (python), typescript-language-server (ts),
gopls (go), rust-analyzer (rust), jdtls (java). `which <tool>` + `tldr doctor` output. For MISSING servers:
escalate ONE decision_gate listing what's missing + the install commands (brew/npm/rustup) and WAIT — do
not install anything without my ack. Harvest proceeds language-by-language for whatever IS available.

## Harvest mechanics
A small python3 driver `continuum/benchmark/harvest_lsp.py` (stdlib-only + the LSP servers via subprocess
JSON-RPC over stdio): initialize → for each sampled call site's enclosing function: callHierarchy/prepare +
callHierarchy/outgoingCalls → map returned items to truth.v1 edges (file paths relative to corpus root).
Cache raw LSP responses under repos/<repo>/raw/ for auditability. Timeout per request; a repo whose server
can't index in reasonable time (say 10 min) → document + skip + note in report.
**Python runtime traces:** for ONE python repo (flask), also run a tiny trace harness (sys.settrace or
coverage's trace) over its test suite subset (bounded: <=2 min run) collecting caller→callee pairs within
repo files only; intersect with the sampled sites where possible; provenance source=runtime-trace. If the
test suite won't run cleanly in the environment, document + decision_gate rather than hack.

## HARD CONSTRAINTS
- continuum/benchmark/** only. Corpora in ~/.tldr-audit/corpora are READ-ONLY (never modify them).
- No network beyond LSP servers already installed (installs only via decision_gate ack).
- Deterministic sampling (documented seed method). Leave UNCOMMITTED.
- Do NOT wire these into run_truth.py scoring yet if repo-case support needs harness changes — if harness
  changes ARE needed, keep them minimal and report them explicitly.

## WHEN DONE report worker_done with
(1) tool inventory result, (2) per-repo: sampled-site count, harvested-edge count, spot-check outcome,
skips+reasons, (3) runtime-trace outcome for flask, (4) harness changes if any, (5) file tree summary,
(6) confirmation corpora untouched + nothing outside continuum/benchmark/.
