---
trdd-id: PX8JOJY4
title: Ship a calibrated code-scan workflow skill with tldr-code
column: todo
created: 2026-09-05T15:08:16+0200
updated: 2026-09-05T15:12:00+0200
current-owner: claude-session-2026-09-05
task-type: feature
min-approval-requirement: none
blocked-by: []
labels: [skill, workflow, token-economy]
---

# Ship a calibrated code-scan workflow skill with tldr-code

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-05

- NEXT ACTION: wait for workflow run `wf_b18824d3-a84` (full-codebase scan, 220 batches) to finish; harvest its calibration data (see Acceptance); then build `skills/tldr-scan-workflow/` from the persisted script.
- Script to start from: `scripts_dev/workflows/codebase-scan-and-fix.js` in this checkout (gitignored dev copy of the run's persisted script; `batches-index.json` beside it is the batch plan), already patched to make `tldr references/impact/definition/structure` the mandatory navigation and to forbid recursive grep and `sed -n` dumps. Its canonical home becomes `skills/<skill>/references/workflow.js` once the skill exists. A contributor without that dev copy rebuilds it from the prompts in this card's What section.
- Measured so far: pilot batch b067 (4 files, 2825 lines, Sonnet lean-worker, medium effort) = 158K tokens, 171 s, 27 tool calls, 3 real fixes, 3 refuted findings, compiled clean. The pilot made ZERO `tldr` calls under the softer "tldr or grep" wording; the wording is the lever because lean-workers have no Skill tool, only Bash.
- Unmeasured: tokens and finding quality of a batch under the hardened tldr-only prompt; verify-stage revert rate; fastedit as the write path.

## Why

The user asked (2026-09-05) for a skill, shipped in this repo, that packages the most token-efficient code-scan workflow: calibrated agent contexts and prompts, the tldr CLI for navigation, fastedit for symbol-scoped writes, minimal token use, and high defect yield. A workflow that is only in one session's history is lost; a skill makes it reusable from any checkout.

## What

A skill directory `skills/tldr-scan-workflow/` (name to confirm) containing:

1. `SKILL.md` — when to use, the pipeline shape (batch → scan → verify-edits → consolidate → build+test → commit → TRDD proposals), the batching recipe (~3000 lines per worker, oversized files alone, fixtures excluded), the pilot-first rule (measure one unit, then fan out), and the report line format.
2. `references/workflow.js` — the Workflow-tool script template, parameterised by `args` (repo root, report dir, batch dir, counts, pilot record, done list for resume).
3. `references/prompts.md` — the scan, verify and consolidate prompts with the measured rationale for every constraint (why tldr is mandatory, why no cargo inside workers, why one region per call, why `rustfmt --emit stdout` as the parse check).
4. `scripts/make_batches.py` — deterministic batch planner (the one used in this session), emitting per-batch list files and an index.

## Acceptance

- [ ] Calibration table in the skill, from real runs: tokens per batch (grep-prompt vs tldr-prompt), findings per 100K tokens, FALSE_POSITIVE share, verify REVERT share, compile-break count after the run.
- [ ] The template runs end-to-end on this repo from a fresh session using only the skill's instructions.
- [ ] Workers use `tldr` for cross-file navigation (verified by counting `tldr` invocations in worker transcripts, not by the prompt text).
- [ ] fastedit evaluated as the write path for symbol-body replacements; adopted only if it measurably reduces tokens versus Edit on the same batch, with the number recorded.
- [ ] `make install-skill` installs it alongside `tldr-code` (or the Makefile target is extended), and `tldr doctor` detects it if that check is generalised.

## Notes and lessons learned

- Prompt wording decides tool use: "tldr … or grep" produced zero tldr calls in the pilot; mandatory shapes plus an explicit ban on `grep -r`/`sed -n` is the working form.
- With a shared 12-slot pool, `pipeline()` stage-2 calls queue behind every stage-1 call issued at start, so verification effectively runs after all scans; harmless, but the consolidation must not be read as "verified as it went".
