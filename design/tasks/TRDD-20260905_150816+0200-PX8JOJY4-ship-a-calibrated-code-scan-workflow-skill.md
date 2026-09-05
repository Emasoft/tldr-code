---
trdd-id: PX8JOJY4
title: Ship a calibrated code-scan workflow skill with tldr-code
column: todo
created: 2026-09-05T15:08:16+0200
updated: 2026-09-05T17:32:00+0200
current-owner: claude-session-2026-09-05
task-type: feature
min-approval-requirement: none
blocked-by: []
labels: [skill, workflow, token-economy]
---

# Ship a calibrated code-scan workflow skill with tldr-code

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-05

- NEXT ACTION: wait for workflow run `wf_b18824d3-a84` (full-codebase scan, 220 batches) to finish; harvest its calibration data (see Acceptance); then build `skills/tldr-scan-workflow/` from the persisted script.
- Script to start from: `scripts_dev/workflows/codebase-scan-and-fix.js` in this checkout (gitignored dev copy of the run's persisted script; `batches-index.json` beside it is the batch plan), already patched to make `tldr references/impact/definition/structure` the mandatory navigation and to forbid recursive grep and `sed -n` dumps. Its canonical home becomes `skills/<skill>/references/workflow.js` once the skill exists. Until then this card is actionable only from a checkout that has that dev copy (the prompts live nowhere tracked yet); shipping the skill is what removes that limitation.
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
- [ ] No absolute home paths and no personal names anywhere in the shipped skill, template, or prompts: paths are `~/`-relative or repo-relative, the repo root is an `args` value, and the report dir is derived from it (user directive 2026-09-05).

## Lessons from runs 1 and 2 (2026-09-05) — design constraints for the skill

Measured (run 2: 143 scan + 153 verify + 1 consolidation agents, 36.9M tokens, 77 min):

| measure | value |
|---|---|
| tokens per landed fix | ~128K (36.9M / 287 fixes) |
| scan vs verify transcript size | 201 KB vs 61 KB avg; verify ~30% of total cost |
| verify verdicts | 350 KEEP, 0 REVERT; at least 2 kept hunks broke ~200 tests |
| tldr navigation calls vs `sed -n` dumps vs `grep -r` | 191 vs 209 vs 69 (bans in prose were ignored) |
| batches with zero fixes | 46 of 142, many in uncompiled `commands/archived/` |
| findings the worker itself refuted | 305 of 768 (40%) |
| pilot (grep prompt) | 158K tokens / 2825 lines, 3 fixes, compiled clean |

What worked: ~3000-line batches, one worker each, read-once-fix-in-place (185 files, zero
compile errors); greppable report lines + one consolidation agent (768 findings); resume from
report files after a stall; pilot-first; a compile+test gate at the end.

What failed, and the rule the skill adopts:

1. VERIFY WAS A RUBBER STAMP. Same model, same evidence, judging a sibling: 0 reverts, 2
   regressions passed (scanner root skipped; AST cache rejected .js). Both were
   "reachability verified by grep" errors. Rule: the verifier must hold NEW evidence — the
   orchestrator runs `cargo check -p <crate>` per wave, and a hunk whose reachability claim is
   not backed by pasted `tldr references` output defaults to REVERT.
2. NO FEEDBACK UNTIL THE END. All scans queued before any verify (shared FIFO pool), so a
   systemic regression surfaced after 77 min. Rule: waves of ~24 batches: scan → verify →
   build + targeted tests → next wave.
3. PROSE BANS ARE WEAK. Rule: ship a `scan-nav` helper wrapping `tldr` and grade the report's
   evidence, not the transcript; tell workers the exact grammar path
   (`~/.cargo/registry/src/*/tree-sitter-<lang>-*/src/node-types.json`); every command stays
   inside the repo; a command over 30 s is a bug.
4. WASTED BATCHES. Rule: exclude uncompiled/cfg-gated modules first (module reachable from
   lib.rs; `tldr dead`), rank the rest with `tldr hotspots`.
5. POOL FRAGILITY. Run 1 froze at 14:42 (six `find /` timeouts and/or foreground review forks
   competing for the agent pool; never proven). Rule: no foreground agents during a run;
   liveness = started−results constant AND no report mtime advance for 10 min ⇒ stop, resume
   from reports (done-list derived by the orchestrator, script cannot read the FS).
6. FALSE-POSITIVE TAX (40%). Rule: distil each run's FALSE_POSITIVE lines into a
   "known-intentional patterns" context fed to the next run — the skill's learning loop.
7. TEST-FILE CLAIMS. Workers removed 32 `#[ignore]` on the strength of a binary they could
   not build. Rule: coverage-widening test edits form their own wave gated by the suite.
8. MACHINE MAPPING. Rule: emit a JSONL twin of every report plus a batch index so failing
   test → file → batch → fixer dispatch needs no human.
9. TOOLING PROXIES. `node --check` passed a script the Workflow loader rejected (duplicate
   `const`); scripts cannot call Date (pass timestamps via args). Rule: the parse check is a
   one-batch dry run of the Workflow tool itself.

## Notes and lessons learned

- Prompt wording decides tool use: "tldr … or grep" produced zero tldr calls in the pilot; mandatory shapes plus an explicit ban on `grep -r`/`sed -n` is the working form.
- With a shared 12-slot pool, `pipeline()` stage-2 calls queue behind every stage-1 call issued at start, so verification effectively runs after all scans; harmless, but the consolidation must not be read as "verified as it went".
