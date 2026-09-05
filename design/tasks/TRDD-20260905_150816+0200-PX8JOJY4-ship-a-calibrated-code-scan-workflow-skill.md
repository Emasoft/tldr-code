---
trdd-id: PX8JOJY4
title: Ship a calibrated code-scan workflow skill with tldr-code
column: human_review
created: 2026-09-05T15:08:16+0200
updated: 2026-09-05T21:27:36+0200
current-owner: claude-session-2026-09-05
task-type: feature
min-approval-requirement: none
blocked-by: []
labels: [skill, workflow, token-economy]
---

# Ship a calibrated code-scan workflow skill with tldr-code

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-05

- NEXT ACTION: the landing is COMMITTED, not pushed (2026-09-05 21:00): `62bfe3a` scan, 184 files (three scan-caused root fixes inside: scanner depth-0 cycle guard, AST-cache language dispatch, `is_inside_class` for Java interface/enum/record); `8706dff` 7 proposals, none approved; `24a6bad` the skill under `skills/tldr-scan-workflow/` + Makefile target; `f7444bd` val013 registry isolation; `866c21e` six stale/env-dependent upstream tests. Residual failures: 87 pre-existing at the parent 7f50527 (same name, per-binary count and assertion text or full failure block), 1 unreproducible hang tracked as proposal TRDD-0M2P188T. Open acceptance lines: the end-to-end template run from a fresh session and the fastedit evaluation. Moved to `human_review` at 21:27, not left in `todo`: `todo` asserts approved, designed and NOT started, which eight landed commits contradict, and it hides delivered work from the board. `human_review` states what is true — the work is delivered and a human verdict is pending on the two open lines. `testing` and `ai_review` were exercised but never recorded as columns, so the card went `todo` → `human_review` in one edit. `testing`: this card's own acceptance (colony row 10) re-runs green — the five skill files present, `node --check` on `workflow.js`, `make_batches.py --help`, an empty leak grep over the skill and Makefile, the Makefile target. `ai_review`: adversarial reviews read the skill, this card's acceptance tick and its column move, and their findings were acted on. Verdict sought: run the shipped template end to end from a fresh session and evaluate fastedit on one batch, or drop those two lines and close the card. With `min-approval-requirement: none` there is no named reviewer, so only the user moves it out of this column.
- Canonical script: `skills/tldr-scan-workflow/references/workflow.js` (committed in `24a6bad`), with the prompts in `references/prompts.md` and the measured figures in `references/calibration.md`. The gitignored dev copy `scripts_dev/workflows/codebase-scan-and-fix.js` (+ `batches-index.json`) is the run's original and is no longer needed to act on this card.
- Measured so far: pilot batch b067 (4 files, 2825 lines, Sonnet lean-worker, medium effort) = 158K tokens, 171 s, 27 tool calls, 3 real fixes, 3 refuted findings, compiled clean. The pilot made ZERO `tldr` calls under the softer "tldr or grep" wording; the wording is the lever because lean-workers have no Skill tool, only Bash.
- Unmeasured: tokens and finding quality of a batch under the hardened tldr-only prompt; verify-stage revert rate; fastedit as the write path; an end-to-end run of the shipped template itself.

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
- [ ] Workers use `tldr` for cross-file navigation, measured by yield, not by call ratio: every FIXED report line carries a pasted `tldr references` or `tldr impact` excerpt for its reachability claim (lines without one are auto-SKIPPED by the verifier, lesson 1), and the regression rate after the per-wave gate is below the run-2 baseline of 2 broken hunks per 287 fixes. (The earlier "tldr calls ≥ 3× grep + sed" bar was dropped: run 2 scored 191 vs 278 and still landed real fixes, so the ratio measures obedience, not value.)
- [ ] fastedit evaluated as the write path for symbol-body replacements; adopted only if it measurably reduces tokens versus Edit on the same batch, with the number recorded.
- [ ] `make install-skill` installs it alongside `tldr-code` (or the Makefile target is extended), and `tldr doctor` detects it if that check is generalised.
- [x] No absolute home paths and no personal names anywhere in the shipped skill, template, or prompts: paths are `~/`-relative or repo-relative, the repo root is an `args` value, and the report dir is derived from it (user directive 2026-09-05).

## Lessons from runs 1 and 2 (2026-09-05) — design constraints for the skill

Measured (run 2: 143 scan + 153 verify + 1 consolidation agents, 36.9M tokens, 77 min):

| measure | value |
|---|---|
| tokens per landed fix (run 2 only: 36.85M / 186 fixes in its 142 batches) | ~198K |
| scan vs verify transcript size (bytes; billing split unmeasured, the tool reports one total) | 201 KB vs 61 KB avg |
| run 1 (grep prompt, stalled at 14:42) | 78 scans, 101 fixed / 57 skipped / 119 refuted, 0 verifies, tokens unmeasured (journal has no usage) |
| detection audited | high/critical band sampled and real; the 73 `low | FIXED` cleanups are unaudited and mostly untested |
| verify verdicts | 350 KEEP, 0 REVERT; at least 2 kept hunks broke ~200 tests |
| tldr navigation calls vs `sed -n` dumps vs `grep -r` vs `find /` | 191 vs 209 vs 69 vs 13 — every prose ban was violated. All 13 read: 5 `-maxdepth 0` probes (a worker testing whether `find` is allowed, then walking `~` anyway), 3 `-maxdepth 6` walks, 5 unbounded hunts for `node-types.json`/`grammar.js` despite the hint. The hint must name both files and say `ls` the exact glob |
| run-2 fixed count | 186 FIXED report lines; 189 by worker self-report; the gap is range-style lines (`:431-466`), unresolved; hunks in `git diff` were not counted |
| batches with zero fixes (both runs) | 67 of 220; only 4 entirely in uncompiled `commands/archived/` |
| findings the worker itself refuted | 305 of 768 (40%) |
| pilot (grep prompt) | 158K tokens / 2825 lines, 3 fixes, compiled clean |

What worked: ~3000-line batches, one worker each, read-once-fix-in-place (185 files, zero
compile errors); greppable report lines + one consolidation agent (768 findings); resume from
report files after a stall; pilot-first; a compile+test gate at the end.

What failed, and the rule the skill adopts:

1. VERIFY HAD THE WRONG EVIDENCE. Only 28 of the 76 KEEP verdict lines in the verify reports (`t*.md`) name at least two distinct `.rs` path strings (the earlier hand count of "39 of 353" had no recorded basis and could not be reproduced; this one is re-derived by the command below, run against `reports/workflows/20260905_141407+0200-codebase-scan/`); the
   rest judged the hunk in isolation, and even the ones that looked cross-file passed 2
   regressions out of 350 hunks, because both bugs lived outside the hunk: the scanner's root
   pre-seeding 60 lines above it, and `secure.rs`'s admitted extension list in another file. A
   diff reader cannot see that reliably; a compiler and a test can. Rule (one mechanism, replaces separate verify/wave/parse rules):
   WAVES of ~24 batches, each followed by `cargo check -p <crate>` and the targeted tests of the
   files touched, run by the orchestrator; a hunk whose reachability claim carries no pasted
   `tldr references` output is auto-SKIPPED by the verifier. Price: ~9 serialized incremental
   checks on a 306K-line crate; the per-check time was NOT captured this session (measure it
   in the pilot wave and record it here before the skill ships). Whatever it is, it buys
   catching a systemic break after one wave instead of after all 220 batches, and it stays.
   Counting command for the cross-file figure (prints the number of KEEP verdict lines that
   name at least two distinct `.rs` files; 28 on the run-2 reports):

```bash count-cross-file-keep
RP=~/Code/tldr-code/reports/workflows/20260905_141407+0200-codebase-scan
/usr/bin/grep -h 'KEEP' "$RP"/t*.md | while IFS= read -r l; do
  n=$(printf '%s\n' "$l" | /usr/bin/grep -oE '[A-Za-z0-9_./-]+\.rs' | sort -u | wc -l | tr -d ' ')
  [ "$n" -ge 2 ] && echo x
done | wc -l | tr -d ' '
```

2. (merged into 1.)
3. PROSE BANS ARE WEAK, AND A HELPER CANNOT REFUSE COMMANDS while workers hold an unrestricted
   Bash tool. Rule: enforcement is the report-evidence gate in rule 1 (a finding without tldr
   evidence is skipped), not the prompt; the prompt still names the exact grammar path
   (`~/.cargo/registry/src/*/tree-sitter-<lang>-*/src/node-types.json`) and keeps every command
   inside the repo. Future form: a worker whose Bash is allow-listed by a PreToolUse hook to
   `tldr`, `rustfmt --emit stdout`, `ls`, `wc` (no registered agent type is Bash-less with
   Edit, and `tldr` is a CLI, so a hook is the only real enforcement).
   fastedit as the write path: not exercised (302 Edit calls in run 2, run 1 uncounted, 0 fastedit in either); no data.
4. WASTED BATCHES. 67 of 220 batches produced no fix; uncompiled `archived/` code explains
   only 4 of them. Rule: rank batches with `tldr hotspots` (churn × complexity) and scan the
   long tail last or under a budget; exclude uncompiled/cfg-gated modules as a minor extra.
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
   one-batch dry run of the Workflow tool itself, which doubles as the pilot of rule 1's wave.

## Notes and lessons learned

- Prompt wording decides tool use: "tldr … or grep" produced zero tldr calls in the pilot; mandatory shapes plus an explicit ban on `grep -r`/`sed -n` is the working form.
- With a shared 12-slot pool, `pipeline()` stage-2 calls queue behind every stage-1 call issued at start, so verification effectively runs after all scans; harmless, but the consolidation must not be read as "verified as it went".
