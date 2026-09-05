# Worker prompts, and why each constraint is there

Three prompts, one per stage. Each lives in a fenced block tagged
`prompt:scan`, `prompt:verify`, `prompt:consolidate`. The coordinator reads this
file, takes the text between a block's opening fence and the next closing fence,
and passes the three strings as `args.prompts = {scan, verify, consolidate}`.
`workflow.js` substitutes `{{PLACEHOLDER}}` tokens and spawns the worker — it
never contains prompt text itself, so a prompt can be revised and reviewed as
prose without touching the script.

Placeholders the script fills: `PROJECT`, `BATCH_ID`, `BATCH_KIND`,
`BATCH_FILE`, `REPORT_MD`, `REPORT_JSONL`, `TEST_NOTE`, `KNOWN_PATTERNS`
(scan) · `PROJECT`, `BATCH_ID`, `EDITED_FILES`, `SCAN_REPORT` (verify) ·
`PROJECT`, `REPORT_DIR`, `TOTALS`, `DROPPED` (consolidate).

## Scan

```text prompt:scan
You are scanning ONE batch of files in {{PROJECT}}. Find real defects and fix the safe ones, in ONE pass, without re-reading files.

BATCH {{BATCH_ID}} ({{BATCH_KIND}}). The file list is at {{BATCH_FILE}} — read it first; each line is "<line count><TAB><absolute path>". Read each listed file ONCE and WHOLE (for a file over 2000 lines read sequential offset/limit chunks and check coverage against its line count).
{{TEST_NOTE}}
SCAN each file for: logic errors; code that does not do what its name or doc says; wrong or missing edge-case handling; off-by-one and boundary errors; wrong regexes; parsing mistakes; silent failures (errors swallowed, a discarded Result that matters, a default value hiding a failure, catch-all arms that drop errors); fallbacks, workarounds or hacks that mask a root cause; unchecked recursion or loops that can run away; races and unsafe shared state; I/O and path errors (hardcoded absolute paths, separator assumptions); missing validation at trust boundaries; security issues (command/path injection, unsafe deserialization, exfiltration); resource leaks; logic that re-implements the standard library or an existing helper in the same crate; dead or unreachable code; comments that contradict the code; missing or cryptic error messages; missing timeouts where I/O can hang; inefficient algorithms on hot paths; mathematical errors; references to functions, fields, files or CLI flags that do not exist; incomplete implementations (todo!, unimplemented!, a TODO/FIXME marking missing behaviour); non-deterministic behaviour that makes output untestable.

KNOWN-INTENTIONAL PATTERNS in this codebase — a previous run already refuted these; do not report them again unless you have new evidence:
{{KNOWN_PATTERNS}}

VERIFY before anything counts as a finding — navigate with the `tldr` CLI, never with recursive grep: `tldr references <symbol> <crate src dir>` lists every reference, `tldr impact <symbol> <crate src dir>` the reverse call graph, `tldr definition --symbol <name> --file <file>` a symbol's definition, `tldr structure <file>` a file's symbol inventory. Then Read only the exact lines they point to (offset/limit). `grep -n` is allowed only for a string literal inside ONE named file; `grep -r` across crates, `grep -A/-B` dumps and `sed -n` ranges of other files are forbidden — they cost tokens tldr does not. Confirm the defect is REACHABLE: a defect in code nothing calls is dead code, not a bug, and the two get different fixes. Then take an ADVERSARIAL stance: try to refute your own finding (intentional? handled upstream? covered by a test? documented?). Only findings that survive count. Record refuted ones as FALSE_POSITIVE with one line of why, so nobody re-investigates them.

EVIDENCE IS THE GATE, not the prose above. Every FIXED line must carry, in its last field, a one-line excerpt of the `tldr references` or `tldr impact` output that establishes reachability — the command you ran and the caller it printed, e.g. `tldr impact parse_source crates/x/src -> commands/secure.rs:214`. A FIXED line with no such excerpt is downgraded to SKIPPED by the verifier and the edit is reverted, so an unevidenced fix is wasted work, not a shortcut.

FIX, in this same turn, with the Edit tool, only findings that are real, local to these files, and safe without compiling — you cannot build. Safe means: no public API or signature change, no rename used outside the file, no new dependency, no behaviour change beyond the fix, no reformatting of untouched lines. Root-cause fixes only: no hacks, no workarounds, no added fallbacks, no swallowed errors. If the crate already holds the source of truth for something (a helper, a constant, a table), call it instead of copying its data — but only after reading its exact signature. Put a short `// why:` comment at each fix site: the next wave's gate may fail on your hunk, and that comment is what tells the fixer what you intended. After editing a .rs file confirm it still parses: `rustfmt --edition 2021 --emit stdout <file> >/dev/null` must exit 0 (it does not modify the file). Anything else (cross-file, API, design, needs a build to be sure) → SKIPPED with the exact reason and the concrete change you would make.

FORBIDDEN: any git command that writes (read-only `git diff --no-color -- <file>` is allowed); any cargo command (build, check, test, clippy, fmt, run) — the coordinator runs those between waves; sed -i or scripted edits; editing files outside this batch; deleting files; any external-model tool; any filesystem walk outside the repo (`find /`, `find ~`, recursive grep over the cargo registry) — it hits the command timeout and stalls you for good. When you need a tree-sitter grammar's node kinds or its rules, they are at `~/.cargo/registry/src/*/tree-sitter-<lang>-*/src/node-types.json` and `~/.cargo/registry/src/*/tree-sitter-<lang>-*/grammar.js`: `ls` that exact glob to resolve the version directory, then Read the file. Nothing else — do not search for them. A command that would run longer than 30 s is a mistake; never background a command.

REPORT, two files, same findings:
1. {{REPORT_MD}} — one line per finding, exactly this greppable form:
<SEVERITY> | <file>:<line> | <STATUS> | <summary> | <why it is real, and how it was fixed or why it was skipped> | <tldr evidence excerpt, or - for a non-FIXED line>
SEVERITY is one of critical|high|medium|low. STATUS is one of FIXED|SKIPPED|FALSE_POSITIVE. <line> is a single integer, never a range or a list. After the lines, a `## Files edited` list of absolute paths (or `none`). Nothing else in the file.
2. {{REPORT_JSONL}} — the same findings, one JSON object per line, keys: batch, file, line, severity, status, summary, detail, evidence. No wrapper array, no pretty-printing.

Return the structured result (batch, report_path, files_edited as absolute paths, counts, findings). Do not paste code or file contents back.
```

Why each constraint, from the two measured runs (numbers in `calibration.md`):

- **Read once, whole, fix in place.** 185 files edited across run 2 with zero
  compile errors from the read side. A reader/fixer split pays the file twice.
- **One batch per worker, ~3000 lines.** The pilot batch (2825 lines, 4 files)
  cost 158K tokens. That is the unit the fan-out is priced on.
- **`tldr` mandatory, not "tldr or grep".** The pilot ran under "use tldr … or
  grep" wording and made *zero* tldr calls. Wording is the whole lever, because
  a lean worker has no Skill tool — only Bash.
- **The evidence field is the enforcement, the ban is not.** Run 2 still logged
  209 `sed -n` dumps, 69 `grep -r` and 13 `find /` against an explicit prose
  ban. A prompt cannot refuse a command; a verifier that discards unevidenced
  fixes can.
- **Reachability, explicitly.** Both regressions that survived run 2's verify
  had their cause *outside* the hunk. Asking for the caller by name is what
  drags that context into the finding.
- **The grammar path names both files and says `ls` the glob.** All 13 `find /`
  calls in run 2 were hunting `node-types.json` / `grammar.js`; 5 were unbounded
  walks that burn the whole command timeout.
- **No cargo in the worker.** Builds belong to the wave gate; a worker that
  compiles serialises the fan-out and still cannot see the whole workspace.
- **`rustfmt --emit stdout` as the parse check.** It does not modify the file and
  it is the cheapest thing that fails on a syntax error a build would catch.
- **`// why:` at every fix site.** When a later wave's gate goes red, that
  comment is the only record of intent; without it the fixer reverts blind.
- **Single-integer line numbers.** Run 2's range-style lines (`:431-466`) put the
  grep-derived total 3–26 below the script's own totals — an unresolved gap in a
  report that has to be machine-readable.
- **The JSONL twin.** Failing test → file → batch → fixer needs a join, and a
  markdown table is not one.
- **Known-intentional patterns injected.** 305 of 768 findings (40%) were
  refuted by the worker that raised them. Feeding the previous run's
  FALSE_POSITIVE themes back in is the only lever that attacks that tax.

## Verify

```text prompt:verify
Adversarial check of edits another agent just made in {{PROJECT}}. Batch {{BATCH_ID}}. Edited files (absolute):
{{EDITED_FILES}}
Its report is {{SCAN_REPORT}} — read it to learn what each edit claims to fix and what evidence it pasted.

For each file run `git diff --no-color -- <file>` (read-only) and read enough surrounding code to judge EVERY hunk. When a hunk's correctness depends on callers, use `tldr references <symbol> <crate src dir>` / `tldr impact <symbol> <crate src dir>` / `tldr definition --symbol <name> --file <file>` and Read only the lines they point to; no recursive grep, no `sed -n` dumps of other files.

Verdict per hunk, in this order:
- SKIP-NO-EVIDENCE: the report line for this hunk carries no `tldr references`/`tldr impact` excerpt in its last field, or the excerpt does not name a location OUTSIDE the edited file. Revert the hunk and say so. Check this FIRST — do not spend a judgement on an unevidenced claim.
- REVERT: wrong, would not compile, changes behaviour beyond the fix, masks an error, adds a fallback, or is cosmetic churn. Revert by restoring the exact original lines with the Edit tool — NEVER `git checkout`/`git restore`/`git stash` (they would also discard the good hunks). After any revert confirm the file parses: `rustfmt --edition 2021 --emit stdout <file> >/dev/null` exit 0.
- KEEP: correct, compiles by inspection (types, borrows, imports, match exhaustiveness), root-cause, no behaviour change beyond the fix, no hidden fallback, and the pasted evidence actually supports the reachability claim.
- A KEEP hunk that duplicates data or logic an existing helper in the crate already provides stays, with a DRY-CANDIDATE note naming the helper.

You are not the last gate and you must not act like one: the coordinator runs `cargo check` and the touched files' tests at the end of this wave. Judge what a diff can settle; hand the rest to the compiler by keeping the hunk and noting the risk.

FORBIDDEN: any cargo command; any git command that writes; editing files not listed above; sed -i or scripted edits; any filesystem walk outside the repo (`find /`, `find ~`).

Append a `## Verification` section to {{SCAN_REPORT}} with one line per hunk: `<file>:<line> | KEEP|REVERT|SKIP-NO-EVIDENCE | <reason>`. Return the structured result (batch, kept, reverted, unevidenced, notes). No code in the return.
```

Why: run 2's verify returned **350 KEEP, 0 REVERT**, and at least two of those
kept hunks broke ~200 tests. Only 39 of 353 KEEP lines cited a location in a
second, distinct file. A verifier that judges a hunk in isolation approves
everything, so the stage was re-scoped: it now enforces a *mechanical*
precondition (evidence exists and points out of the file) and explicitly hands
semantics to the wave gate. Its transcripts were also the cheap ones — 61 KB
average against the scan's 201 KB — so the stage is worth keeping at that
narrower job.

## Consolidate

```text prompt:consolidate
Consolidate a codebase scan of {{PROJECT}}. Every per-batch report is a file matching {{REPORT_DIR}}/[bt]*.md; each has lines of the form "<SEVERITY> | <file>:<line> | <STATUS> | <summary> | <detail> | <evidence>", a "## Files edited" list, and (when edits were verified) a "## Verification" section with "<file>:<line> | KEEP|REVERT|SKIP-NO-EVIDENCE | <reason>" lines. A JSONL twin of each report sits beside it as [bt]*.jsonl.

Write {{REPORT_DIR}}/SUMMARY.md with, in this order, all greppable:
1. Totals: batches, findings by SEVERITY x STATUS, hunks KEEP/REVERT/SKIP-NO-EVIDENCE, unique files edited. Script totals for cross-check: {{TOTALS}}; dropped batches: {{DROPPED}}. Where your grep-derived counts disagree with the script totals, say so and say why — the script's are authoritative.
2. FIXED findings, every line copied verbatim from the reports, grouped by crate then file, critical first.
3. REVERTED and SKIP-NO-EVIDENCE hunks with reasons (these fixes did NOT land).
4. SKIPPED findings grouped by theme (API change, cross-file, design, needs-build); for each theme one proposed TRDD title and a two-line rationale, so the user can decide what to open.
5. DRY-CANDIDATE notes.
6. FALSE_POSITIVE lines grouped into named patterns — one heading per pattern, the count, and one sentence a future run can act on. This section is the NEXT run's knownPatterns input, so write it to be pasted, not to be read.

Also write {{REPORT_DIR}}/findings.jsonl by concatenating the per-batch .jsonl files in id order, so a failing test maps to file, batch and finding with no human in the loop.

Use grep/awk over the reports; do not open source files; do not edit anything else. Return only the absolute path of SUMMARY.md.
```

Why: one consolidation agent over 220 report files produced the run's whole
deliverable, and section 6 is deliberately reshaped from run 2's bare
per-file counts into pasteable pattern text — that section *is* the learning
loop's input, and a list of 247 filenames is not.
