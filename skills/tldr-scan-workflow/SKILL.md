---
name: tldr-scan-workflow
description: >
  Scan and fix a WHOLE codebase with a fan-out of cheap workers that navigate
  with the `tldr` CLI instead of reading files, in ~3000-line batches, one
  worker per batch, with a build+test gate every ~24 batches. Use it when the
  ask is "audit/scan/harden the entire repo", "find and fix every X across all
  crates", or any sweep too large for one context — not for a single file or a
  known bug. Ships the batch planner, the Workflow script, the calibrated
  prompts, and the measured cost table (~198K tokens per landed fix) so a run
  can be priced before it is launched.
---

# Full-codebase scan and fix

A codebase-wide sweep is a fan-out problem with two failure modes that only
show up at scale: workers that read whole files instead of navigating (token
burn), and fixes that look right in a diff and break the build 200 batches
later (silent regression). This skill is the shape that survived both — every
rule below is a scar from a measured run; see `references/calibration.md`.

**Do not use it** for one file, one known bug, or a change you can name up
front. The fan-out only pays when you cannot enumerate the work.

## Pipeline

```
plan batches → PILOT one batch → wave of ~24 batches → gate → next wave → … → test wave → consolidate → commit
                (measure, then fan out)   ↑ scan → verify per batch      ↓ cargo check + touched-file tests
```

- **scan** — one worker per batch: read the batch's files once, navigate with
  `tldr`, refute its own findings, fix the safe ones in place, write
  `<batch>.md` + `<batch>.jsonl`.
- **verify** — one worker per *edited* batch: judge every hunk. Its first check
  is mechanical — a fix whose report line pastes no `tldr references`/`impact`
  excerpt pointing outside the edited file is reverted, unread.
- **gate** — the coordinator, between waves: `cargo check -p <crate>` plus the
  targeted tests of the files this wave touched.
- **consolidate** — one agent over every report → `SUMMARY.md` +
  `findings.jsonl`.

## 1. Plan the batches

```bash
git -C <repo> ls-files 'crates/*.rs' \
  | uv run --quiet python3 scripts/make_batches.py \
      --repo-root <repo> --out-dir <repo>/reports/workflows/<stamp>-scan/batches
```

~3000 lines per batch, oversized files alone, `bNNN` for sources and `tNNN`
for tests. Fixtures/docs/vendored are `--exclude` globs; gitignored files are
excluded by construction because the list comes from `git ls-files`. Output is
one `<id>.txt` per batch (`<lines>\t<absolute path>`) plus `index.json`
(`[{id, kind, lines, nfiles}, …]`) — the script's `args.batches`.

Rank first when the repo is large: feed a `tldr hotspots <dir>`-ordered list
with `--no-sort` and scan the long tail last or under a budget. 67 of 220
batches in the measured run produced no fix at all.

## 2. Pilot one batch, then fan out

Launch with no `args.pilot` and the script runs **exactly one batch**, whatever
`waveSize` says. That one run is three things at once: the cost measurement
that prices the fan-out, the parse check of the script (`node --check` passes
scripts the Workflow loader rejects — only a real launch proves it loads), and
the first exercise of the wave gate.

Record `{batch, tokens, seconds, fixes}` and pass it back as `args.pilot`.
Nothing fans out until that record exists.

## 3. Run a wave, then gate

The script runs **one wave per invocation** and stops — a build is a shell
command and workflow scripts have no shell. Each invocation returns:

```js
{ wave, nextWaveStart, totals, dropped, reportDir, edited: [repo-relative paths], summary }
```

The coordinator loop, per wave:

1. `Workflow({scriptPath: 'references/workflow.js', args})` with `waveStart`.
2. `cargo check -p <crate>` and the tests covering `edited`. **Red gate stops
   the run** — fix at the root (the `// why:` comment at each fix site says what
   was intended), never revert blind, then re-gate.
3. Relaunch with `waveStart = nextWaveStart`; stop when it is `null`.
4. On the final wave pass `consolidate: true`.

Waves of ~24 batches cost ~9 serialized incremental checks on a 306K-line
crate (per-check time **unmeasured** — capture it in your pilot wave and record
it). It buys catching a systemic break after one wave instead of after 220
batches, which is exactly what run 2 failed to do.

**Test batches are their own wave, last.** Coverage-widening edits — removing
an `#[ignore]`, tightening an assertion — are claims about a binary the worker
cannot build. Run the `tNNN` batches after the source waves and gate them on
the full suite, not on `cargo check`.

## 4. Prompts live in prose, not in the script

`references/workflow.js` contains no prompt text. The coordinator reads
`references/prompts.md`, takes the text between each opening fence
(` ```text prompt:scan `, `prompt:verify`, `prompt:consolidate`) and its closing
fence, and passes them as `args.prompts = {scan, verify, consolidate}`. Anchor
the match on a line that *starts* with the fence — the tags are also named in
that file's prose and in this paragraph, so a bare substring search finds the
wrong line. The script substitutes `{{PLACEHOLDER}}` tokens. Revise a prompt as
reviewable prose with its rationale beside it; the script never changes.

## 5. args

| key | meaning |
|---|---|
| `root` | repo root, absolute. Never hardcode it — the script has no other source of truth for paths |
| `runStamp` | `YYYYmmdd_HHMMSS+ZZZZ` from the shell; scripts cannot call `Date` |
| `reportDir` | defaults to `<root>/reports/workflows/<runStamp>-scan` |
| `batchDir` | where `make_batches.py` wrote the plan |
| `batches` | `index.json` contents (or `nSrc`/`nTest` counts as a fallback) |
| `waveStart`, `waveSize` | this wave's window; `waveSize` defaults to 24 |
| `pilot` | the pilot record; absent ⇒ one-batch pilot run |
| `done` | resume list, `[{id, e: [rel paths], c: [fixed, skipped, false_positive]}]` |
| `prompts` | `{scan, verify, consolidate}` from `prompts.md` |
| `knownPatterns` | the previous run's FALSE_POSITIVE patterns (see the learning loop) |
| `project` | one sentence describing the codebase, for the worker prompts |
| `consolidate` | `true` on the final wave only |
| `agentType`, `effort` | worker type and reasoning effort; default `lean-worker` / `medium`, the pair the calibration numbers were measured on |

`root` is required and the script throws without it; so is one of
`reportDir`/`runStamp`, because a missing stamp would otherwise write the whole
run under `undefined-scan` and the resume path could never find it.

## 6. Report line format

```
<SEVERITY> | <file>:<line> | <STATUS> | <summary> | <why real, how fixed or why skipped> | <tldr evidence>
```

`SEVERITY ∈ critical|high|medium|low`, `STATUS ∈ FIXED|SKIPPED|FALSE_POSITIVE`,
`<line>` a single integer — never a range. Range-style lines put the
grep-derived totals 3–26 below the script's in the measured run, an unresolved
gap in a file that has to be machine-readable.

The last field is the enforcement. A `FIXED` line without a pasted
`tldr references`/`tldr impact` excerpt naming a location outside the edited
file is reverted by the verifier. Prose bans do not hold: run 2 logged 209
`sed -n` dumps, 69 `grep -r` and 13 `find /` against an explicit ban, because a
worker holds an unrestricted Bash tool and a prompt cannot refuse a command.
(The real fix is a `PreToolUse` allow-list on the worker's Bash — `tldr`,
`rustfmt --emit stdout`, `ls`, `wc`. Until that exists, the evidence gate is
what actually bites.)

Every report has a `.jsonl` twin with the same findings (`batch, file, line,
severity, status, summary, detail, evidence`), and the consolidator concatenates
them into `findings.jsonl`. That plus `index.json` is what turns a failing test
into file → batch → fixer with no human in the loop.

## 7. Resume, and liveness

Reports are the state. A stalled or killed run resumes from what is on disk:

```bash
for f in <reportDir>/[bt]*.md; do … ; done   # id + files edited + counts → args.done
```

The script cannot read the filesystem, so the coordinator builds `done` and
passes it; those batches skip the scan and go straight to verify.

**Liveness rule.** A run is dead when *started − results* holds constant **and**
no report file's mtime advances for 10 minutes. Stop it and resume from the
reports. Do not wait longer — run 1 froze for hours and produced nothing after
the freeze.

**No foreground agents while a run is live.** Run 1 stalled the minute review
forks began competing for the agent pool. Nothing else spawns agents until the
run returns.

## 8. The learning loop

40% of findings (305 of 768) were refuted by the very worker that raised them.
The consolidator's last section groups FALSE_POSITIVE lines into *named
patterns* written to be pasted, not read; feed that text back as
`args.knownPatterns` on the next run over the same codebase. That is the only
lever this workflow has against the refutation tax.

## 9. Cost

Roughly **198K tokens per landed fix**, measured — 36.85M tokens for 186 fixes
across 142 batches, 77 minutes, 296 agents. A ~2800-line pilot batch cost 158K
tokens and 171 s. Full numbers, and an explicit list of what is still
unmeasured (per-wave gate time, the hardened prompt's yield, the revert rate
under the evidence gate, fastedit as the write path), are in
`references/calibration.md`. Read it before promising anyone a runtime.
