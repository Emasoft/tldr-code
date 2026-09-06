---
trdd-id: MWLIUB72
title: Decide whether the encoding module is wired into the read paths or retired
column: todo
created: 2026-09-06T04:14:07+0200
updated: 2026-09-06T04:14:07+0200
current-owner: unassigned
task-type: refactor
min-approval-requirement: user
labels: [scan-2026-09-05, encoding, api_change]
parent-trdd: 7X459MTO
---

# Decide whether the encoding module is wired into the read paths or retired

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-06

- This card exists because the decision had NO card. TRDD-7X459MTO's STATE block routed it to
  TRDD-V11BVG55, and a session handoff repeated that. Both were wrong — V11BVG55's 17 items were
  read in full and none mentions `encoding`. Corrected on both of those cards.
- NOTHING IS DECIDED YET. This card is the decision, not its outcome. The facts below are
  measured; the verdict is open.

## Why

`tldr-core` exposes `pub mod encoding` (`crates/tldr-core/src/lib.rs:45`) offering
`read_source_file`, `read_source_file_or_skip`, `FileReadResult` and `EncodingIssues` — a file
reader that classifies a source file as ok / lossy / binary / skipped and accumulates per-file
encoding problems for reporting.

**It has zero non-test callers anywhere in the workspace.** Verified across all four crates,
excluding the module's own file and its tests. Every command reads files directly instead.

TRDD-7X459MTO fixed a real defect inside this module (UTF-16 files were handed to callers as an
empty string, counted as analysed with zero symbols while the warning said "skipping"). That fix
is correct and shipped, but it corrects code nothing in this repo calls, and 7X459MTO's second
acceptance line — a `tldr structure` JSON run listing the file in an issues section — is
unsatisfiable until this card is decided, because no command consumes `EncodingIssues`.

## The measured facts that constrain the decision

**1. The status quo is worse than "the module is unused" suggests.** A survey of every non-test
`read_to_string` call site (176 real sites; report under `reports/encoding-survey/`) buckets them
by what happens when a file is not valid UTF-8:

| bucket | sites | effect on a non-UTF-8 file |
|---|---|---|
| PROPAGATED | 75 | the whole command aborts |
| SILENT | 73 | the file vanishes from the analysis, no message |
| PANIC | 25 | the process panics |
| WARNED | 3 | the user is actually told |

So today a single UTF-16 file in a tree can kill a command or silently shrink the result set,
and only 3 sites out of 176 report it. That is precisely the defect class this module was built
to fix. (Spot-checked first-hand: a one-line grep for `.unwrap()`/`.expect(` on a
`read_to_string(` line finds 24; the survey's 25 includes one multi-line form.)

**2. RETIRE is not the cheap cleanup it looks like, but not for the obvious reason.** The
tempting argument — "it is published public API, so it has callers you cannot grep" — is WRONG
here. Those callers belong to crates.io `tldr-core` ≤ `0.4.0`, a different artifact. This tree is
`0.4.1-fork.1` and is not in the index. Measured: GitHub code search for `"Emasoft/tldr-code"` in
a `Cargo.toml` returns **0**, the fork has **0** forks, upstream `"parcadei/tldr-code"` returns
**5**. This fork has no library consumers; its consumers run the `tldr` binary.
What actually argues against deletion is **divergence cost**: this fork's value depends on
tracking upstream, and every deletion is a merge conflict forever after. That standard is
recorded on TRDD-V11BVG55 and must be applied consistently, including against changes that have
already shipped.

**3. WIRE IN is large.** 176 call sites plus every command's output schema would have to carry an
issues section. It is also arguably upstream's architectural call, not a fork's to make
unilaterally.

## What

Pick ONE and record the reasoning:

- **WIRE IN** — route command file reads through `read_source_file_or_skip` and surface
  `EncodingIssues` in each command's output. Fixes the 73 SILENT and 25 PANIC sites. Large; needs
  its own staged plan and almost certainly an upstream conversation.
- **RETIRE** — delete `pub mod encoding`. Cheap in-tree, but pays divergence cost forever and
  discards the only code that addresses the table above.
- **LEAVE AS-IS, documented** — keep the module as an available public utility and add a doc note
  saying no in-repo command routes through it. Costs nothing, changes nothing, and leaves the 73
  SILENT / 25 PANIC sites unaddressed — so this option is only honest if the read-path robustness
  problem is split out into its own card rather than dropped.

## Acceptance

- [ ] One of the three options is chosen, with the reasoning recorded in this card's STATE block.
- [ ] If LEAVE AS-IS is chosen, a separate card exists for the 73 SILENT + 25 PANIC read sites —
      that defect is real whatever happens to this module.
- [ ] TRDD-7X459MTO's acceptance line 2 is either satisfied or explicitly marked unsatisfiable
      with this card's decision as the reason.

## Approval log

- 2026-09-06T04:14:07+0200 — Filed by the session Claude under the user's 2026-09-05 directive to
  decide from verified facts. Filing only; no option chosen and no code changed.
