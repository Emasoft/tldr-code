---
trdd-id: BKALIK1B
title: A source file that is not valid UTF-8 panics the process or vanishes from the analysis
column: todo
created: 2026-09-06T04:16:38+0200
updated: 2026-09-06T04:24:00+0200
current-owner: unassigned
task-type: bugfix
min-approval-requirement: user
labels: [scan-2026-09-05, robustness, encoding]
---

# A source file that is not valid UTF-8 panics the process or vanishes from the analysis

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-06

- Filed UNCONDITIONALLY and deliberately kept independent of TRDD-MWLIUB72 (the `encoding`
  wire-in-or-retire decision). This defect is real whichever way that card goes — 25 panics and
  73 silent drops are a robustness bug whether the encoding module is wired, retired, or left
  alone. It was first written as a conditional obligation inside MWLIUB72's acceptance, which
  was the wrong home: a future session choosing WIRE IN would never have filed it, and the
  finding would have died inside a checkbox.
- Not yet triaged per-site. The bucket counts are measured; which specific sites matter most is
  not.

## Why

`std::fs::read_to_string` returns `Err(InvalidData)` on a file that is not valid UTF-8 — a
UTF-16 source, a file with a stray byte, a mis-detected binary. A survey of **every non-test
call site** in the workspace (176 real sites after discarding 8 false positives; full report
under `reports/encoding-survey/`, filename dated 2026-09-06) buckets them by what the caller
does with that error:

| bucket | sites | what the user experiences |
|---|---|---|
| PROPAGATED | 75 | the whole command aborts |
| SILENT | 73 | the file is dropped from the analysis, no message |
| PANIC | 25 | the process panics |
| WARNED | 3 | the user is told which file was skipped and why |

**3 sites out of 176 report the problem.** The other 173 either kill the run or quietly shrink
the result set.

The SILENT bucket is the more dangerous of the two large ones, because it is invisible: a
`tldr` run over a tree containing one UTF-16 file returns a smaller, wrong answer and reports
success. Nothing tells the user their result is incomplete. The PANIC bucket is louder but
worse-behaved — a `.unwrap()` on a file read turns a bad input file into a crash.

Spot-check corroborating the survey (run first-hand, not taken on the worker's word): a
single-line grep for `.unwrap()`/`.expect(` on a `read_to_string(` line finds 24; the survey's
25 includes one multi-line form.

## What

Not a mechanical sweep — the three buckets need different treatment, and 176 sites is too many
to change blind:

**Severity and sequencing are NOT the same ranking here, and an earlier version of this card
conflated them** — it called SILENT "the more dangerous" and then told the reader to start with
PANIC, presenting an effort tie-break as a severity judgment. Stated separately:

**By severity, SILENT (73) is the worst bucket.** It produces a smaller, wrong answer *reported
as success*. Nothing tells the user their result is incomplete, so it corrupts whatever decision
the output feeds. PANIC (25) is second: it is loud, reproducible and self-reporting — the user
sees the crash, knows the run is invalid, and can file it. A crash is a bad outcome; a confidently
wrong answer is a worse one.

**By sequencing, do PANIC first — on tractability, not severity.** The two buckets need different
kinds of work:

- **PANIC (25)** — mechanical and self-contained. `.unwrap()`/`.expect(` on a file read becomes a
  handled error; no design decision, no schema change, no dependency on any other card. It can
  land immediately and independently.
- **SILENT (73)** — needs a per-site judgment (skip-with-a-warning vs propagate) and a place to
  put the warning. Most sit inside directory walks, where aborting the whole command over one bad
  file would be wrong, so skip-with-a-warning is the likely answer — which is precisely the
  problem `EncodingIssues` was designed to solve. So this bucket is entangled with TRDD-MWLIUB72:
  it is currently decided LEAVE-AS-IS, but if that is ever reopened to WIRE IN, most of this work
  is subsumed and would be done twice.
- **PROPAGATED (75)** — probably already correct for single-file reads, where failing loudly is
  right. Confirm rather than change.

If forced to fix only one bucket, fix SILENT — it is the one that lies. PANIC goes first only
because it is free to do now and blocks nothing.

## Acceptance

- [ ] No non-test `read_to_string` call site panics on a file that is not valid UTF-8.
- [ ] A `tldr` run over a directory containing one unreadable file either reports that file or
      fails — it never returns a silently-incomplete result reported as success.
- [ ] A regression test covers at least one directory-walk command against a tree containing a
      UTF-16 file.

## Approval log

- 2026-09-06T04:16:38+0200 — Filed by the session Claude under the user's 2026-09-05 directive to
  decide from verified facts. Filing only; no code changed.
