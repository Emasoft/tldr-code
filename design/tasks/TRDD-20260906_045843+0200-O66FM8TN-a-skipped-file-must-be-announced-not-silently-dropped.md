---
trdd-id: O66FM8TN
title: A file the analysis skips must be announced, not silently dropped from the result
column: todo
created: 2026-09-06T04:58:43+0200
updated: 2026-09-06T04:58:43+0200
current-owner: unassigned
task-type: bugfix
min-approval-requirement: user
labels: [robustness, encoding, silent-failure]
parent-trdd: BKALIK1B
---

# A file the analysis skips must be announced, not silently dropped from the result

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-06

- Split out of TRDD-BKALIK1B, which fixed a REPRODUCED instance (a wide-encoded file analysed as
  zero symbols) and should close on that. This card carries the larger, different problem it
  exposed: **a skip that nobody is told about.**
- Nothing here is speculative. The skipping already happens and is already correct; what is
  missing is the message. Measured inventory below.

## Why

`tldr dead` over a tree containing one unreadable file returns a dead-code report computed over
a **silently smaller file set**, and exits 0.

That is not a lesser bug than a wrong answer — it *is* a wrong answer, in the shape that does the
most damage. Dead-code detection is whole-program by nature: a function is dead only if *nothing*
references it. Dropping a file removes its references, so a function referenced **only** from the
dropped file is now reported as dead.

**MEASURED, not argued** (2026-09-06). Two directories, identical file contents, encoding the only
variable. `lib.py` defines `used_only_from_utf16()` and `genuinely_dead()`; `caller.py` imports and
calls the first.

| `caller.py` encoding | `tldr dead` → `possibly_dead` |
|---|---|
| UTF-16 (skipped by the guard) | `used_only_from_utf16`, `genuinely_dead` ← **FALSE POSITIVE** |
| UTF-8 (control) | `caller`, `genuinely_dead` |

With the caller readable, `used_only_from_utf16` correctly drops off the list. With the caller
skipped, a live function is reported as possibly dead and is **indistinguishable from the
genuinely dead one** — and `warnings` is `None`, so nothing hints that a file was omitted.

Honest scoping of that result: the name lands in `possibly_dead`, not `dead_functions`, so the
tool is already hedging. The defect is that the hedge carries no reason, and the user has no way
to learn that a file was dropped. `calls` has the same property — a missing file means missing
edges, so the call graph is confidently incomplete.

Verified 2026-09-06 (TRDD-BKALIK1B's probes): `dead`, `calls` and `smells` DO reach the encoding
guard and correctly exclude an unreadable file — and none of them surfaces a warning naming it.
`structure`, `secure` and `vuln` already do, through `files_skipped` + `warnings`, so the pattern
to copy exists in-tree.

## What

Two pieces, in order:

1. **Make the commands that already skip say so.** `dead`, `calls`, `smells` reach the guard and
   drop the file; they need the `files_skipped` + `warnings` treatment `structure` already has.
   Smallest useful change, and it fixes the most dangerous instance first.
2. **The SILENT read-site inventory: 56 production sites.** Full list in
   `reports/encoding-survey/*-CORRECTED-production-only.md`. Each discards a read error and skips
   the file with no user-visible message. Decide per site whether the right behaviour is
   skip-with-a-warning or propagate — most sit inside directory walks, where aborting the whole
   command over one bad file would be wrong, so a warning is the likely answer.

Counts to trust, and the ones NOT to: the corrected survey reads **56 SILENT · 0 PANIC ·
94 PROPAGATED · 4 WARNED** (154 production sites). **The PANIC bucket is EMPTY** — all 24
`.unwrap()`s on a read are test code. An earlier survey said 25 production panics; it classified
by path alone and counted `#[cfg(test)]` code as production. Do not go fixing those.

**BUT 56 IS NOT THE READ SURFACE — it is the `read_to_string`-shaped part of it.** The survey
searched for `read_to_string` only. A further **33 non-test read sites use a different primitive
and were never bucketed**: 30 `File::open` and 2 `.read(&mut …)`. `is_binary_file`
(`metrics/file_utils.rs:304`) is one of them, and its error handling is `Err(_) => false` — a read
failure is silently treated as "not binary", which is this card's defect in a helper the survey
could not see. Bucket those 33 before planning off 56.

## Acceptance

- [ ] `tldr dead`, `tldr calls` and `tldr smells` over a directory containing an unreadable file
      name that file in a user-visible warning, as `structure` does.
- [ ] A regression test covers at least one whole-program command (`dead`) against
      `design/reproducers/TRDD-BKALIK1B/`, asserting the warning is present — not merely that the
      file is absent from the results, which is what the buggy behaviour also produces.
- [ ] Every one of the 56 SILENT sites has a recorded decision: warn, propagate, or
      deliberately-silent-with-a-reason.
- [ ] The 33 `File::open` / `.read(&mut …)` sites the survey never saw are bucketed the same way.
- [ ] The skip path is centralised, so a NEW command cannot silently drop a file without
      inheriting the warning.
      — This replaces an earlier line, "no command returns a result computed over a reduced file
      set without saying so", which was **unfalsifiable**: it quantified over all commands, all
      inputs and all future code, so nothing could ever discharge it and it would have been
      ticked on vibes or never. Same defect as the unfalsifiable standard caught on
      TRDD-MWLIUB72. Centralisation is the mechanism that actually generalises the guarantee, and
      it is checkable.

## Notes

The one methodological trap this work will hit, learned the hard way on the parent card: **a
file's absence from a command's output is not evidence about WHY it is absent.** It is equally
consistent with "skipped by the guard", "skipped by `is_binary_file`", and "read fine but parsed
to nothing". Distinguishing them needs a probe whose candidate explanations predict OPPOSITE
observations — e.g. a NUL at offset 1928, which is past the encoding guard's 1024-byte prefix but
inside `is_binary_file`'s 8 KB sample. Three successive probes were needed on the parent card
before one actually discriminated.

## Approval log

- 2026-09-06T04:58:43+0200 — Filed by the session Claude, split from TRDD-BKALIK1B on the reasoning
  that the parent had established its defect and fixed it, while "every skip is announced" is a
  larger piece of work with its own 56-site inventory. Keeping both on one card would mean the
  parent never closes and its acceptance keeps being rewritten. Filing only; no code changed.
