---
trdd-id: O66FM8TN
title: A file the analysis skips must be announced, not silently dropped from the result
column: dev
created: 2026-09-06T04:58:43+0200
updated: 2026-09-06T06:40:00+0200
current-owner: session-claude
task-type: bugfix
min-approval-requirement: user
labels: [robustness, encoding, silent-failure]
parent-trdd: BKALIK1B
---

# A file the analysis skips must be announced, not silently dropped from the result

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-06 06:40

- **Piece 1 LANDED (2026-09-06 ~06:30): `dead`, `calls`, `smells` now announce every file they
  drop.** One shared helper, `tldr_core::fs::skipped_file_warning(path, reason)`, produces the
  `Skipped <path>: <reason>` line for all of them AND for `structure` (which was rewritten to use
  it), so a new command has one thing to call. Per command:
  - `dead` (CLI, both the refcount default and `--call-graph`): the collectors used
    `if let Ok(..) = parse_file(..)` / `extract_file(..)` and dropped the error. They now return
    the skip list; `DeadCodeReport` gained `files_skipped: usize` + `warnings: Vec<String>`
    (`#[serde(default)]`, emitted in the hand-rolled Serialize), text mode prints
    `Files skipped: N (results exclude them)` under the headline numbers.
  - `smells` (core): `filter_map(|f| analyze_file(f).ok())` swallowed every failure. Now
    partitioned; failures go to the pre-existing `SmellsReport.warnings`, which the text
    formatter already rendered. The `--deep` aggregate path carries them through too.
  - `calls` (core builder + CLI): `build_indices_parallel` read with plain `fs::read_to_string`,
    which SUCCEEDS on BOM-less UTF-16 (valid UTF-8, ASCII interleaved with NUL) — so a wide file
    was pushed as an EMPTY `FileIR`, present in the graph with zero functions. It now reads via
    `fs::read_to_string_tolerant` (the same guard as `structure`), and a file whose
    `FileParseResult.error` is set is recorded in the new `CallGraphIR.warnings` and left OUT of
    the graph. The CLI's `CallGraphOutput` gained `files_skipped` + `warnings`.
  - **Correction to the parent card's table:** `calls` did NOT "reach the guard" before this.
    It had no guard on its read path at all; the wide files were analysed-as-empty, which is the
    parent card's original bug shape, on a second path. The probe that "settled" the row could
    not distinguish analysed-as-empty from skipped, because both leave the file out of `nodes`.
  - The two OTHER consumers of the dead collector (`todo`, `bugbot born-dead`) have no warnings
    channel; they print the skip list to stderr rather than drop it. Wiring it into their
    reports is still open on this card.
  - The daemon `dead` handler and the MCP `dead` tool were NOT touched: the daemon derives
    `all_functions` from graph edges (its own pre-existing oddity) and the MCP tool drops
    `structure.warnings` on the floor. Both are still silent. Open.
- **Tests:** `crates/tldr-core/tests/encoding_skip_tests.rs` +2 (smells, calls over the
  BKALIK1B fixtures: warning names each of the 5 wide files, none of the 3 readable ones, and
  for `calls` the dropped files are absent from `ir.files`). New
  `crates/tldr-cli/tests/skipped_file_warning_tests.rs` (5): dead/calls/smells JSON name exactly
  the 5, dead text prints them, and the card's measured scenario — a UTF-16 `caller.py` — now
  yields a warning naming the caller. Each CLI test pins `TLDR_DAEMON_REGISTRY_DIR` to an empty
  tempdir so a live daemon cannot serve a cached pre-fix payload.
- **Still open on this card:** the 56-site SILENT inventory decisions, the `File::open` /
  `read_to_end` bucketing, and the daemon/MCP/todo/bugbot channels above.
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

**Whether this counts as a `dead` bug turns on what `possibly_dead` means, so it was settled from
the CODE, not from a doc comment.** The objection to answer: maybe `possibly_dead` is the
tool's hedge for "uncalled, but my analysis may have been incomplete" — in which case listing the
function is self-consistent and calling it a false positive is a category error.
It is not that. `analysis/dead.rs:133` splits the two buckets on **`is_public` alone**:
public-and-uncalled → `possibly_dead`, private-and-uncalled → `dead_functions`. The in-code
comment says "may be API surface". So "possibly" qualifies WHY an uncalled public function might
be legitimate, and carries no claim about analysis confidence. The module contract
(`dead.rs:3`) is likewise unqualified: *"Find functions that are never called"*.

**Being fair to the other reading, because it changes where the fix belongs.** Any static
analyser can only compute "uncalled *within what it read*" — that much is inherent, and blaming
`dead` for it would be unreasonable. So the actionable defect is NOT that `dead` computed the
wrong answer over its input; it is that **the input set was silently reduced and the report says
nothing about it.** Both readings agree on that, which is why it lives on this card and not on a
`dead`-specific one. What the measurement establishes is the CONSEQUENCE: the reduction is not
harmless bookkeeping, it changes a user-visible verdict about a real function.

Honest scoping, and the semantics were CHECKED rather than assumed — the hedge does not excuse it.
`types.rs:2454` documents `possibly_dead` as *"Public/exported but uncalled (may be API surface)"*.
The hedge is about INTENT — a public function may be uncalled on purpose. It is not a hedge about
whether the tool might have MISSED a call. `used_only_from_utf16` is genuinely called, so listing
it there is wrong against the field's own documented meaning, not merely unhelpful. It lands in
the softer of the two tiers (`dead_functions` is the harder claim), and the user still has no way
to learn a file was dropped. `calls` has the same property — a missing file means missing
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
searched for `read_to_string` only, so reads through other primitives were never bucketed at all.
`File::open` (read-only in Rust; `File::create`/`OpenOptions` are the write paths) plus
`read_to_end` / `.read(&mut …)` account for the rest.

**Deliberately stated as a SCOPE claim and not a defect count.** Nobody has bucketed those sites
into silent/warned/propagated, and many will be reading config, caches or reports rather than
source. Quoting a number here as "N more silent sites" would repeat precisely the error this
card's parent made three times (25 production panics; 176 call sites; the single chokepoint).
The order of work is: bucket them, THEN count.

> **Methodology trap, because it corrupted this very figure.** An **unquoted** `--include=*.rs`
> does NOT filter — the shell eats it, and the grep silently searches every file type. My first
> count of these sites was 33 and included hits from a `.md` design document; quoted, it is 31.
> The same unquoted form inflates a `read_to_string` count from 204 to 207. **Always quote
> `--include='*.rs'`,** and treat any inventory built without it as an upper bound.
One example of why the bucketing needs judgment rather than a sweep: `is_binary_file`
(`metrics/file_utils.rs:304`) handles a read failure as `Err(_) => false` — an unreadable file is
treated as "not binary". That LOOKS like this card's defect, and it may instead be deliberate:
returning `false` lets the downstream read produce the real, specific error rather than
mislabelling the file as binary here. **Not established either way; assess in context.**

## Acceptance

- [x] `tldr dead`, `tldr calls` and `tldr smells` over a directory containing an unreadable file
      name that file in a user-visible warning, as `structure` does. — landed 2026-09-06, see
      STATE; verified by `skipped_file_warning_tests` against the built binary.
- [x] A regression test covers at least one whole-program command (`dead`) against
      `design/reproducers/TRDD-BKALIK1B/`, asserting the warning is present — not merely that the
      file is absent from the results, which is what the buggy behaviour also produces.
      — `dead_json_names_every_skipped_file` + the UTF-16-caller scenario test.
- [ ] Every one of the 56 SILENT sites has a recorded decision: warn, propagate, or
      deliberately-silent-with-a-reason.
- [ ] The `File::open` / `read_to_end` / `.read(&mut …)` sites the survey never saw are bucketed
      the same way — count them AFTER bucketing, not before.
- [ ] The skip path is centralised, so a NEW command cannot silently drop a file without
      inheriting the warning.
      — PARTIAL: the MESSAGE is centralised (`fs::skipped_file_warning`, used by structure,
      dead, smells, calls). The DECISION to warn still lives at each `Err` arm; a new command
      that writes `if let Ok(..)` is not stopped by anything. Left open on purpose — a walk
      helper that owns the error arm would be the real mechanism.
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
