---
trdd-id: BKALIK1B
title: A UTF-16 source file is reported as analysed with zero symbols instead of being skipped
column: dev
created: 2026-09-06T04:16:38+0200
updated: 2026-09-06T04:38:00+0200
current-owner: claude-session-2026-09-06
task-type: bugfix
min-approval-requirement: user
labels: [scan-2026-09-05, robustness, encoding]
---

# A UTF-16 source file is reported as analysed with zero symbols instead of being skipped

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-06

- **The bug is REPRODUCED end-to-end.** Fixture committed at
  `design/reproducers/TRDD-BKALIK1B/`. `control.py` and `bad.py` hold byte-identical source text
  and differ only in encoding: `tldr structure` finds **2 definitions in the UTF-8 one and 0 in
  the UTF-16 one**, lists `bad.py` as analysed, prints no warning, and **exits 0**.
- **Root cause is ONE LINE**, in the pool's `parse_file_with_lang`
  (`crates/tldr-core/src/ast/parser.rs`, after the `std::fs::read`):
  `String::from_utf8_lossy(&bytes)` does not FAIL on UTF-16 — it substitutes U+FFFD and returns
  a string of replacement characters that parses cleanly to zero symbols. Nothing reports an
  error because, by the type system's lights, nothing went wrong.
- **This card was filed on numbers that were wrong, and the rewrite is why.** Its first version
  said "25 PANIC sites, start there". Verified before touching any of them: there are 24, and
  **all 24 are test code — 0 production**. Fixing them would have been wrong work at scale.
- **THE METHODOLOGY LESSON, which is the transferable part.** The survey excluded paths
  containing `/tests/` and nothing else. Rust has two further ways to be test-only, and both were
  miscounted as production: an inline `#[cfg(test)] mod tests { … }` block (20 of the 24), and a
  whole file pulled in by `#[cfg(test)] mod <name>;` in the PARENT module — the other 4, in
  `analysis/clones_integration_tests.rs`, gated at `analysis/mod.rs:119` with nothing inside the
  file saying so. **A filename or directory saying "tests" is not what makes code test-only; the
  `cfg` attribute is, and it can live in a different file from the code it gates.**
  My own first correction was ALSO wrong: I classified by "line number > the file's first
  `#[cfg(test)]`", which is the same crude shape and fails *silently* toward TEST — hiding real
  defects instead of inventing them. All 24 are now accounted for individually: 18 inside
  brace-matched `cfg(test)` block ranges, 4 externally gated (verified at `mod.rs:119`), 2 in
  `first_run.rs` read directly (asserts + temp dirs, under the `#[cfg(test)]` at line 474).
- **The SILENT (73) and PROPAGATED (75) counts remain UNRELIABLE** — same method, same blind
  spot. A corrected production-only re-survey is running; its report lands in
  `reports/encoding-survey/` as `*-CORRECTED-*`. Do not plan work off the old numbers.
- **"176 call sites" was the wrong frame for the parse path.** `parse_file_with_lang` is, in its
  own words, "the single chokepoint every parse-based command goes through (structure, calls,
  smells, dead, secure, …)" — the oversize policy is already enforced there for exactly that
  reason. So this defect is one fix for all parse-based commands, not one per call site. This
  also corrects TRDD-MWLIUB72's premise that wiring encoding-awareness in means touching 176
  sites; for parse-based commands it means touching one.
- NEXT ACTION: fix in flight at the chokepoint — detect a UTF-16 BOM after the read and return a
  new `TldrError::UnsupportedEncoding`, handled where `FileTooLarge` already is in
  `get_code_structure` (skip the file, increment `files_skipped`, push a user-visible warning).

## Why

A file that cannot be read as valid UTF-8 should be skipped with a message. Instead it is
analysed as though it were empty, and the command reports success.

This is not the same defect as "the file was skipped". Being skipped is visible; being reported
as analysed-with-no-symbols is indistinguishable from a genuinely empty file, so the caller has
no way to know the answer is incomplete. A tree containing UTF-16 sources yields a confidently
wrong result with a zero exit code — the failure mode that corrupts downstream decisions,
because nothing invites anyone to check.

`TldrError` is not `#[non_exhaustive]`, so adding a variant is a breaking change. It is taken
deliberately, and it is the first change to clear the divergence-cost bar recorded on
TRDD-MWLIUB72 by fixing a defect that demonstrably reaches actual binary users, rather than
merely tidying code nothing reaches.

## What

- Detect the two UTF-16 BOMs (`FF FE`, `FE FF`) at the chokepoint, immediately after the read and
  before `from_utf8_lossy`, and return `TldrError::UnsupportedEncoding { path, detail }`.
- Handle that variant where `FileTooLarge` is already handled in `get_code_structure` (both the
  single-file and dir-walk arms): skip the file, bump `files_skipped`, push a warning naming it.
- **Deliberately NOT in scope:** heuristics for BOM-less UTF-16, or counting replacement
  characters to guess at corruption. A heuristic that misfires would reject valid UTF-8, which is
  a worse bug than the one being fixed. BOM detection is exact.

## Still open, and NOT to be planned off the old numbers

The SILENT bucket — files dropped from an analysis with no message — is the same class of defect
at read sites *outside* the parse chokepoint. Its size is unknown until the corrected re-survey
lands. Sequencing, once it does:

- **By severity, SILENT is the worst bucket**: a smaller, wrong answer reported as success.
- **The PANIC bucket is empty in production** and needs no work at all.
- **PROPAGATED** is probably correct for single-file reads, where failing loudly is right.
  Confirm rather than change.

## Acceptance

- [ ] `tldr structure design/reproducers/TRDD-BKALIK1B` no longer reports `bad.py` as analysed
      with zero symbols; it is skipped with a warning naming the file, while `good.py` and
      `control.py` still report 2 definitions each.
- [ ] A regression test covers the committed fixture, so the fixture cannot rot into a UTF-8 file
      and pass for the wrong reason.
- [ ] The corrected production-only survey has landed and the SILENT bucket's real size is
      recorded here.
- [ ] `cargo test -p tldr-core` shows no regression against the known baseline.

## Approval log

- 2026-09-06T04:16:38+0200 — Filed by the session Claude under the user's 2026-09-05 directive to
  decide from verified facts. Filing only; no code changed.
- 2026-09-06T04:38:00+0200 — Rewritten after reproducing the bug end-to-end. The first version's
  central claim (25 production panic sites) was false and is retracted; the card had also been
  left arguing with itself, a STOP banner contradicting its own body, which is a trap for a
  reader who skims to the section they need. Column moved `todo` → `dev`: a fix is in flight.
