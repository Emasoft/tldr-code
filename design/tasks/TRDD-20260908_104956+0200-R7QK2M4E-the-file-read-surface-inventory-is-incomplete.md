---
trdd-id: R7QK2M4E
title: The file-read surface inventory is incomplete so no count over it can be trusted
column: todo
created: 2026-09-08T10:49:56+0200
updated: 2026-09-08T10:49:56+0200
current-owner: session-claude
task-type: audit
min-approval-requirement: none
labels: [audit, error-handling, inventory]
---

# The file-read surface inventory is incomplete so no count over it can be trusted

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body)

Split out of **TRDD-O66FM8TN** on 2026-09-08. That card is about a user-visible
behaviour (a skipped file must be announced). This one is about the
**inventory**: which file-read call sites exist at all. It ships no behaviour
change.

**SIBLING, not a prerequisite.** An earlier draft called this an NPT of
O66FM8TN and carried `parent-trdd:`. Both were wrong. The `parent-trdd:` broke
the depth-1 rule (the edge belongs on the parent's `npt:`, so writing it on the
child put it on the wrong end and left the right end empty). And the
relationship itself was false: O66FM8TN's remaining work is decisions on 56
ALREADY-ENUMERATED sites plus centralising the skip path — **neither depends on
this card.** Calling it an NPT would have promoted a self-imposed blocker into a
declared dependency, which is worse than a box, because a box can be skipped and
a declared NPT cannot.

The split was made because O66FM8TN had grown to five acceptance boxes, three
of which were about *how to measure the read surface* rather than about
announcing skipped files. A card that collects everything found while working
it is a session log, not a task.

**Two of the three passes are DONE and verified. One pattern family is open.**

| pass | patterns | status |
|---|---|---|
| 1 | `read_to_string` | DONE (earlier) — 56 SILENT sites, decisions still owed on O66FM8TN |
| 2 | `File::open`, `read_to_end`, `.read(&mut …)` | **DONE 2026-09-08, audited first-hand** |
| 3 | `fs::read(`, `read_exact` | **OPEN** — 13 raw hits, unbucketed |

**There is no basis yet for calling even the union of all three "the read
surface."** Pass 3 exists only because pass 2's pattern set was assumed
complete and was not. `File::create`, `OpenOptions::new().open()`, and any
multi-line call where `&mut` falls on the next line are all still outside every
pattern run so far. State the patterns, never "the read surface".

## Pass 2 — DONE, and audited first-hand

Delegated survey:
`reports/encoding-survey/20260908_103909+0200-file-open-read-to-end-bucketing.md`.

**Result: 8 production sites — PROPAGATED 6 · SILENT 2 · WARNED 0 · PANIC 0.**
Zero new instances of O66FM8TN's defect (a silently dropped file) among them.

The survey was delegated; **the audit was not.** All 32 raw hits were
re-verified first-hand on 2026-09-08, because the first version of this
conclusion was ticked from a 2-of-8 sample and that was correctly faulted:

- The grep was **re-run** with a quoted `--include='*.rs'` → **32 hits**, the
  same set. (Unquoted, the shell eats the glob and grep searches every file
  type, silently inflating any inventory. The quoting is the difference between
  a count and a number.)
- **All 19 exclusions read verbatim.** Every one is a `//` or `///` comment or
  a quoted string — 11 of them inside `remaining/api_check.rs`, which
  implements a lint rule that *detects* `File::open` in other people's code.
  **Zero wrongly-excluded call sites.** This was the bucket with no evidence
  phrase and the one where being wrong leaves no trace, so it is the one that
  most needed reading.
- **All 4 test lines confirmed** by reading the declarations, not by filename:
  `analysis/mod.rs:101` and `fix/mod.rs:38` carry `#[cfg(test)] mod …;` for
  whole files that have no `#[cfg(test)]` of their own, and `check.rs:836`
  opens an inline `#[cfg(test)] mod tests`.
- **5 of the 6 PROPAGATED carry `?` on the hit line itself**; `salsa.rs:530`
  was read in context and is `.map_err(|e| …)?`. The 2 SILENT
  (`metrics/file_utils.rs:315`, `:318`) were read in full earlier.

**The report's bolded "Test-site total: 5" is WRONG — there are 4.** Its own
reconciliation two sections below uses 4 (`8 + 4 + 19 + 1 = 32`) and is right.
Recorded here so the 5 is not re-quoted from a report that is otherwise
accurate in every classification.

### The one limit that survives the audit

**PROPAGATED describes the SITE, not what a user sees.** `?` propagates one
frame. A caller doing `if let Ok(x) = helper(path)` kills the error there, and
the site is still correctly bucketed PROPAGATED. Establishing that any of the
6 reaches a user requires tracing callers, which this pass did not do and does
not claim.

### A trap this pass set and nearly caught me

`check.rs:3015` and `:3035` are `let file = File::open(path)?;` — no quotes on
the line, so they read as live code in a grep hit. They are inside
`format!(r#"…"#)` raw-string mutation-test templates; the `r#"` is on a
*different line*. **A single grep line cannot tell you whether it is code.**
That is the same one-line-inference shape as the rest of this work, and it
fails toward "this is a real call site", which is the safe direction here but
the unsafe one elsewhere.

## Pass 3 — OPEN

`fs::read(` and `read_exact` were in **neither** pattern set. Measured
first-hand 2026-09-08 with a quoted `--include='*.rs'` over `crates/*/src`:

**13 raw hits.** Raw hits, not call sites — the distinction this whole card
exists to enforce:

| hit | status |
|---|---|
| `fix/rust_lang.rs:33` — `("read_exact", "use std::io::Read;")` | **NOT a call** — a string in a fixup table |
| `semantic/enrichment_tests.rs:465` | test code living in `src/` — the classify-by-reading trap again |
| `salsa.rs:831` — `fs::read(&cache_path).unwrap()` | **suspected test** (`unwrap`, fixture path); UNCONFIRMED |
| the other 10 | **UNAUDITED** — same status the 19 exclusions had before they were read |

So the production count is **≤ 11 and possibly lower**, and stating "13 sites"
would repeat, inside the card that documents it, the exact defect the card is
about.

Sites in the unaudited 10, for the implementer's convenience — `encoding.rs:252`,
`ast/parser.rs:345`, `fs/mod.rs:127`, `callgraph/languages/base.rs:99`,
`patterns/validation.rs:328`, `contracts/validation.rs:386` and `:442`, and
three `read_exact` calls at `salsa.rs:508`, `:516`, `:524`.

## Acceptance

- [x] Pass 2 (`File::open` / `read_to_end` / `.read(&mut …)`) is bucketed, and
      every one of the 32 raw hits is classified by someone who read it.
- [ ] Pass 3 (`fs::read(` / `read_exact`) is bucketed the same way. Count
      AFTER classification. Name the non-calls; do not report raw hits as sites.
- [ ] Every count in the closing notes names its PATTERN SET. "The read
      surface" is not a phrase any pass here has earned.
- [ ] Whichever patterns are still unrun (`File::create`,
      `OpenOptions::new().open()`, multi-line `.read(\n &mut …)`) are named
      explicitly as unrun, so the next reader does not assume closure again.

## Origin

Split from TRDD-O66FM8TN on 2026-09-08, on a review finding that the parent had
become a topic rather than a task: its acceptance criteria had drifted from
"announce skipped files" to "inventory our read sites", and the second only
matters because it serves the first. Sibling split: TRDD-B3XN8VP1 (the
duplicate `is_binary_file`), also found during pass 2 — provenance, not
membership.
