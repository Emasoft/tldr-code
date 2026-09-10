---
trdd-id: B3XN8VP1
title: is_binary_file is duplicated with divergent error contracts and both are live
created: 2026-09-08T10:49:56+0200
updated: 2026-09-10T14:37:13+0200
column: complete
implementation-commits: [a5bff82]
current-owner: session-claude
task-type: refactor
min-approval-requirement: none
labels: [duplication, error-handling, silent-failure]
---

# is_binary_file is duplicated with divergent error contracts and both are live

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-10

**DONE (worker-7).** Deleted the bool `is_binary_file` from
`metrics/file_utils.rs` (was L281-325, plus its 2 tests, plus a now-unused
`use std::io::Read`). Kept `crate::encoding::is_binary_file` (`Result`). Sole
production caller `metrics/loc.rs:566` now imports the `Result` variant and
**propagates** the read error instead of swallowing it:
`if has_binary_extension(path) || is_binary_file(path)? {`. An earlier pass of
this card landed `.unwrap_or(false)`; that was replaced with `?` because
`analyze_file` already returns `Result<_, TldrError>` and documents I/O errors,
so there is nothing to swallow — the `?` only moves the unreadable-file error
from the later `read_to_string` to the binary probe (`is_binary_file` reads the first 8 KB, so the error surfaces there), same error class. Also fixed:
`metrics/mod.rs` re-export list
(removed the dead `file_utils::is_binary_file` re-export),
`tests/metrics_tests.rs` (import switched + `.unwrap()` on the 2 call sites —
call-expression-only edit, per grant). `tests/encoding_base_tests.rs` needed
no change.

Verify: `grep -rn 'fn is_binary_file' crates/tldr-core/src` → 1 hit. `cargo
test -p tldr-core --lib` 4828 passed. `--test encoding_base_tests` 48 passed.
`--test metrics_tests` 105 passed. `cargo clippy -p tldr-core --lib -- -D
warnings` clean. `cargo build --workspace` clean (after other workers'
in-flight edits settled). Full evidence:
`reports/kanban-wave1/20260910_093026+0200-worker7-B3XN8VP1.md`.

Re-verified after the `?` edit, in the 2026-09-10 workspace gate:
`--test metrics_tests` 105 passed / 0 failed; `-p tldr-core --lib` 4828 passed
/ 0 failed; `make lint` (`cargo clippy --workspace -- -D warnings`) exit 0.

**The new `Err` path is NOT covered by a run — stated plainly rather than left
implied.** `crates/tldr-core/tests/metrics_tests.rs` was searched for a test
that feeds `analyze_file` or `is_binary_file` an existing-but-unreadable path:
**none exists.** The two nearest tests both miss it, and both were read to be
sure rather than counted from a grep. `test_analyze_file_not_found` (`:1129`)
passes `/nonexistent/file.py`, which returns at the `!path.exists()` guard
(`loc.rs:553-556`) and never reaches the `?` at all.
`test_analyze_file_binary` (`:1139`) passes a real temp file, so
`is_binary_file` returns `Ok(true)` — it exercises the `?`'s **Ok** arm.
So the `?` arm is covered **by type, not by a run**: the compiler guarantees
the error is propagated as a `TldrError`, and nothing observes what a caller
sees when it is. Making a genuinely unreadable file portably (permissions do
not bite as root, and not at all on some filesystems) is the reason no such
fixture exists here; if the behaviour ever needs pinning, that is the obstacle
to solve first, not an oversight to scold.

Split out of **TRDD-O66FM8TN** on 2026-09-08. Found *while* surveying that
card's read sites, which is provenance, not membership: nothing about this
duplication has to do with announcing skipped files.

Two functions, same name, opposite error contracts, both
reachable (pre-fix state, kept for history):

| | signature | on error |
|---|---|---|
| `tldr-core/src/encoding.rs:356` | `fn is_binary_file(&Path) -> Result<bool, TldrError>` | PROPAGATES |
| `tldr-core/src/metrics/file_utils.rs:304` | `fn is_binary_file(&Path) -> bool` | SILENT (`Err(_) => false`, twice) |

**The `bool` one is NOT dead code** — `metrics/loc.rs:34` imports
`is_binary_file` from `metrics::file_utils` by name. Verified first-hand.
`encoding_base_tests.rs` exercises the `Result` one
(`is_binary_file(..).unwrap()`).

## The defect is the DUPLICATION, not the shared name

An earlier draft of this card said "two contracts may both be legitimate; the
shared NAME is the defect", and recommended renaming the `metrics` one to
`is_binary_file_lossy` as the lazy fix. **That was wrong, and it is worth
recording why, because it is the seductive answer.**

Renaming makes the collision survivable and thereby removes the pressure to fix
it. What actually bites is that there are **two independent implementations of
one predicate**:

1. **They will diverge.** One gains an extension, the other does not. One gains
   a BOM check, the other does not. Then a file is binary to `loc.rs` and text
   to whatever calls the `Result` variant — inconsistent output from a single
   tool, and miserable to trace back to an import.
2. **It has already bitten once.** `BUG-003` is filed against one variant, with
   an `#[ignore]`-ed test on one variant, while the other carries a similar
   shape untested. That is divergence-in-maintenance happening in plain sight.
3. **Reuse-before-write says so.** Two copies of a null-byte scan, and possibly
   two `BINARY_EXTENSIONS` tables, is duplication the codebase already had a
   home for.

**The genuinely lazy fix is smaller than the rename:** keep the `Result`
variant, delete the `bool` one, and let its single caller spell the swallow out
loud — `is_binary_file(path).unwrap_or(false)` at `loc.rs`. That is a smaller
diff, it removes the ambiguity instead of documenting it, and it puts the
discard-the-error decision where a reviewer can see it. Making a silent swallow
*visible at the call site* is exactly what the parent card is about, so this
fix advances O66FM8TN rather than merely tidying near it.

## Establish BEFORE choosing — do not fix the error contract alone

**Whether the two implementations agree on NON-ERROR behaviour is UNREAD.**
Only `metrics/file_utils.rs:304-323` has been read in full. If the two scan
different byte counts or consult different extension lists, then the same file
gets different binary/not-binary answers depending on which import is in scope
— a correctness divergence strictly worse than the error contract, and one an
implementer who fixes only the error handling would leave behind.

Read both bodies first. The answer decides whether "delete one" is a
no-behaviour-change refactor or a behaviour change that needs its own test.

## What BUG-003 does and does not establish

`crates/tldr-core/tests/encoding_base_tests.rs:313` carries:

```rust
#[ignore = "BUG-003: is_binary_file only reads 8KB and may miss null bytes beyond that boundary"]
```

It is attached to a test of the **`Result` variant**.

**Verified:** the `bool` variant's body reads into `[0u8; 8192]` and scans that
buffer, so *it* has an 8KB horizon. That is a direct read of the code.

**NOT verified, and deliberately not claimed:** that BUG-003's 8KB horizon is
the same one, or that the `Result` variant still has it. `encoding.rs:356`'s
body has not been read. An earlier draft asserted "BUG-003 applies to BOTH" on
the strength of `8192` matching the string "8KB" — a number matching a number.
If the `Result` variant was since fixed to stream and the `bool` one was not,
that claim is backwards about which is defective, and two functions sharing a
name is precisely the situation where a claim about "both" is likeliest to be
wrong.

Also worth separating: an 8KB horizon on binary detection is a defensible
engineering choice, not self-evidently a bug. BUG-003 asserts bug-ness; this
card does not inherit that assertion, it only records where the limit is.

## Acceptance

- [x] Both bodies read. They did NOT fully agree: the bool variant also had an
      extension pre-check (`BINARY_EXTENSIONS`) the `Result` variant lacked;
      byte budget matched (`8192`, single read, no loop). See report §1 — the
      divergence was harmless because the one real caller (`loc.rs:566`)
      already ran `has_binary_extension` separately in the same `||`.
- [x] One implementation remains: `crate::encoding::is_binary_file` (Result).
      `loc.rs:566` does not swallow at all — it propagates:
      `if has_binary_extension(path) || is_binary_file(path)? {`. The swallow
      the card originally asked to make visible turned out to be unnecessary:
      the caller `analyze_file` returns `Result<_, TldrError>`, so the error
      has a home. The bool wrapper and its 2 tests are gone from
      `metrics/file_utils.rs`, the re-export is gone from `metrics/mod.rs`,
      and `tests/metrics_tests.rs` imports
      `tldr_core::encoding::is_binary_file` and `.unwrap()`s.
- [x] BUG-003's 8KB limit READ against the survivor: `encoding.rs:356-365`
      does a single `reader.read(&mut [0u8; 8192])`, no loop — same horizon
      as the deleted bool variant. Confirmed by direct read, not inferred
      from the literal. See report §3.
- [x] No behaviour change at any live call site (report §1) — no
      discriminating fixture exists/needed. Test coverage unchanged in
      aggregate: the 2 deleted file_utils.rs tests were exact duplicates of
      pre-existing `encoding_base_tests.rs` assertions.

## Origin

Surfaced by the `File::open` / `read_to_end` survey under TRDD-O66FM8TN
(2026-09-08), which bucketed `file_utils.rs:315` and `:318` as the only two
SILENT sites and noted the same-name divergence in passing. Split to its own
card on a review finding that the parent had accumulated five acceptance boxes
across three unrelated subjects. Sibling split: TRDD-R7QK2M4E (the read-surface
inventory).
