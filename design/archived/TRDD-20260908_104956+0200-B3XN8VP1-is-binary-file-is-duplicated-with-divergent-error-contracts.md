---
trdd-id: B3XN8VP1
title: is_binary_file is duplicated with divergent error contracts and both are live
created: 2026-09-08T10:49:56+0200
updated: 2026-09-08T10:49:56+0200
column: todo
current-owner: session-claude
task-type: refactor
min-approval-requirement: none
labels: [duplication, error-handling, silent-failure]
---

# is_binary_file is duplicated with divergent error contracts and both are live

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body)

Split out of **TRDD-O66FM8TN** on 2026-09-08. Found *while* surveying that
card's read sites, which is provenance, not membership: nothing about this
duplication has to do with announcing skipped files.

**Not started.** Two functions, same name, opposite error contracts, both
reachable:

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

- [ ] Both bodies read. Whether they agree on NON-ERROR behaviour (byte budget,
      extension list) is recorded here with the evidence, before any fix.
- [ ] One implementation remains. If the swallow is genuinely wanted at
      `loc.rs`, it is spelled at the call site, not hidden in a helper.
- [ ] Whether BUG-003's 8KB limit applies to the surviving implementation is
      recorded as READ, not inferred from the literal `8192`.
- [ ] Red-proofed if behaviour changes: a file that the two variants classify
      differently is the discriminating fixture. If no such file exists, say so
      — that is the evidence that "delete one" was behaviour-preserving.

## Origin

Surfaced by the `File::open` / `read_to_end` survey under TRDD-O66FM8TN
(2026-09-08), which bucketed `file_utils.rs:315` and `:318` as the only two
SILENT sites and noted the same-name divergence in passing. Split to its own
card on a review finding that the parent had accumulated five acceptance boxes
across three unrelated subjects. Sibling split: TRDD-R7QK2M4E (the read-surface
inventory).
