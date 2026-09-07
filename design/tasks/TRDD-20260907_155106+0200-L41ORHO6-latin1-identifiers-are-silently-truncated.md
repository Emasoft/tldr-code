---
trdd-id: L41ORHO6
title: A latin-1 accented identifier is silently reported under a truncated name
column: backburner
created: 2026-09-07T15:51:06+0200
updated: 2026-09-07T15:51:06+0200
current-owner: unassigned
task-type: bugfix
min-approval-requirement: user
labels: [robustness, encoding, silent-failure]
parent-trdd: BKALIK1B
---

# A latin-1 accented identifier is silently reported under a truncated name

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-07

- **MEASURED 2026-09-07, first-hand, against the built binary.** TRDD-BKALIK1B recorded this as
  "unmeasured and unfixed" and required its own card before closing; this is that card, and the
  measurement is now done, so it is no longer a hypothesis.
- **It is worse than the parent card guessed.** The parent predicted the symbol would "mangle or
  fail to parse and the surrounding structure can be dropped". What actually happens is quieter:
  the symbol is reported under a **truncated name that does not exist in the source**, and its
  neighbours are unaffected — so nothing looks wrong.

## The measurement

Two files, byte-identical source text, encoding the only variable:

```python
def funcion_ascii(): return 1
def función():       return 2
def naive_tail():    return 3
```

| file | `tldr structure` reports |
|---|---|
| `utf8_control.py` | `funcion_ascii`, **`función`**, `naive_tail` |
| `latin1.py` | `funcion_ascii`, **`funci`**, `naive_tail` |

`files_skipped: null`, `warnings: null`. The file is ANALYSED, not skipped — correctly so by the
current design: latin-1 carries no NUL and is not valid UTF-8, so it takes the deliberate M2
lossy fallback rather than the guard.

**What is measured, and what is not — because the first version of this card got it wrong.**
Measured: the emitted symbol name is `funci`, and its bytes are exactly `b'funci'` — the
identifier is TRUNCATED at the accent. This card originally said the name carries U+FFFD, the
replacement character `from_utf8_lossy` substitutes. **It does not.** Checked by dumping the
name's UTF-8 bytes from the JSON: no U+FFFD anywhere in it. The lossy substitution is what the
read path is documented to do, and U+FFFD is not an identifier character in the grammars tldr
uses, so a substituted-then-truncated-at-the-substitution chain is the obvious explanation — but
that chain is INFERRED from the code, not observed in the output. The observation supports
exactly this: *invalid UTF-8 in an identifier yields a silently truncated name.* Anyone fixing
this should establish the intermediate for themselves rather than inherit it from here.

**The consequence, also measured.** Add `caller.py` (UTF-8) importing and calling `función`:

```
tldr dead  ->  possibly_dead: ['funci', 'caller']     files_skipped: 0   warnings: []
```

A function that IS called is reported possibly-dead, because the definition is indexed under
`funci` while every caller references `función`. That is the same silent-wrong-answer shape as
TRDD-BKALIK1B's UTF-16 case — with one difference that makes it harder to notice: **nothing was
skipped, so there is nothing for TRDD-O66FM8TN's warning to announce.** The file was read,
analysed, and answered about incorrectly.

Reproducer built at measurement time from the snippet above (latin-1 encode of the same string);
it is not committed, because a committed latin-1 fixture needs the same `.gitattributes`
treatment as the TRDD-BKALIK1B directory — that is part of the work, not a precondition for it.

## Why this is not covered by the existing guard

`fs::wide_encoding_marker` keys on a BOM or a NUL in the first `NUL_SCAN_PREFIX` bytes. Latin-1
has neither. That is deliberate: the parent card measured that a UTF-8-validity check would
reject latin-1/cp1252 files whose structure is pure ASCII and whose only non-ASCII bytes sit in
comments or string literals — where the lossy path is the RIGHT answer. So the fix cannot be
"reject invalid UTF-8"; it has to distinguish an accent in a comment (fine, lossy is correct)
from an accent in an identifier (wrong, currently silent).

## What (not yet decided — this is the open question)

Three shapes, none of them chosen:

1. **Detect the damage at the identifier's boundary** — NOT by looking for U+FFFD *inside* the
   extracted name, which the measurement above rules out: the name comes back as `funci` with no
   replacement character in it. Whatever signal is used has to be visible where the truncation
   happens (the byte after the identifier's end in the decoded source, or the decode step itself),
   not in the name the extractor hands back. Narrowest option, and it acts exactly where the
   damage is; needs a decision about what a partially-analysed file reports.
2. **Transcode instead of lossy-decoding** (latin-1 → UTF-8 when the bytes are valid latin-1),
   which fixes the name rather than reporting the damage. Risks guessing the wrong codepage —
   latin-1 and cp1252 differ in `0x80-0x9F`, and every byte is "valid latin-1" by construction,
   so this cannot be a detection, only a default.
3. **Warn per file when the lossy path substituted anything**, leaving the analysis as-is. The
   cheapest, and the only one that generalises past identifiers, but it is noise on the large
   population of files where lossy is correct.

Whichever is picked, it needs the population argument the parent card's guard got: how many real
files are latin-1 with accented identifiers, versus latin-1 with accents only in strings.

## Acceptance

- [ ] A latin-1 source file with an accented identifier no longer yields a truncated symbol name
      with no warning — either the name is correct, or the damage is announced.
- [ ] A regression test asserts the fixture's ENCODING (invalid UTF-8, no NUL) before asserting
      behaviour, and `.gitattributes` covers its directory — same rot-protection as
      TRDD-BKALIK1B's fixtures, for the same reason.
- [ ] The `tldr dead` false positive above is gone, demonstrated with the caller/callee pair.
- [ ] The chosen shape records WHY the other two were rejected, with the population measurement.

## Notes

Filed while acting on the delegated human review of TRDD-BKALIK1B. That card lists two items as
needing their own cards before it closes: the 56 SILENT read sites (TRDD-O66FM8TN) and this one.
