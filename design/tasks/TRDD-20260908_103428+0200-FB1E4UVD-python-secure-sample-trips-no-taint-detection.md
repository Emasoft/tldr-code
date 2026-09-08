---
trdd-id: FB1E4UVD
title: PYTHON_SECURE_SAMPLE trips no taint detection so test_secure_detects_taint fails
column: todo
created: 2026-09-08T10:34:28+0200
updated: 2026-09-08T10:34:28+0200
current-owner: session-claude
task-type: bugfix
min-approval-requirement: none
labels: [test-failure, fixture, taint]
---

# PYTHON_SECURE_SAMPLE trips no taint detection so test_secure_detects_taint fails

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body)

Filed 2026-09-08. **Not started.** This failure was UNMASKED by `3bd0efb`
(TRDD-8068ASKJ) — it did not exist as a visible failure before, because the test
died earlier on a deserialization error and never reached this assertion.

**RESOLVED to (a) — the fixture. The fork below is settled; it is kept only to
show what was weighed.** The filed version asserted "Production is NOT broken"
in this block while the body still offered fork (b) "genuine detection
regression → fix the ENGINE". Those contradict, and STATE supersedes the body,
so an implementer would have been told authoritatively not to look at the engine
and then handed the engine as a candidate. The contradiction existed because the
strongest claim was made without the cheapest measurement: **the fixture was
never opened.**

It has now been read. `PYTHON_SECURE_SAMPLE` contains SINKS but no SOURCE:

```python
from flask import request          # imported, never used
def unsafe_command(filename):
    os.system(f"cat {filename}")   # sink, fed by a PARAMETER
def unsafe_deserialize(data):
    return pickle.loads(data)      # sink, fed by a PARAMETER
```

Every tainted value arrives as a function parameter. The control sample that
DOES report `taint_count: 2` differs in exactly one relevant way — it opens with
`user_input = input("id: ")`, an explicit source. So the engine is not failing to
propagate; there is no source→sink flow in this fixture to propagate.

**The fix is the FIXTURE.** Give it a real source (`input()`, or the `request`
it already imports) flowing into one of the sinks it already has.

**One design question this leaves open, and it is NOT a blocker:** whether an
untrusted *parameter* should itself count as a taint source is a legitimate
engine-design question. It is not a regression, so it does not belong on this
card — if it is worth pursuing, it is a new one.

## What fails

`crates/tldr-cli/tests/remaining_test.rs:1409`:

```rust
assert!(report.summary.taint_count > 0, "Should detect taint issues");
```

against `PYTHON_SECURE_SAMPLE`. `taint_count` is 0.

## What is ruled out, and by what

**The taint engine works.** The same debug binary, run on a hand-written sample:

```python
def vulnerable():
    user_input = input("id: ")
    eval(user_input)
    query = "SELECT * FROM t WHERE id = " + user_input
    cursor.execute(query)
```

reports `"taint_count": 2` with 2 findings, both `category: "taint"`. So a
generic "secure no longer detects taint" hypothesis is dead.

**The sibling assertion passes.** `test_secure_basic_analysis` asserts
`!report.findings.is_empty()` on the SAME fixture and is green. So `secure`
does find issues in `PYTHON_SECURE_SAMPLE` — just none categorised as taint.

That pair is the discriminating evidence: the fixture reaches the analyzer and
produces findings, and the analyzer can produce taint findings; what is missing
is specifically taint findings FROM THIS FIXTURE.

## The fork the implementer must decide, not assume

| | reading | consequence |
|---|---|---|
| a | the fixture never contained a taint pattern the engine recognises, and the assertion was only ever green by accident | fix the FIXTURE — add a real source→sink flow |
| b | the fixture does contain a pattern that SHOULD be detected and no longer is | a genuine detection regression, narrower than "taint is broken"; fix the ENGINE |

**Read `PYTHON_SECURE_SAMPLE` first.** If it has no `input()`/`request`-style
source flowing to an `eval`/`execute`-style sink, (a) is settled and the fix is
the fixture. If it does, (b) is live and this becomes a production bug — in
which case the hand-written sample above is the control that proves the engine
is not wholly broken, and the difference between the two samples is the lead.

**Do not "fix" this by weakening the assertion to `>= 0` or deleting it.** An
assertion that cannot fail is worse than a red test; the whole reason this was
invisible until today is that an earlier error stopped it being evaluated.

## Acceptance

- [ ] `test_secure_detects_taint` passes, and the (a)/(b) decision above is
      recorded here with the reason and the fixture evidence.
- [ ] If (a): the fixture contains an explicit source→sink flow, and the test
      still asserts `taint_count > 0` — not a weakened predicate.
- [ ] Red-proofed: the assertion is observed FAILING against a fixture with the
      taint pattern removed, so it is known to discriminate.
- [ ] `cargo test -p tldr-cli --test remaining_test secure_command` is 10/10.

## Origin

Unmasked by `3bd0efb` (TRDD-8068ASKJ), which fixed the `path`→`root` shadow
struct key and took `secure_command` from 3 passed / 7 failed to 9 passed /
1 failed. This card is the 1. Sibling: TRDD-8068ASKJ (the schema fix),
TRDD-8K4YKK1Q (the same BUG-14 rename sweep, `function_name` → `function`).
