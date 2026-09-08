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

### Probe results, 2026-09-08 — recorded here because they are ENGINE facts

Six one-file probes through `target/debug/tldr secure <file>`. They are on this
card and not in a source comment: engine behaviour ages out of a fixture
comment, and a claim in source gets read as current fact with no commit message
beside it to date it.

| probe | shape | taint_count |
|---|---|---|
| `c_samebody` | `input()` → `os.system` inside ONE `def` | **1** |
| `f_modlevel_direct` | `input()` → `os.system`, module level, no call | **0** |
| `e_modlevel_call` | module-level `input()` → call into param-fed sink | 0 |
| `b_withcaller` | `input()` in one `def` → call into a param-fed sink in another | 0 |
| `d_control` | as `b_withcaller`, plus a resource leak | 0 — **leak IS reported** |
| `a_nocaller` | param-fed `os.system` alone, no source | 0 findings at all |
| **`g_both_in_one_file`** | **a same-body flow AND a cross-call flow in ONE file** | **1, at line 5** |

**`g` is the probe that settles it, and it is the only one that needs no
cross-file inference.** One file, three functions: a same-body `input()` →
`os.system`, a parameter-fed sink, and a caller passing a source into it. Result:
`taint_count: 1`, reported at **line 5** — the same-body flow. The cross-call
flow in that same file is not reported. So the taint pass demonstrably RAN on
this file and entered a function body, and still did not follow the call. Every
earlier conclusion here rested on importing a fact from file `c` into a claim
about file `d`; `g` removes that join.

**One mechanism explains all seven probes: analysis is per-function-body and
does not follow calls.** Same body → found (`c`, `g` line 5). Split across two
bodies → not found (`b`, `d`, `g`'s other flow). Module level, which has no
function body at all → not found (`e`, `f`). No source anywhere → not found
(`a`). This is the best-supported reading; it is not proof, because no
implementation was read.

**Superseded:** an earlier version of this section asserted "the flow is not
followed across a CALL" on the `b`/`c` pair alone, which `f` refuted — `f` has
source and sink in the same scope with NO call and still reports 0. The claim is
now back, but on `g`'s evidence rather than that pair's.

**Ruled out:** a missing `import os` (every probe file carries it).

**NOT ruled out, though an earlier version said it was:** that `os.system` is
recognised as a sink *in general*. `c` and `g` show the PAIR (`input()` source,
`os.system` sink, one body) yields a finding. If a sink is only observable when
a tainted value reaches it, no probe here isolates the sink on its own.

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
