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

### Probe observations, 2026-09-08

Eight one-file probes through `target/debug/tldr secure <file>`. **Observations,
not engine facts** — the header said "ENGINE facts" and that was the wrong noun
for a black-box result. They are on this card and not in a source comment:
engine behaviour ages out of a fixture comment, and a claim in source gets read
as current fact with no commit message beside it to date it.

Each probe is described by its SHAPE below rather than by a path, because the
files were written to a session scratchpad that will not survive. The shapes are
three to twelve lines each and reconstructing one is faster than locating it.

**A residual `d_control` left open, now closed by `g`:** `d` reporting a
resource leak proves the RESOURCE pass ran on that file, not that the TAINT pass
did — `secure` runs several sub-analyses. `g` closes it, because `g`'s finding
is itself a taint finding in the same file as the unreported cross-call flow.

| probe | shape | taint_count |
|---|---|---|
| `c_samebody` | `input()` → `os.system` inside ONE `def` | **1** |
| `f_modlevel_direct` | `input()` → `os.system`, module level, no call | **0** |
| `e_modlevel_call` | module-level `input()` → call into param-fed sink | 0 |
| `b_withcaller` | `input()` in one `def` → call into a param-fed sink in another | 0 |
| `d_control` | as `b_withcaller`, plus a resource leak | 0 — **leak IS reported** |
| `a_nocaller` | param-fed `os.system` alone, no source | 0 findings at all |
| **`g_both_in_one_file`** | **a same-body flow AND a cross-call flow in ONE file** | **1, at line 5** |
| **`h_three_flows`** | **three same-body flows, one file** | **3, at lines 5, 9, 13** |

**`g` is the probe that settles it, and it is the only one that needs no
cross-file inference.** One file, three functions: a same-body `input()` →
`os.system`, a parameter-fed sink, and a caller passing a source into it. Result:
`taint_count: 1`, reported at **line 5** — the same-body flow. The cross-call
flow in that same file is not reported. So the taint pass demonstrably RAN on
this file and entered a function body, and still did not follow the call. Every
earlier conclusion here rested on importing a fact from file `c` into a claim
about file `d`; `g` removes that join.

**`h` kills the alternative that would have undone `g`.** Every probe that found
taint at all found exactly ONE, and the fixture's two findings were one taint
plus one resource_leak — i.e. one per CATEGORY. So "the engine emits at most one
taint finding per file" explained `g`'s single result just as well as
"the cross-call flow was not found", and would have made `g` worthless. `h` puts
three same-body flows in one file and gets **3**, at three distinct lines. No
cap, no per-category dedup. `g`'s 1 is therefore a real absence.

**One mechanism explains all eight probes: analysis is per-function-body and
does not follow calls.** Same body → found (`c`, `g` line 5, `h` ×3). Split
across two bodies → not found (`b`, `d`, `g`'s other flow). Module level, which
has no function body at all → not found (`e`, `f`). No source anywhere → not
found (`a`).

**Parsimony is not proof, and it is worth saying why the hedge is not a
formality here.** No implementation was read. "One mechanism fits everything"
is the standard shape of a story that fits because it was built after seeing
the data — every probe above was designed by me, so the set is not a random
sample of engine behaviour and cannot rule out mechanisms nobody thought to
probe. What would settle it is reading the analyzer's traversal, which is
cheap and has not been done. Until then this is the best-supported reading, not
a fact about the engine.

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

## Open: does `secure` ever emit a non-high severity?

`test_secure_severity_sorting` is `#[ignore]`d because every finding on this
fixture is `"high"`, making its sort comparison true in either order. Six Python
patterns were probed; the three that produced findings were all `high`.

**That is a fact about six probes, not about the analyzer, and the distinction
decides who owns the bug:**

- If `secure` CAN emit low/medium/critical and these probes just missed those
  paths → the fixture is inadequate, and the fix is a richer fixture.
- If `secure` emits only `high` → the severity field carries no information, a
  security dashboard rates a resource leak identically to command injection,
  and that is an ENGINE defect. The ignored test would then be reporting a real
  product problem, and "fix the fixture" would be exactly the wrong instruction.

**A first attempt to resolve this by grep was itself wrong, and is recorded so
nobody repeats it.** Counting severity string literals under `commands/remaining/`
returned 3 `high`, 2 `low`, 1 `medium` — which looks like a clean refutation. It
is not. Reading the hits: `types.rs:648` is `confidence: "low"`, a DIFFERENT
FIELD that the pattern matched on the literal alone; `api_check.rs:2803-2804` are
`serialize_misuse_severity`, belonging to the api_check sub-analysis, which has
not been shown to feed a `SecureFinding` at all.

**Resolve it by reading the emitter that builds `SecureFinding`, not by grepping
for severity words.** Anything that matches a bare string literal will keep
picking up other fields with the same vocabulary.

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
