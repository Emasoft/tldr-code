---
trdd-id: 8068ASKJ
title: secure emits a root key where remaining_test's shadow SecureReport requires path
column: todo
created: 2026-09-08T10:26:05+0200
updated: 2026-09-08T10:26:05+0200
current-owner: session-claude
task-type: bugfix
min-approval-requirement: none
labels: [test-failure, json-output, schema, stale-test]
---

# secure emits a root key where remaining_test's shadow SecureReport requires path

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body)

Filed 2026-09-08. **FIX LANDED in `3bd0efb` the same day.** Cause was settled
from production source before filing — these tests are stale, production is
correct. Sibling of TRDD-8K4YKK1Q: same commit, same intent, different field.

**Result: 9 passed / 1 failed, from 3 passed / 7 failed.** Both mechanisms this
card identified are fixed. The remaining failure is a DIFFERENT defect that the
schema fix UNMASKED — `test_secure_detects_taint` now deserializes fine and
fails on `summary.taint_count > 0`. It is filed as **TRDD-FB1E4UVD** and is not
a residue of this card. Taint detection itself is confirmed working
(`taint_count: 2` on a hand-written `input()`→`eval()` sample); the fixture
`PYTHON_SECURE_SAMPLE` is the suspect.

**The "which SecureReport is on the wire" question is CLOSED, and by better
evidence than this card asked for.** The card demanded reading the
serialization call path. Two things were done instead, and the second is
stronger: `crates/tldr-cli/src/commands/remaining/secure.rs:56` imports the type
from `super::types` (still an inference — naming a type is not proof it is the
one serialized), and then the command was RUN, yielding a payload with `root`
present and `path` absent. A behavioural observation of the actual output beats
reading either type definition, and it is self-verifying: had the `tldr-core`
type been on the wire, `root` would not appear and the fix would have failed
loudly rather than silently.

**What is NOT verified, stated so nobody ticks it by inspection:** the six
deserialization guards were genuinely observed red-then-green (they failed on
the stale key before the fix, which is exactly the mutation the acceptance list
asks for). The NON-EMPTY half of the `:1550` predicate was never observed
failing — no payload with a null or empty `root` was constructed. That box
stays open.

Until this card existed the work was queued only as a parenthetical inside
commit `5c1d56d`'s body, which is the weakest possible queue — not on the board,
not greppable as a card. That is what this file fixes.

## What is measured

`cargo test -p tldr-cli --test remaining_test secure_command`:

```
test result: FAILED. 3 passed; 7 failed; 0 ignored; 0 measured; 85 filtered out
```

**The three that PASS are exactly the three that never parse JSON** —
`test_secure_help`, `test_secure_text_output`, `test_secure_file_not_found`.
That split is itself the mechanism signature: nothing about the `secure` command
is broken, only the tests that decode its JSON.

Every one of the 7 failures is accounted for, by panic site:

| panic site (`remaining_test.rs`) | n | failure |
|---|---|---|
| `:1384:43`, `:1401:66`, `:1417:66`, `:1435:66`, `:1460:66`, `:1492:66` | 6 | ``Error("missing field `path`", line: 27, column: 1)`` |
| `:1550:9` (`test_secure_json_schema`) | 1 | `assertion failed: value.get("path").is_some()` |

6 + 1 = 7 = the failure count, so no failure is unclassified. That message occurs
exactly 6 times in the run, which pins each of those six sites to one message
rather than leaving the total satisfiable by some other split.

**Two mechanisms, not one** — the same shape as TRDD-8K4YKK1Q:
typed deserialization against a shadow struct (6), plus one raw key lookup (1).
A fix that only edits the shadow struct leaves `:1550` red.

## Cause — production is right, the tests are stale

`crates/tldr-cli/src/commands/remaining/types.rs:349` — the emitter:

```rust
pub struct SecureReport {
    pub wrapper: String,
    /// cross-command-consistency-v1 (BUG-14): renamed in JSON to `root`
    /// so project-root field naming is identical across commands. The Rust
    /// field is still `path` for backwards compatibility; JSON callers see
    /// `root`. The `alias` keeps deserialisation of older bodies working.
    #[serde(rename = "root", alias = "path")]
    pub path: String,
    ...
}
```

`crates/tldr-cli/tests/remaining_test.rs:243` — the shadow copy the tests decode
into, with no serde attribute at all:

```rust
pub struct SecureReport {
    pub wrapper: String,
    pub path: String,
    ...
}
```

So production serializes `root`; the shadow struct demands `path`; serde reports
`missing field \`path\``. Same commit and same intent as TRDD-8K4YKK1Q
(`66fa8bc`, BUG-14, "cross-command-consistency-v1") — a deliberate wire rename
whose test sweep was incomplete. Different field, so it is a separate card.

**Do NOT take the doc comment as the proof.** It is prose beside an attribute,
and this exact chain has already been misled once by trusting a doc comment
instead of the emitter (recorded in TRDD-8K4YKK1Q). The load-bearing evidence is
runtime: the payload the tests receive genuinely lacks `path`, which is why
serde fails. Re-derive from `git show 66fa8bc` if the direction is ever doubted.

## The trap: there are TWO SecureReport types in production

- `crates/tldr-cli/src/commands/remaining/types.rs:349` — has the
  `rename = "root"`. Runtime behaviour says this is the one on the wire.
- `crates/tldr-core/src/wrappers/secure.rs:64` — a DIFFERENT type, bare
  `pub path: String`, no rename, and its `summary` is a
  `HashMap<String, serde_json::Value>` rather than a typed `SecureSummary`.

**Confirm which type actually reaches stdout before editing either.** The
inference above is from the failure (the payload lacks `path`, and only the CLI
type renames it), not from reading the serialization call path. That inference
is sound but it is an inference; a fix that edits the core type would be a
production change made on a guess.

## The fix, and the one decision that is NOT obvious

For the six deserialization sites, add to the SHADOW struct:

```rust
#[serde(rename = "root")]
pub path: String,
```

**`rename`, deliberately NOT `alias`** — the identical reasoning that
TRDD-8K4YKK1Q settled for `ExplainReport`, and it must not be re-litigated into
the easy answer. Production carries `alias = "path"`, so making the shadow
struct accept BOTH spellings would blind it to exactly the distinction it exists
to pin down: a later revert of the rename would pass silently. The shadow
struct's whole value is that it CAN disagree with production.

For `:1550`, swap the raw key: `value.get("root")`.

**Deleting the shadow struct and importing production is the tempting fix and it
is wrong**, for the same reason — production derives `Deserialize` with
`alias = "path"`, so an imported type accepts both names and asserts nothing.

## Acceptance

- [ ] All 7 `secure_command::*` tests pass; the 3 that already pass still do.
- [ ] The 6 deserialization sites are fixed via `rename` on the shadow struct,
      NOT `alias`, and NOT by importing the production type. The reason is in a
      code comment at the struct, so the next reader does not "simplify" it back.
- [ ] `:1550`'s raw key lookup is fixed too — it is a second mechanism and a
      shadow-struct-only fix leaves it red.
- [ ] `:1550` asserts a non-empty STRING, not mere presence. `get` returns
      `Some(Value::Null)` for an explicit null, so a presence-only check passes
      on a null payload — the defect already fixed in the 36 matrix guards under
      TRDD-8K4YKK1Q. Do not reintroduce it here.
- [ ] Red-proofed: each guard is observed FAILING before it is accepted. The
      mutation is reverting the emitter's `rename` to `path`, not deleting the
      assertion.
- [ ] Which production `SecureReport` is on the wire is CONFIRMED by reading the
      serialization path, not inferred from the failure. Recorded here.
- [ ] No claim in the closing notes is quantified beyond what was run. The run
      is `-p tldr-cli`; `tldr-core`, `tldr-daemon` and `tldr-mcp` have their own
      test targets and are NOT covered by it.

## Origin

Surfaced by the same unfiltered `cargo test -p tldr-cli --no-fail-fast` run that
produced TRDD-8K4YKK1Q, and deferred while that card's 44 `function_name`
assertions were fixed (`5c1d56d`). Sibling cards: TRDD-8K4YKK1Q (same commit,
`function_name` → `function`), TRDD-DPL55YB3 (the `functions`/`methods` stale
sweep), TRDD-BJ9T0U9I (tests asserting against a stale release binary — NOT this
one, which resolves its binary with `assert_cmd::cargo::cargo_bin!`).

`remaining_test.rs` is currently in a MIXED state: `ExplainReport` carries the
`rename` from `5c1d56d`, `SecureReport` does not. That inconsistency is an
argument for doing this card soon, and it is why the convention comment in the
acceptance list is not optional.
