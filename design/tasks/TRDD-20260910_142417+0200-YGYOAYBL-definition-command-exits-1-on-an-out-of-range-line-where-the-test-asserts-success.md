---
trdd-id: YGYOAYBL
title: test_definition_invalid_position asserts success but the binary exits 1 on an out-of-range line
column: todo
created: 2026-09-10T14:24:17+0200
updated: 2026-09-10T14:24:17+0200
current-owner: session-claude
task-type: bugfix
scope: project
min-approval-requirement: none
labels: [test-failure, cli, exit-code]
---

# test_definition_invalid_position asserts success but the binary exits 1 on an out-of-range line

## Symptom — OBSERVED OUTPUT ONLY

`definition_command::test_definition_invalid_position` in
`crates/tldr-cli/tests/remaining_test.rs` fails. This card records what the run
printed and nothing else. **No diagnosis is offered here on purpose** — see
"What this card does NOT claim".

From `gate-fail-detail.txt`, the 2026-09-10 workspace gate, verbatim:

```
---- definition_command::test_definition_invalid_position stdout ----

thread 'definition_command::test_definition_invalid_position' (410750127) panicked at
  /Users/…/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/ops/function.rs:250:5:
Unexpected failure.
code=1
stderr=```"Error: definition not found for /var/folders/…/T/.tmph5psMc/sample.py:9999:0: invalid argument: line 9999 out of range (file has 13 lines)\n"```
command=`"/Users/…/tldr-code/target/debug/tldr" "definition" "/var/folders/…/T/.tmph5psMc/sample.py" "9999" "0"`
code=1
```

So: the test invokes `tldr definition <tmpfile>.py 9999 0`, the binary exits
**1** with a message naming the out-of-range line, and the assertion — an
`assert_cmd` success assertion, which is what produces "Unexpected failure" from
`ops/function.rs` — fails because it required exit 0.

## What this card does NOT claim

- **Not** that the binary is wrong. Exiting non-zero on an out-of-range
  argument is a defensible contract, arguably the better one.
- **Not** that the test is stale. It may be pinning a deliberate
  "invalid position degrades gracefully to a not-found result" contract.
- **Not** that this is pre-existing. It was **not** measured at a pre-wave
  checkout. It is absent from the 2026-09-08 baseline set
  (`reports/integration-failure-set/20260908_140723+0200-head-integration-failures.md`,
  lines 203-228), and no worker in the 2026-09-10 wave touched the `definition`
  command path — but "nobody touched it" is an argument, not a measurement, and
  this card does not upgrade it to one.

Which of production or test is wrong is exactly the question, and it is
undecided. Recording it as observed output is the honest state; the shape
("production-right / test-stale" vs "production-regressed") is what the
implementer must establish, from the command's documented contract and its
history, before changing either side.

## Acceptance

- [ ] The intended contract for an out-of-range line/column is established from
      the command's own source and docs, and recorded here. Not inferred from
      which side is easier to change.
- [ ] Whether this failure is pre-existing is MEASURED — the target run at a
      pre-wave checkout with a clean `git status --porcelain` — or the card
      states plainly that it was not measured and why.
- [ ] Exactly one side is fixed, and the reason the OTHER side was left alone
      is recorded.
- [ ] Red-proofed: the fixed assertion is observed FAILING under a deliberate
      mutation before being accepted as passing.

## Relationships

- TRDD-2U7D9PNS — the unfiltered `cargo test -p tldr-cli` run; this red is one
  of the things blocking it.

## Notes
