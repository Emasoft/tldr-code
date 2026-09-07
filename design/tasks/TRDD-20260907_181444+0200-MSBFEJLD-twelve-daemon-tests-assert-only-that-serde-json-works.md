---
trdd-id: MSBFEJLD
title: Twelve daemon tests assert only that serde_json parses a literal they just wrote
column: todo
created: 2026-09-07T18:14:44+0200
updated: 2026-09-07T18:14:44+0200
current-owner: unassigned
task-type: bugfix
min-approval-requirement: user
labels: [tests, fake-tests, daemon]
---

# Twelve daemon tests assert only that serde_json parses a literal they just wrote

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-07

- **MEASURED, not suspected.** Bodies read directly from
  `crates/tldr-daemon/tests/daemon_tests.rs`. Nothing here is inferred from a name or a count.
- Found while settling an unrelated coverage question on TRDD-O66FM8TN. It is filed rather than
  fixed in place because rewriting twelve tests is its own task, not a side effect of that one.

## The measurement

Every test in `mod message_tests` (`daemon_tests.rs:57`) has this shape:

```rust
#[test]
fn structure_request_format() {
    let request = r#"{"cmd": "structure", "language": "python", "max_results": 100}"#;
    let parsed: serde_json::Value = serde_json::from_str(request).unwrap();
    assert_eq!(parsed["cmd"], "structure");
    assert_eq!(parsed["language"], "python");
    assert_eq!(parsed["max_results"], 100);
}
```

The test writes a JSON string literal, hands it to `serde_json`, and asserts the parsed value
equals what it just wrote. **It never references a daemon type, a request struct, a handler, or
any `tldr_daemon::` item.** `mod message_tests` has no `use` statements at all. The assertions
cannot fail unless `serde_json` itself regresses, and if the daemon's real request format
changed tomorrow — a renamed field, a new required key, a changed type — all twelve would still
pass.

The twelve: `ping_request_format`, `tree_request_format`, `structure_request_format`,
`extract_request_format`, `calls_request_format`, `cfg_request_format`, `context_request_format`,
`impact_request_format`, `search_request_format`, `slice_request_format`,
`response_ok_format`, `response_error_format`.

That is 12 of the 39 test functions the harness reports for `tldr-daemon` — roughly 30% of the
crate's apparent test count, asserting nothing about the crate.

## The same file already diagnosed this defect and fixed only one instance

`mod socket_tests`, thirty lines above, carries this comment:

> why: the previous version of this test re-implemented the MD5 hashing logic inline instead of
> calling the daemon's own function, so it could never catch a regression in
> `compute_socket_path`/`compute_tcp_port` itself (a fake/conceptual test — see tldr rule on
> tests that don't exercise the code they claim to test).

Someone identified the exact class, wrote down why it is fatal, fixed `socket_tests` to call
`compute_socket_path` for real — and left twelve instances of the same defect in the next module
down, in the same file. So this is not an unknown problem; it is a known one that was fixed
locally and not swept.

## Why it matters beyond tidiness

The count is what makes it dangerous. `cargo test -p tldr-daemon` reports 39 passing tests, and
39 sounds like a covered crate. It is the number a future session will use to decide the daemon
is safe to change. Subtract these twelve and the remaining 27 are: 9 path-traversal rejections,
4 response/socket unit tests, 7 state tests, 3 cache tests, 2 perf, 2 socket. **No test anywhere
in the crate asserts on any handler's output content** (established separately, at body level,
on TRDD-O66FM8TN) — and the inflated count is part of why nobody noticed.

## What

Not decided — the options differ in cost and in what they buy:

1. **Delete them.** Cheapest, and honest: a test that cannot fail is worse than no test because
   it inflates the count. Loses nothing, since they assert nothing.
2. **Make them real** — parse into the daemon's actual request/response types
   (`tldr_daemon::message::*` or wherever the wire structs live) so a field rename breaks them.
   This is what the `socket_tests` fix did for its own case, and it is the shape the standing
   project rule asks for.
3. **Replace with round-trip tests** against the real server: send the request, assert the
   response shape. Highest value, highest cost, and it overlaps whatever unit 5's decision
   produces on TRDD-O66FM8TN.

2 is the direct analogue of the fix already applied in this same file, which is the argument for
it over 1.

## Acceptance

- [ ] No test in `crates/tldr-daemon/` asserts a property of a literal it constructed in the
      same function without passing it through daemon code.
- [ ] Whatever replaces them FAILS when a daemon request/response field is renamed —
      demonstrated by renaming one, watching it go red, and reverting.
- [ ] The daemon's reported test count is stated honestly on this card before and after, so the
      change in the number is visible rather than silent.

## Notes

Filed while settling the daemon coverage question on TRDD-O66FM8TN. Not fixed in that card's
commits: it is a different defect, in a different file, and a twelve-test rewrite is not a side
effect of a documentation correction.
