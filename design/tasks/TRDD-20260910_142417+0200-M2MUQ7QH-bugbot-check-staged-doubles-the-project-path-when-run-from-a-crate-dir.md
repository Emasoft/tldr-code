---
trdd-id: M2MUQ7QH
title: bugbot check --staged doubles the project path when run from a crate dir
column: todo
created: 2026-09-10T14:24:17+0200
updated: 2026-09-10T14:24:17+0200
current-owner: session-claude
task-type: bugfix
scope: project
min-approval-requirement: none
labels: [cli, paths, bugbot]
---

# bugbot check --staged doubles the project path when run from a crate dir

## Symptom — OBSERVED OUTPUT ONLY

Run `tldr bugbot check --staged .` with the working directory set to
`crates/tldr-cli` (which is what `cargo test` does for that crate's tests), and
the emitted `changed_files` entries contain the crate path **twice**.

From `bugbot-and-binaries.txt`, 2026-09-10, verbatim:

```json
{
  "tool": "bugbot",
  "mode": "check",
  "language": "rust",
  "base_ref": "HEAD",
  "detection_method": "git:staged",
  "changed_files": [
    "/Users/…/tldr-code/crates/tldr-cli/crates/tldr-cli/tests/bench_quality_multilang.rs",
    "/Users/…/tldr-code/crates/tldr-cli/crates/tldr-cli/tests/bench_remaining_multilang.rs"
  ],
```

`crates/tldr-cli/crates/tldr-cli/tests/…` — the segment appears twice, and no
such path exists on disk. cwd was `crates/tldr-cli`, `project` was `.`.

**This is recorded as observed output, not as a diagnosed join bug.** The
obvious reading is that a repo-relative path from `git diff --name-only
--staged` is being joined onto a project root that is already the crate dir —
`crates/tldr-cli/src/commands/bugbot/changes.rs:67` and `:74` are where those
git invocations live and are the place to start reading. But that is a
hypothesis from the shape of the string, and the card does not assert it: the
implementer reads the join site and establishes what actually happens.

## Second, separate finding — record it, do not conflate it

`bugbot_tests::bugbot_check_staged_flag_changes_detection_method`
(`crates/tldr-cli/tests/bugbot_tests.rs:103`) **assumes a clean index.** It
asserts `should exit 0`, but `tldr bugbot check --staged` exits **1 on any
finding**, over whatever happens to be staged in the developer's own index at
the moment the test runs. In the 2026-09-10 gate it failed with `should exit 0`
because two staged bench-file renames produced a legitimate `call-graph-change`
finding (`200 new edges, 200 removed edges`), and `bugbot_exit=1` followed
correctly.

So the test is **environmental**: it passes or fails according to the state of
the machine's git index, not according to the code. It cleared once those
renames were committed. That is a test-design defect independent of the path
doubling — the two merely surfaced in the same run — and fixing one does not
fix the other. The test needs its own controlled repo/index (a tempdir git
repo it stages itself) rather than the ambient one.

## Acceptance

- [ ] The path doubling is reproduced deliberately (a documented command +
      cwd) and its actual mechanism read from the source, replacing the
      hypothesis above with a verified statement.
- [ ] `changed_files` entries name paths that exist on disk, from any cwd. A
      test pins this from a NON-root cwd specifically, since from the repo root
      the bug is invisible.
- [ ] `bugbot_check_staged_flag_changes_detection_method` no longer depends on
      the ambient git index — it builds and stages its own fixture repo, or it
      asserts on the detection method rather than on an exit code that
      legitimately varies.
- [ ] Red-proofed: both new assertions are observed FAILING against today's
      code before being accepted as passing.

## Notes
