---
trdd-id: 0M2P188T
title: tldr coupling child hung 30 CPU-minutes once inside the test suite
column: planned
created: 2026-09-05T20:40:44+0200
updated: 2026-09-06T03:20:52+0200
current-owner: codebase-scan-2026-09-05
task-type: bugfix
min-approval-requirement: user
labels: [scan-2026-09-05, hang]
---

# tldr coupling child hung 30 CPU-minutes once inside the test suite

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-09-06

- **IT RECURRED, and this time it was caught live and profiled.** On 2026-09-06, during
  `cargo test -p tldr-cli --no-fail-fast -j 2 -- --test-threads=2`.
- MEASURED on the live child (pid 26887,
  `tldr coupling <tmp>/mod.py <tmp>/client.py --format json -q`):

  | quantity | value |
  |---|---|
  | elapsed | 13 min 17 s, still running when killed |
  | CPU time | **15 min 42 s** |
  | CPU usage | 99.4-100 %, sustained |
  | RSS | 528 MB to 576 MB, climbing ~165 KB/s |

  It burns CPU continuously and ALLOCATES continuously. Same phenomenon as the body's original
  in kind (sustained CPU-minutes, not a slow test).
- **Thread attribution is UNRESOLVED, and the two numbers above disagree.** 15 min 42 s of CPU
  in 13 min 17 s elapsed is 118 %, which needs at least two threads burning — yet `ps` reported
  99-100 % and the 5-second profile showed the rayon workers parked in `registry::main_loop`.
  Both can be true if the early phase was parallel and it converged to one hot thread before
  sampling, but that is NOT established. Do NOT repeat the body's "on one core" as if it were
  measured here. `ps -M <pid>` gives per-thread CPU and settles it in one command; it was not
  run while the process was alive, which is the main thing to do differently next time.
- **A 60-second warning is NOT the signature — do not use it as one.** The same run printed
  libtest's 60 s warning for `verify_command::test_verify_default_current_dir`, and that test
  COMPLETED OK on the very next line. Both tests spawn the freshly built CLI, and a fresh
  binary stalls on first exec on this machine, so a 60 s warning alone is fully explained
  without any defect. What distinguishes the real thing is CPU TIME ACCUMULATING: a stalled
  binary burns ~0 % CPU; this one burned 15 CPU-minutes. Check CPU, not the wall clock.
- **Hot path, from `/usr/bin/sample` on the live process** (note: `sample` on PATH may resolve
  to an unrelated Python shim — use the absolute path):

  ```
  callgraph::builder_v2::build_project_call_graph_v2
    -> callgraph::resolution::resolve_call_with_receiver
      -> callgraph::resolution::resolve_local_fuzzy_match      (heaviest)
      -> callgraph::resolution::resolve_type_aware_fallback
        -> callgraph::type_resolver::find_var_in_line          (str::match_indices)
        -> callgraph::type_resolver::find_type_annotation
        -> callgraph::type_resolver::resolve_python_receiver_type
  ```

  `str::match_indices` / `TwoWaySearcher` inside `find_var_in_line` carries the deep-frame
  weight, reached from fuzzy-match resolution of a Python receiver type; `FuncIndex::find_by_name`
  and `::iter` recur throughout. CAVEAT on how that list was produced: the per-symbol counts
  were occurrences of mangled names in the text dump, counted with `uniq -c`, which tracks call-
  graph BREADTH, not time. Only the deep-frame excerpt carried real sample weights. Treat the
  ordering as a lead and re-profile rather than trusting the ranking.
- **THE INPUT IS 18 LINES**, preserved at `design/reproducers/TRDD-0M2P188T/` — a 10-line class
  with three methods, and an 8-line caller. This is the fact that rules out the benign reading:
  fuzzy matching is plausibly O(calls x funcs x line-length), but on four functions and a
  handful of calls that is microseconds, not 15 CPU-minutes and 576 MB. No terminating
  super-linear algorithm reaches these numbers on this input.
- Honest limit on that: the process was KILLED at 13 minutes, and the body's occurrence was
  killed at 45. Neither was ever observed terminating on its own, so "non-terminating" is
  inferred from the input-size argument above, not from having waited it out.
- NEXT ACTION, two hypotheses, not one:
  1. **Non-terminating loop** — read `resolve_local_fuzzy_match` and `resolve_type_aware_fallback`
     for a loop whose termination depends on resolution succeeding. The steadily growing RSS is
     a second handle on it.
  2. **Unbounded growth on an unresolvable import** — `client.py` opens
     `from .mod import Service`, a RELATIVE import, while `mod.py` is in a DIFFERENT directory,
     so it can never resolve. That is a specific candidate trigger fitting the same hot path.
     Test it by making the import resolvable and re-running. Marked hypothesis, not finding.
- Killed with `kill 26887` at 03:16:46 to unblock the gate — the same action the body records
  for occurrence 1. The run resumed immediately and the test failed at
  `crates/tldr-cli/tests/path_and_schema_cleanup_v3.rs:60`, matching the body's account.
- Still NOT established: why it triggers only sometimes. Standalone runs finish in ~1.2 s (see
  the body) and this test passes in other runs. The trigger is unknown; the loop is located.

## Why
During the second full `cargo test --workspace` run of the scan landing (2026-09-05, parent
7f50527 plus the scan edits), the test
`path_and_schema_cleanup_v3::coupling_path_preserves_user_supplied`
(`crates/tldr-cli/tests/path_and_schema_cleanup_v3.rs`) never returned. Its child process,
`tldr coupling <tempdir>` with no `--format` flag (so the JSON path), spun from about 19:50 for
more than 45 minutes of wall time and over 30 CPU-minutes on one core. The temp dir still held
the python package fixture the test expects. Only the child was killed (`kill <pid>` at
20:37:28); the test then failed with the usual assert_cmd "Unexpected failure" and the run went
on. A hang inside a shipped command is a live defect even if it happened once, so it gets its
own card instead of a line in the pre-existing-failures list, where it does not belong: it was
never observed at the parent commit.

## What is known
- Not reproducible standalone. The parent-commit binary and the edited binary both finish
  `tldr coupling` on a comparable two-file python fixture in under 1.2 s for `json`, `text`
  and `compact`, with byte-identical output, from the repo root and from a temp cwd.
- The scan's hunks in `crates/tldr-core/src/quality/coupling.rs` add no loop (6 insertions,
  19 deletions, dead-code removal); the `text` formatting hunk is on a path the hung child
  never took. No scan hunk is implicated, but the cause is unknown.
- The sibling tests of that binary run in parallel threads, each with its own temp dir; only
  one child hung.

## What to do
1. Run the binary alone in a loop, 20 iterations each with `--test-threads=1` and with the
   default thread count, and record whether the hang recurs.
2. If it recurs, sample the child while it spins (`/usr/bin/sample <pid> 5` on macOS; the bare
   `sample` name can be shadowed by a Python shim) and attach the stack to this card.
3. Read coupling's directory walk and import resolution for an input that can loop or explode:
   a symlink cycle under the temp dir, or a cwd-relative path that resolves to the repo root
   and walks the whole workspace including `target/`.
4. Give the test's command a wall-clock bound (assert_cmd `.timeout(...)`) so a recurrence
   fails instead of stalling the whole suite.

## Acceptance
- [ ] cause identified with file:line, or 20 clean iterations per thread setting recorded here
- [ ] the test carries a timeout

## Approval log

- 2026-09-05T21:33:13+0200 — APPROVED by the session Claude under the user's 2026-09-05 directive to decide from verified facts and implement what is good. Work is authorized; no push.
