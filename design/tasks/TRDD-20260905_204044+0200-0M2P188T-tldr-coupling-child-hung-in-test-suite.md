---
trdd-id: 0M2P188T
title: tldr coupling child hung 30 CPU-minutes once inside the test suite
column: planned
created: 2026-09-05T20:40:44+0200
updated: 2026-09-06T03:33:08+0200
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
  weight, and that part had real sample counts beside it.
- **CORRECTION — the top frame above is WRONG. `build_project_call_graph_v2` is NOT on this
  command's path.** It is called from `patterns/temporal.rs` and `commands/calls.rs`;
  `coupling.rs` uses its own `find_cross_calls` (coupling.rs:1409, invoked at 1920-1921). The
  bad symbol reached the diagram through a bad method: per-symbol counts taken with `uniq -c`
  over mangled names in the text dump, which measures call-graph BREADTH and sweeps in other
  threads' frames, not time. Only the deep-frame excerpt was weighted. Re-profile and read the
  per-thread breakdown before trusting any ordering here.
- **RETRACTED: "the read-set is just those two files" and the 18-line argument built on it.**
  An earlier revision of this card asserted both, from reading only `coupling.rs::run`'s first
  40 lines. The full path was then traced and it is not what that claimed. `coupling.rs:1973`
  calls `analyze_coupling(&args.path_a, ...)` in `tldr_core::quality::coupling` (imported as
  `core_analyze_coupling`), and that function does:

  ```
  analyze_coupling(path, ..)                       quality/coupling.rs:441
    -> detect_dominant_language(path)
    -> build_project_call_graph(path, lang, None, true)   callgraph/builder.rs:29
         config.use_type_resolution = true                builder.rs:40
         WorkspaceConfig::discover(root)                  builder.rs:50
    -> analyze_coupling_with_graph(path, ..)
  ```

  So the command DOES walk the filesystem (workspace-marker discovery) and DOES enable type
  resolution. The two `read_file_safe` calls are only the pair-comparison half; the call-graph
  half takes a ROOT.
- ## ✅ ROOT CAUSE LOCALIZED — this bullet supersedes every earlier account on this card
  The profile was right from the beginning. My CODE SEARCHES were wrong, for one mundane
  reason: I grepped `coupling.rs` for `callgraph` and got ZERO hits, then built four
  conclusions on that zero. The function is `augment_with_project_call_graph` — `call_graph`
  WITH AN UNDERSCORE. The pattern could not match it.

  The real path, from the sample's own weights (3366 of 3366 samples, main thread):

  ```
  tldr::main                                          main.rs:460
   -> tldr::run_command                               main.rs:698
    -> patterns::coupling::run
     -> patterns::coupling::run_pair_mode             <- PAIR mode, as established
      -> patterns::coupling::augment_with_project_call_graph   coupling.rs:1487, CALLED AT 1936
       -> callgraph::builder::build_project_call_graph
        -> callgraph::builder_v2::build_project_call_graph_v2        3327
         -> extract_and_resolve_calls                                3327
          -> resolve_call_site_for_builder                           3327
           -> resolve_method_or_attr_call                            3326
            -> BuilderResolutionContext::resolve                     3326
             -> resolution::resolve_call_with_receiver          1451 + 1389
              -> resolution::resolve_global_fuzzy_match         1109  -> Vec::spec_from_iter
              -> resolution::resolve_local_fuzzy_match          1389  -> Vec::spec_from_iter
  ```

  Consequences, each replacing an earlier claim on this card:
  - `build_project_call_graph_v2` IS on the pair-mode path. Retracted, un-retracted, then
    re-retracted across four commits; the UN-retraction was the correct one.
  - The read-set is NOT the two files. `augment_with_project_call_graph` builds a project call
    graph, so the earlier "18 lines is the whole input" argument does not hold. Terminating vs
    non-terminating remains open on the evidence here.
  - Time is spent in FUZZY-MATCH RESOLUTION, and its leaves are `Vec::spec_from_iter` — i.e.
    each resolution attempt COLLECTS INTO A FRESH VEC. That is the allocation site, and it
    explains the steadily growing RSS directly rather than by inference.
  - The `find_var_in_line` frames I once called the hot path were 7 and 3 samples out of 3366,
    under 0.2 % — a negligible branch I mistook for the peak because my symbol grep matched
    `tldr_core` names and structurally EXCLUDED `tldr_cli`'s own frames, where the real chain
    starts.
  - **The timeout gap is now exact:** the last check is line 1912 and the expensive call is
    line 1936, so `augment_with_project_call_graph` runs entirely unguarded.
- NEXT ACTION: read `resolve_global_fuzzy_match` and `resolve_local_fuzzy_match` in
  `core/src/callgraph/resolution.rs`, looking at what they collect per call site and how many
  times the builder retries them. Two candidate shapes, both fitting the weights above: a
  per-call-site full-index scan that is quadratic in (call sites x functions), or a retry that
  never converges. The Vec allocation per attempt is the handle either way.
- Superseded detail, kept only so the earlier commits are readable — the pair-mode surface
  below is accurate as far as it goes, but INCOMPLETE: it omits the 1936 call above, which is
  exactly the omission that produced the wrong conclusions.

  ```
  run_pair_mode              coupling.rs:1844-1968
    1872-73  read_file_safe(path_a), read_file_safe(path_b)   <- the ONLY file reads
    1907-08  extract_module_info(..)   local, coupling.rs:359
    1912     timeout check             <- the LAST one
    1920-21  find_cross_calls(..)      local, coupling.rs:1409
    1965     output_pair_report -> return
  ```

  `core_analyze_coupling` — the entry that reaches `build_project_call_graph` and thence
  `build_project_call_graph_v2` — is at line 1973, inside `run_project_mode`, a DIFFERENT
  function that pair mode never enters. So:
  - the READ-SET IS the two files, now checked across the whole of `run_pair_mode` rather than
    its first 40 lines, and `coupling.rs` has no `read_dir` / `WalkDir` / other `File::open`;
  - `build_project_call_graph_v2` IS NOT on the hung path. The original retraction was right;
    the un-retraction that followed it was wrong, made by tracing a chain without checking
    that its first hop executes in this mode.
- **CONSEQUENCE — a genuine, narrow contradiction. Do not paper over it.**
  Two things are separately true and they do not fit:
  1. The weighted frames ARE the main thread's. They were read from the sample's lines 24-538,
     where line 24 is `Thread_… com.apple.main-thread` and the next thread header is 539. So
     the main thread really was inside `callgraph::type_resolver::find_var_in_line`.
  2. Pair mode's traced path cannot reach it. `coupling.rs` has ZERO occurrences of `callgraph`
     or `type_resolver`; `extract_module_info` (359) and `find_cross_calls` (1409) are both
     local and their bodies call no `tldr_core` entry point; and pair mode uses none of
     `core_analyze_coupling` / `compute_martin_metrics_from_deps` / `analyze_dependencies`.

  So the gap is in a helper NOT yet traced, not in the profile. `coupling.rs` does use
  `tldr_core::quality::coupling` 18 times and `tldr_core::analysis::deps` 8 times somewhere in
  the file, and `quality/coupling.rs:43` imports `crate::callgraph::build_project_call_graph` —
  so a reachable route plausibly exists through a helper called below `extract_module_info`.
  That is the thread to pull, and it is a SMALL search now that pair mode's own two functions
  are excluded.
- **STANDING INSTRUCTION for the next occurrence — this one can no longer be answered.**
  118 % CPU means two or more threads burned CPU; only one (the main thread) was ever
  accounted for. `ps -M <pid>` would have named the second, and the process is now killed, so
  for THIS occurrence it is permanently unanswerable. Next time, before anything else:
  `ps -M <pid>` first, then `/usr/bin/sample`, then read code. Do not write a causal story
  before the busy thread is named.
- Because of that, the earlier `build_project_call_graph_v2 -> resolve_* -> find_var_in_line`
  diagram has been REMOVED rather than annotated. It was produced by an unsound method
  (`uniq -c` over mangled symbols) and then defended twice; leaving it visible with a caveat
  invited exactly the re-derivation it caused.
- **DISPROVED, recorded so nobody re-runs it:** discovery does not ascend into `/tmp`.
  `WorkspaceConfig::discover` (`core/src/types.rs:1799`) probes workspace markers AT the given
  path only, with no `parent()` walk, returning `None` when none match. (This mattered only
  under the project-mode reading, which no longer applies — kept because the walk-up idea is
  the obvious next guess and it is wrong.)
- Consequence for the earlier reasoning: "no terminating super-linear algorithm reaches 15
  CPU-minutes on 18 lines" was sound ONLY under the read-set claim that has now been retracted.
  If the real input is `/tmp`, an expensive-but-terminating walk explains everything and there
  may be no loop bug at all. Both processes were killed (at 13 and 45 minutes) and neither was
  observed terminating, so nothing here settles terminating vs not.
- **SEPARATE DEFECT FOUND WHILE CHECKING THIS — `coupling`'s `--timeout` cannot fire during
  the analysis.** `coupling.rs` checks `start.elapsed() > timeout` exactly three times, at lines
  1864, 1876 and 1912 — after path validation, after the file read, and once more — and
  `find_cross_calls` runs at 1920-1921 with NO further check. Verified by scanning every line
  after 1912 for another check: there is none. So the timeout bounds only setup, and the phase
  that actually hangs is unbounded by construction. That is why a child with a timeout argument
  ran 13 minutes. This is worth fixing REGARDLESS of the hang's root cause, because it is what
  turns a slow analysis into an unkillable one, and it is a much smaller change than the loop.
  It deserves its own card when someone picks this up.
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
