# Reproducer input for TRDD-0M2P188T

These two files are the ACTUAL input that made `tldr coupling` spin for 15 CPU-minutes and
allocate 576 MB on 2026-09-06. They were recovered from the live test's temp directories before
`/tmp` reclaimed them, so this is the triggering input itself, not a reconstruction.

The test that generates them is
`coupling_path_preserves_user_supplied` in `crates/tldr-cli/tests/path_and_schema_cleanup_v3.rs`.
It writes the two files into TWO SEPARATE temp directories and passes both paths.

## The command

```sh
tldr coupling <path>/pkg_a/mod.py <path>/pkg_b/client.py --format json -q
```

That is the child's argv as captured from the process table, with the temp paths replaced.

## Why the size matters

Eighteen lines total. A class with three methods, and a caller. No legitimate super-linear
algorithm spends 15 CPU-minutes or half a gigabyte here, which is what rules out "expensive but
terminating work on pathological input" and leaves a non-terminating loop.

## Hypothesis, NOT established

`client.py` opens with `from .mod import Service` — a RELATIVE import — while `mod.py` lives in
a DIFFERENT directory, so the relative import can never resolve to it. The profile's hot path
is the fuzzy-match resolution retry (`resolve_local_fuzzy_match`, `find_by_name`,
`find_var_in_line`), which is what an unresolvable receiver type would drive.

That fits, and it is exactly the kind of fit that has been wrong before on this card's sibling
work: a story consistent with the evidence is not the same as a story established by it.
Confirm by editing the import and re-running before believing it.

## Reproduction is NOT guaranteed

The hang is intermittent — this test passes in most runs, and standalone runs of the binary on
comparable input finish in about 1.2 s. Having the exact input does not make the hang
deterministic; the trigger remains unknown. If it completes quickly, that does NOT clear the
defect.

## What to measure, if it does hang

CPU TIME, not wall clock. `ps -o pid,etime,time,rss,%cpu -p <pid>`. A binary merely stalled by
the OS on first exec burns ~0 % CPU; this defect burns a full core and grows RSS steadily.
Profile with `/usr/bin/sample <pid> 5 -file out.txt` — use the absolute path, since `sample` on
PATH may resolve to an unrelated Python shim.
