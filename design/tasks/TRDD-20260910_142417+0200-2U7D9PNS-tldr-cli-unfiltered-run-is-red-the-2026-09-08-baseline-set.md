---
trdd-id: 2U7D9PNS
title: tldr-cli unfiltered run is red — the 2026-09-08 baseline set
column: todo
created: 2026-09-10T14:24:17+0200
updated: 2026-09-10T19:09:41+0200
current-owner: session-claude
task-type: infra
scope: project
min-approval-requirement: none
labels: [test-failure, baseline, suite-health]
---

# tldr-cli unfiltered run is red — the 2026-09-08 baseline set

## Symptom

`cargo test -p tldr-cli` with no filter does not go green. It has not gone
green since at least 2026-09-08, and the reds are a stable, enumerated set —
not a moving target. Because the run is red by default, every new red has to be
diffed against this set by hand before anyone can tell whether their change
broke something, which is the actual cost and the reason this card exists.

## Scope

**One acceptance condition: `cargo test -p tldr-cli` (UNFILTERED) exits 0,
captured from cargo's own exit status, never a wrapper's.**

This card owns that condition and nothing else. It exists because
TRDD-DPL55YB3 carried it as an acceptance box it could never satisfy — that
card is about one JSON key, and a whole-crate green run depends on a dozen
unrelated mechanisms. Parking the ambition on a card that cannot deliver it is
how a card stalls forever; it lives here instead, where the dependencies can
be listed honestly.

## Depends on

`blocked-by:` is deliberately EMPTY and this section is prose, because a
non-empty `blocked-by:` would mandate `column: blocked`, and this card is not
blocked — it is a coordination card whose work is to drive the list below to
zero. Recording the dependencies as prose keeps it on the board and workable.

**Carded, with real ids:**

- **TRDD-YGYOAYBL** — `definition_command::test_definition_invalid_position`
  (`remaining_test`): binary exits 1 on an out-of-range line, test asserts
  success.
- **TRDD-3TCJKGWM** — the unit-1 chop regression
  (`chop_resolves_python_init_dunder`). **Do not touch that card from here** —
  it is owned and in flight.

**Uncarded baseline groups.** Names at
`reports/integration-failure-set/20260908_140723+0200-head-integration-failures.md`,
**lines 203-228** (26 tldr-cli names recorded at HEAD `1af53fb`):

| group | count | shape |
|---|---|---|
| flask-fixture-gated (`schema_cleanup_v1`, `schema_unification_v1`, and siblings) | 16 | panic `test fixture missing: /tmp/repos/flask (clone the flask repo before running)` — an unmet environmental precondition, not a code defect |
| `secure_sweep_tests` `path` key | 3 | `test_secure_json_structure`, `test_secure_single_file`, `test_secure_sub_results_structure` |
| help text | 2 | e.g. `m16_similar_help_lists_by_chunk_flag` |
| `line_number` missing | 1 | |
| `daemons=[]` | 1 | |

**Also in the way, in a different crate:** tldr-core's
`ruby_io_popen_with_user_input_via_compute_taint`. It is recorded as
**pre-existing per `reports/colony/classified-failures.txt`** (line 54) and was
**NOT re-measured at a pre-wave commit** — the pre-existing status is inherited
from that report, not established here, and must not be quoted as if it were.

## The trap this card must avoid

Sixteen of the reds are one missing fixture. Making them green by cloning flask
into `/tmp/repos/` on one machine turns a visible unmet precondition into an
invisible one: the suite goes green here and stays red for everyone else, with
no signal saying why. The `#[ignore]` route keeps the precondition legible in
the test list. Whichever is chosen, it must be chosen for a stated reason, and
a green run bought by a machine-local side effect is not a green run.

## Acceptance

- [ ] The 16 fixture-gated tests either carry `#[ignore]` with a reason naming
      the missing fixture, or the flask clone is provisioned by something the
      repo owns (a script, a CI step) rather than by hand on one machine. The
      choice and its reason are recorded here.
- [ ] Every other red above has its own card or a landed fix — none is left as
      a line in this table with nothing behind it.
- [ ] `cargo test -p tldr-cli` UNFILTERED exits 0, cargo's own status, and the
      run is repeated once to catch a load-sensitive pass.
- [ ] The count of reds is re-derived from a fresh run before this card is
      closed, not carried over from the 2026-09-08 report. The set is a
      snapshot and this card must not outlive its accuracy.

## Relationships

- TRDD-DPL55YB3 — where the whole-crate-green ambition came from; its box 4 was
  reworded to its own three files and points here.
- TRDD-YM857S4Y — wall-clock thresholds. The `l2_ir_cost_bench_05_taint`
  instance can redden an unfiltered run without any code being wrong.

## Notes

- Sibling red gate, pre-existing at a5bff82, outside any wave card: clippy -p
  tldr-core --lib --tests -D warnings fails at
  crates/tldr-core/tests/perf_abstract_interp_benchmark.rs:394
  (unnecessary_sort_by); fmt is TRDD-U5KJ5A8R.
