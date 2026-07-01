# FEATURE-1 d.0 — Differential Parity Harness

**The never-worse-than-name-match safety gate for the `tldr` call graph.**

This is the FOUNDATION that gates every later FEATURE-1 stage. It captures the
*current* name-match call-graph behavior as an immutable baseline, then lets any
later resolution change be checked against it: a change may only *improve*
resolution (collapse name-match broadcast, remove phantom edges) and must **never
make a definitionally-correct edge worse**.

The harness touches **no analysis source** — nothing under `crates/*/src/`. It is
pure test tooling that shells out to the `tldr` binary and diffs JSON.

---

## Files

| File | Role |
|------|------|
| `parity_lib.py` | Core: `calls` edge normalization, the determinism protocol (run N×, keep the stable intersection), the never-worse diff, and cluster-golden evaluation. Importable + has a CLI (`capture` / `cluster-baseline` / `summarize`). |
| `capture_baseline.sh` | Captures the baseline from the **reference** binary over all 38 corpus repos + the cluster cells. |
| `check_parity.py` | The gate. Re-runs `calls` on the **current** binary, diffs vs baseline, evaluates cluster goldens, prints machine-readable counts + `PARITY: PASS/FAIL`, exits non-zero on FAIL. |
| `cluster_goldens.json` | The FEATURE-1 cluster cells: repro command, buggy-now signature, expected-fixed target. Progress reporting per stage. |
| `baseline_summary.json` | **Committed** compact baseline: per-repo edge count + sha digest + capture provenance. The big per-repo edge sets live out-of-repo. |
| `expected_deltas.json` | **Committed** owner-pinned allowlist for the fixed d.1 binary (718 added + 603 removed, `dst_file` on every entry; `removed_audit` documents the removed-edge review). |
| `selftest_parity.sh` | Runs the per-rule teeth self-test (thin wrapper over `selftest_cases.py`). |
| `selftest_cases.py` | The self-test driver: injects ONE synthetic defect per case and asserts the gate reacts (12 cases; see below). |
| `fixtures/posctl/animals.py` | Positive control: a constructor-typed receiver that must stay correctly per-type resolved. |

**Out-of-repo (durable, NOT committed):**
`/Users/cosimo/.tldr-audit/feature1-baseline/`
- `<repo>.calls.json` — full normalized stable edge set per repo (+ unstable edges logged).
- `cluster/<cell>.json` — raw cluster repro output at baseline.
- `cluster_baseline_status.json` — baseline cluster statuses (all `still_buggy` / control `correct`).

---

## The real `tldr calls --format json` schema (introspected, not assumed)

```
edges: [ { src_file, src_func, dst_file, dst_func, call_type } ]   # call_type ∈ intra|direct|method|attr|ref
```

There is **no per-edge line number** and **no confidence / resolution-kind** field
beyond `call_type`. Consequences baked into the harness:

- **Edge identity** = `(src_file, src_func, dst_file, dst_func)`, paths normalized
  relative to the repo root. `call_type` is recorded but kept *out* of the identity
  (a resolution improvement may reclassify `method`↔`attr` without being a regression).
- **Call-site proxy key** = `(src_file, src_func, dst_func)` — "caller invokes a
  callee named N". Its value is the set of `dst_file` definitions N binds to. A
  **flip** = same call-site key, different resolved `dst_file` set. This is the
  faithful stand-in for `(caller, file, line) → callee` given no line numbers.

---

## How to (re)capture the baseline

```bash
bash continuum/autonomous/v0.5.0-fixes/feature1/capture_baseline.sh
```

For each of the 38 repos it runs `tldr calls` **3×** and keeps the **stable
intersection** of the normalized edge set (jitter-proof). A repo whose edge set
differs across runs beyond `UNSTABLE_EXCLUDE_FRAC` (2%) is **excluded** from the
gate and logged (`excluded: true`, with the unstable count) so nondeterminism can
never cause a false regression. Whole-repo runs that time out fall back to a
representative source subdir; the actual `captured_path` is recorded.

Overridable via env: `TLDR_BIN`, `TLDR_CORPORA`, `TLDR_BASELINE_DIR`,
`TLDR_RUNS`, `TLDR_TIMEOUT`.

---

## How to run the gate after a stage build

After installing a new `tldr` binary for a stage, run:

```bash
python3 continuum/autonomous/v0.5.0-fixes/feature1/check_parity.py \
  --binary /Users/cosimo/.cargo/bin/tldr \
  --baseline-dir /Users/cosimo/.tldr-audit/feature1-baseline \
  --root /Users/cosimo/.tldr-audit/corpora \
  --summary continuum/autonomous/v0.5.0-fixes/feature1/baseline_summary.json \
  --allow continuum/autonomous/v0.5.0-fixes/feature1/<stage>_expected.json   # optional
```

It prints, machine-readably:

```
COUNTS  {"repos":N,"baseline_edges":..,"removed":..,"added":..,"flipped":..,
         "flips_on_unique_name":..,"new_low_or_unreviewed":..,
         "cluster_fixed":..,"cluster_still_buggy":..}
CLUSTER {"fixed":..,"improved":..,"still_buggy":..,"correct":..,"regressed":..}
...
PARITY: PASS|FAIL
```

Exit code is `0` on PASS, non-zero on FAIL.

---

## FAIL conditions ("never worse" rules)

Every diff CHANNEL is gated. A delta passes only if it carries an explicit,
**owner-pinned** allowlist entry (see below); otherwise the gate FAILS.

| Rule | FAIL when | Meaning |
|------|-----------|---------|
| **(a)** | `flipped_unreviewed > 0` | A call-site present in BOTH baseline and current resolves to a DIFFERENT owner-file set and is not allowlisted for that new owner — **unique OR non-unique** name (d.2–d.4 re-point ambiguous calls, so non-unique flips are no longer waved through). `flips_on_unique_name` is the louder sub-signal: a flip on a UNIQUE baseline name was definitionally correct, so it is a regression. |
| **(b)** | `new_low_or_unreviewed > 0` | `calls` exposes no confidence field, so every **net-new** edge at a previously-unresolved call-site (an ADDED `(caller, callee-name)` pair) is REVIEW and FAILS unless allowlisted for its resolved owner. |
| **(c)** | a **positive-control** cluster cell `regressed` | The constructor-typed receiver lost its per-type resolution. |
| **(d)** | `removed_unreviewed > 0` | d.2 REMOVES edges (declining bad fuzzy matches). Every **removed** call-site FAILS unless allowlisted — an un-reviewed removal could be a genuine loss of a correct edge, not a broadcast-collapse byproduct. |
| **hard-error** | baseline / binary failure | An **unexpected missing baseline** (a non-excluded repo with no `.calls.json`), a current-binary run that is **not `ok`** (crash/timeout/empty output), or a well-formed-but-**empty** edge set against a non-empty baseline. These previously appended to `errors` and vacuously PASSED; they now FAIL. |

**Legitimately skipped (NOT a failure):** a repo declared in
`baseline_summary.json` `repos_excluded` (nondeterministic, e.g.
`php-symfony-console`) is skipped cleanly — the ONLY path that omits a repo
without failing. Cluster `still_buggy / improved / fixed` are progress
indicators, not gate failures (a stage need not target every cell at once).

---

## The allowlist mechanism (`--allow`)

A stage *declares its intended changes* so its deliberate improvements don't trip
rules (a)/(b)/(d). The allow file is JSON, and every entry is **owner-pinned**:

```json
{ "allow": [
    { "repo": "rust-clap", "type": "added",
      "src_file": "clap_builder/src/builder/arg.rs", "src_func": "Arg.cmp",
      "dst_func": "Arg.get_id",
      "dst_file": ["clap_builder/src/builder/arg.rs"] },
    { "repo": "rust-clap", "type": "removed",
      "src_file": "clap_builder/src/builder/arg.rs", "src_func": "Arg.render_arg_val",
      "dst_func": "Clone.clone",
      "dst_file": ["clap_builder/src/builder/value_parser.rs"] }
] }
```

- `type` is `added` (exempts rule (b)), `removed` (exempts rule (d)), or
  `flipped` (exempts rule (a)).
- **`dst_file` is REQUIRED** — the resolved callee OWNER file(s) (a string or a
  list). It is part of the allow KEY: an allowlisted call-site can NOT silently
  absorb a future owner-flip to a DIFFERENT file. Mutating the resolution to a
  new owner re-trips the gate even though caller/callee names are unchanged.
- `repo: "*"` matches any repo. (Both the concrete-repo and `*` keys are checked
  at match time — previously a `*` entry was stored but never reachable.)
- An exempted delta is still counted in the reported totals; it just no longer
  contributes to a FAIL. The gate prints the exact offending call-sites
  (`OFFENDERS[...]` / `HARD_ERROR[...]`) so a stage can copy them into its allow
  file after review. `expected_deltas.json` is the committed allowlist for the
  fixed d.1 binary (718 added + 603 removed, regenerated from a gate run; see its
  `removed_audit` field for the removed-edge review).

---

## Proving the gate has teeth

```bash
bash continuum/autonomous/v0.5.0-fixes/feature1/selftest_parity.sh
```

The driver (`selftest_cases.py`) injects exactly ONE synthetic defect per case
and asserts the gate reacts. Every rule — not just the gate as a whole — must be
able to fail:

| Case | Injection | Expect |
|------|-----------|--------|
| `clean` | 0-delta current-vs-own-baseline | PASS |
| `a_unique_flip` | re-point a UNIQUE-name edge | FAIL (rule a, `flips_on_unique_name≥1`) |
| `b_added_unreviewed` | delete a call-site from baseline → ADDED | FAIL (rule b) |
| `c_posctl_regressed` | force the positive control to `regressed` | FAIL (rule c) |
| `d_nonunique_flip` | flip a NON-unique-name call-site | FAIL (rule a, `flips_on_unique_name==0`) |
| `e_removed_unreviewed` | add a baseline-only phantom → REMOVED | FAIL (rule d) |
| `f_empty_output` | binary shim prints nothing (status≠ok) | FAIL (hard-error) |
| `f_crash_exit` | binary shim exits 1 | FAIL (hard-error) |
| `g_missing_baseline` | no baseline for a non-excluded repo | FAIL (hard-error) |
| `g_excluded_skip` | intentionally-excluded repo, no baseline | PASS (clean skip) |
| `h_owner_flip_allowlisted` | allowlisted call-site, `dst_file` mutated | FAIL (owner-pinned key) |
| `h_ok_owner_pinned` | allowlist entry with the CORRECT `dst_file` | PASS (absorbed) |

A gate that cannot fail is worthless; a gate whose *individual rules* cannot fail
is worthless per-rule.
```
