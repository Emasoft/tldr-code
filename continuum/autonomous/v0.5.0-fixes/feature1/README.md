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
| `selftest_parity.sh` | Proves the gate has teeth (PASS on unchanged; FAIL on an injected unique-name flip). |
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

| Rule | FAIL when | Meaning |
|------|-----------|---------|
| **(a)** | `flips_on_unique_name > 0` | A call-site whose baseline callee NAME was **unique** across the repo now resolves to a different definition file. Name-match was definitionally correct for a unique name → a flip there is a regression. |
| **(b)** | `new_low_or_unreviewed > 0` | `calls` exposes no confidence field, so every **net-new** edge at a previously-unresolved call-site (an ADDED `(caller, callee-name)` pair) is treated as REVIEW and FAILS unless allowlisted. |
| **(c)** | a **positive-control** cluster cell `regressed` | The constructor-typed receiver lost its per-type resolution. |

**Reported but never auto-failing:** `removed` edges and **non-unique flips**
(collapsing name-match broadcast is the entire point — those names have
cardinality > 1, so they never trip rule (a)). Cluster `still_buggy / improved /
fixed` are progress indicators, not gate failures (a stage need not target every
cell at once).

---

## The allowlist mechanism (`--allow`)

A stage *declares its intended changes* so its deliberate improvements don't trip
rules (a)/(b). The allow file is JSON:

```json
{ "allow": [
    { "repo": "csharp-newtonsoft-json", "type": "added",
      "src_file": "Src/.../JsonReader.cs", "src_func": "JsonReader.ReadAsString",
      "dst_func": "ReadInternal" },
    { "repo": "rust-clap", "type": "flipped",
      "src_file": "src/derive.rs", "src_func": "Parser.parse", "dst_func": "parse" }
] }
```

- `type` is `added` (exempts rule (b)) or `flipped` (exempts rule (a)).
- `repo: "*"` matches any repo.
- An exempted delta is still counted in the reported totals; it just no longer
  contributes to a FAIL. The gate prints the exact offending call-sites
  (`OFFENDERS[...]`) so a stage can copy them into its allow file after review.

---

## Proving the gate has teeth

```bash
bash continuum/autonomous/v0.5.0-fixes/feature1/selftest_parity.sh
```

- **(i)** current-binary-vs-its-own-baseline → `PARITY: PASS`, exit 0.
- **(ii)** a synthetic flip is injected into a copy of the baseline (one edge whose
  callee name is unique is re-pointed to another existing file) → `PARITY: FAIL`
  with `flips_on_unique_name >= 1`, exit non-zero.

Both must hold; a gate that cannot fail is worthless.
```
