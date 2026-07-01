#!/usr/bin/env python3
"""FEATURE-1 parity gate -- negative self-tests (prove EVERY rule has teeth).

Each case injects exactly ONE synthetic defect and asserts the gate FAILS
(exit != 0) for the RIGHT reason; the clean case and the two positive cases
(intentional-exclusion skip, correctly-pinned allowlist) must PASS (exit 0).

A gate that cannot fail is worthless; a gate whose *individual rules* cannot
fail is worthless per-rule. This driver exercises all of them:

  clean       0-delta current-vs-own-baseline                       -> PASS
  a  unique-name flip                                               -> FAIL
  b  un-allowlisted ADDED edge                                      -> FAIL
  c  positive-control regression                                    -> FAIL
  d  NON-unique-name flip                                           -> FAIL
  e  un-allowlisted REMOVED edge                                    -> FAIL
  f  binary EMPTY calls output (status != ok)                      -> FAIL
  f_crash  binary CRASH (exit != 0)                                 -> FAIL
  g  UNEXPECTED missing baseline (non-excluded repo)                -> FAIL
  g_excluded  intentionally-excluded repo skipped cleanly           -> PASS
  h  owner-flip at an ALLOWLISTED call-site (dst_file mutated)      -> FAIL
  h_ok  correctly owner-pinned allowlist entry accepted             -> PASS
"""
import json, os, subprocess, sys, tempfile, shutil, collections, stat

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import parity_lib as pl  # noqa: E402

BIN = os.environ.get("TLDR_BIN", "/Users/cosimo/.cargo/bin/tldr")
CORPORA = os.environ.get("TLDR_CORPORA", "/Users/cosimo/.tldr-audit/corpora")
SUMMARY = os.path.join(HERE, "baseline_summary.json")
REPO = os.environ.get("TLDR_SELFTEST_REPO", "c-sds")
EXCLUDED_REPO = "php-symfony-console"   # declared in baseline_summary repos_excluded
RUNS = 1                                # REPO is deterministic (unstable_frac 0.0)
TIMEOUT = 90

WORK = tempfile.mkdtemp(prefix="feature1_selftest.")


def _capture_current():
    res = pl.stable_calls(BIN, os.path.join(CORPORA, REPO), CORPORA, RUNS, TIMEOUT)
    if res["status"] != "ok" or not res["stable"]:
        sys.stderr.write("FATAL: could not capture current edges for %s (%s)\n"
                         % (REPO, res["status"]))
        sys.exit(3)
    return [list(e) for e in res["stable"]]


def _write_baseline(stable, unstable=None, repo=REPO):
    d = tempfile.mkdtemp(prefix="bl.", dir=WORK)
    doc = {"stable": stable, "unstable": unstable or [],
           "captured_path": os.path.join(CORPORA, repo)}
    json.dump(doc, open(os.path.join(d, repo + ".calls.json"), "w"))
    return d


def _write_allow(entries):
    p = os.path.join(WORK, "allow_%d.json" % len(os.listdir(WORK)))
    json.dump({"allow": entries}, open(p, "w"))
    return p


def _shim(exit_code, emit=""):
    p = os.path.join(WORK, "shim_%d.sh" % (len(os.listdir(WORK))))
    with open(p, "w") as fh:
        fh.write("#!/bin/sh\n")
        if emit:
            fh.write("printf '%s'\n" % emit)
        fh.write("exit %d\n" % exit_code)
    os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return p


def run_gate(baseline_dir, allow=None, repos=REPO, binary=BIN,
             goldens=None, no_cluster=True):
    out = os.path.join(WORK, "verdict_%d.json" % len(os.listdir(WORK)))
    cmd = [sys.executable, os.path.join(HERE, "check_parity.py"),
           "--binary", binary, "--baseline-dir", baseline_dir,
           "--root", CORPORA, "--summary", SUMMARY, "--repos", repos,
           "--runs", str(RUNS), "--timeout", str(TIMEOUT),
           "--json-out", out, "--quiet"]
    if allow:
        cmd += ["--allow", allow]
    if no_cluster:
        cmd.append("--no-cluster")
    if goldens:
        cmd += ["--goldens", goldens]
    env = dict(os.environ)
    env["TLDR_NO_DAEMON"] = "1"
    p = subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    verdict = json.load(open(out)) if os.path.exists(out) else {}
    return p.returncode, verdict


# --------------------------------------------------------------------------- #
CUR = _capture_current()
# name cardinality over the current edge set (== the clean baseline)
card = collections.defaultdict(set)
occ = collections.Counter()
for sf, sfn, df, dfunc in CUR:
    occ[dfunc] += 1
    if df != pl.EXTERNAL:
        card[dfunc].add(df)
FILES = sorted({df for _, _, df, _ in CUR if df != pl.EXTERNAL})


def _pick_unique_edge():
    for i, (sf, sfn, df, dfunc) in enumerate(CUR):
        if df != pl.EXTERNAL and len(card[dfunc]) == 1 and occ[dfunc] == 1:
            alt = [f for f in FILES if f != df]
            if alt:
                return i, (sf, sfn, df, dfunc), alt[0]
    raise SystemExit("no unique-name edge available in " + REPO)


def _pick_any_internal_edge():
    for i, (sf, sfn, df, dfunc) in enumerate(CUR):
        if df != pl.EXTERNAL:
            return i, (sf, sfn, df, dfunc)
    raise SystemExit("no internal edge available in " + REPO)


results = []


def record(case, expected, exit_code, verdict, ok, detail):
    actual = "PASS" if exit_code == 0 else "FAIL"
    passed = ok and (actual == expected)
    results.append({"case": case, "expected": expected, "actual": actual,
                    "exit": exit_code, "ok": passed, "detail": detail})
    print("SELFTEST_CASE %s | expected=%s actual=%s exit=%d ok=%s | %s"
          % (case, expected, actual, exit_code, passed, detail))


# clean ---------------------------------------------------------------------- #
bd = _write_baseline(CUR)
rc, v = run_gate(bd, allow=_write_allow([]))
c = v.get("counts", {})
ok = (c.get("removed_unreviewed") == 0 and c.get("new_low_or_unreviewed") == 0
      and c.get("flipped_unreviewed") == 0 and v.get("parity") == "PASS")
record("clean", "PASS", rc, v, ok,
       "0 delta; rem_unrev/new/flip all 0")

# (a) unique-name flip ------------------------------------------------------- #
i, (sf, sfn, df, dfunc), altf = _pick_unique_edge()
mut = [list(e) for e in CUR]
mut[i] = [sf, sfn, altf, dfunc]
rc, v = run_gate(_write_baseline(mut), allow=_write_allow([]))
c = v.get("counts", {})
ok = c.get("flipped_unreviewed", 0) >= 1 and c.get("flips_on_unique_name", 0) >= 1
record("a_unique_flip", "FAIL", rc, v, ok,
       "flip %s::%s->%s (unique) flip_unrev=%s uniq=%s"
       % (sf, sfn, dfunc, c.get("flipped_unreviewed"), c.get("flips_on_unique_name")))

# (b) un-allowlisted ADDED --------------------------------------------------- #
i2, (bsf, bsfn, bdf, bdfunc) = _pick_any_internal_edge()
k0 = (bsf, bsfn, bdfunc)
base_minus = [list(e) for e in CUR if (e[0], e[1], e[3]) != k0]
addD = sorted({e[2] for e in CUR if (e[0], e[1], e[3]) == k0})
rc, v = run_gate(_write_baseline(base_minus), allow=_write_allow([]))
c = v.get("counts", {})
ok = c.get("new_low_or_unreviewed", 0) >= 1
record("b_added_unreviewed", "FAIL", rc, v, ok,
       "deleted callsite %s::%s->%s from baseline -> added; new=%s"
       % (bsf, bsfn, bdfunc, c.get("new_low_or_unreviewed")))

# (c) positive-control regression -------------------------------------------- #
posctl = None
for g in json.load(open(os.path.join(HERE, "cluster_goldens.json")))["cells"]:
    if g.get("positive_control"):
        posctl = dict(g)
        break
posctl["check"] = json.loads(json.dumps(posctl["check"]))
# force regression: require an edge the binary will NEVER emit.
posctl["check"]["params"]["required"] = [
    {"src_func": "use_cat", "dst_func": "Cat.__never_exists__", "dst_file": "animals.py"}]
gdir = tempfile.mkdtemp(prefix="gold.", dir=WORK)
shutil.copytree(os.path.join(HERE, "fixtures"), os.path.join(gdir, "fixtures"))
gpath = os.path.join(gdir, "goldens.json")
json.dump({"cells": [posctl]}, open(gpath, "w"))
rc, v = run_gate(_write_baseline(CUR), allow=_write_allow([]),
                 goldens=gpath, no_cluster=False)
ok = v.get("cluster", {}).get("regressed", 0) >= 1
record("c_posctl_regressed", "FAIL", rc, v, ok,
       "posctl required impossible edge; cluster.regressed=%s"
       % v.get("cluster", {}).get("regressed"))

# (d) NON-unique-name flip --------------------------------------------------- #
i3, (dsf, dsfn, ddf, ddfunc) = _pick_any_internal_edge()
kd = (dsf, dsfn, ddfunc)
two = "sds.h" if "sds.h" in FILES else FILES[-1]
one = "sds.c" if "sds.c" in FILES else FILES[0]
mutd = [list(e) for e in CUR if (e[0], e[1], e[3]) != kd]
mutd.append([dsf, dsfn, one, ddfunc])
mutd.append([dsf, dsfn, two, ddfunc])   # baseline callsite -> {2 files} = non-unique
rc, v = run_gate(_write_baseline(mutd), allow=_write_allow([]))
c = v.get("counts", {})
ok = (c.get("flipped_unreviewed", 0) >= 1 and c.get("flips_on_unique_name", 0) == 0)
record("d_nonunique_flip", "FAIL", rc, v, ok,
       "callsite %s::%s->%s baseline->{%s,%s} (card>=2); flip_unrev=%s uniq=%s"
       % (dsf, dsfn, ddfunc, one, two, c.get("flipped_unreviewed"),
          c.get("flips_on_unique_name")))

# (e) un-allowlisted REMOVED ------------------------------------------------- #
phantom = [dsf, dsfn, one, "__phantom_removed_callee__"]
mute = [list(e) for e in CUR] + [phantom]
rc, v = run_gate(_write_baseline(mute), allow=_write_allow([]))
c = v.get("counts", {})
ok = c.get("removed_unreviewed", 0) >= 1
record("e_removed_unreviewed", "FAIL", rc, v, ok,
       "baseline-only phantom callsite -> removed; rem_unrev=%s"
       % c.get("removed_unreviewed"))

# (f) empty calls output (status != ok) -------------------------------------- #
rc, v = run_gate(_write_baseline(CUR), allow=_write_allow([]),
                 binary=_shim(0, emit=""))
ok = any("empty" in e.get("error", "") or "status=" in e.get("error", "")
         for e in v.get("errors", [])) and v.get("parity") == "FAIL"
record("f_empty_output", "FAIL", rc, v, ok,
       "shim prints nothing -> status empty; errors=%s" % v.get("errors"))

# (f_crash) binary crash (exit != 0) ----------------------------------------- #
rc, v = run_gate(_write_baseline(CUR), allow=_write_allow([]),
                 binary=_shim(1, emit=""))
ok = any("status=" in e.get("error", "") for e in v.get("errors", [])) \
    and v.get("parity") == "FAIL"
record("f_crash_exit", "FAIL", rc, v, ok,
       "shim exits 1 -> status error; errors=%s" % v.get("errors"))

# (g) UNEXPECTED missing baseline (non-excluded repo) ------------------------ #
empty_bd = tempfile.mkdtemp(prefix="emptybl.", dir=WORK)
rc, v = run_gate(empty_bd, allow=_write_allow([]))
ok = any("missing" in e.get("error", "") for e in v.get("errors", [])) \
    and v.get("parity") == "FAIL"
record("g_missing_baseline", "FAIL", rc, v, ok,
       "no %s.calls.json for non-excluded repo; errors=%s" % (REPO, v.get("errors")))

# (g_excluded) intentional exclusion skipped cleanly ------------------------- #
empty_bd2 = tempfile.mkdtemp(prefix="emptybl2.", dir=WORK)
rc, v = run_gate(empty_bd2, allow=_write_allow([]), repos=EXCLUDED_REPO)
ok = (v.get("parity") == "PASS" and EXCLUDED_REPO in v.get("excluded_skipped", [])
      and not v.get("errors"))
record("g_excluded_skip", "PASS", rc, v, ok,
       "excluded repo skipped cleanly even with no baseline; skipped=%s"
       % v.get("excluded_skipped"))

# (h) owner-flip at an ALLOWLISTED call-site (dst_file mutated) -------------- #
wrongfile = next((f for f in FILES if f not in addD), None)
if wrongfile is None:
    wrongfile = (addD[0] + "/__wrong__")   # guarantee mismatch
allow_wrong = [{"repo": REPO, "type": "added", "src_file": bsf,
                "src_func": bsfn, "dst_func": bdfunc, "dst_file": wrongfile}]
rc, v = run_gate(_write_baseline(base_minus), allow=_write_allow(allow_wrong))
c = v.get("counts", {})
ok = c.get("new_low_or_unreviewed", 0) >= 1   # allow present but dst_file mismatches
record("h_owner_flip_allowlisted", "FAIL", rc, v, ok,
       "allow dst_file=%s but resolved owner=%s -> unabsorbed; new=%s"
       % (wrongfile, addD, c.get("new_low_or_unreviewed")))

# (h_ok) correctly owner-pinned allowlist entry accepted --------------------- #
allow_right = [{"repo": REPO, "type": "added", "src_file": bsf,
                "src_func": bsfn, "dst_func": bdfunc, "dst_file": addD}]
rc, v = run_gate(_write_baseline(base_minus), allow=_write_allow(allow_right))
c = v.get("counts", {})
ok = (c.get("new_low_or_unreviewed", 0) == 0 and v.get("parity") == "PASS")
record("h_ok_owner_pinned", "PASS", rc, v, ok,
       "allow dst_file=%s matches resolved owner -> absorbed; new=%s parity=%s"
       % (addD, c.get("new_low_or_unreviewed"), v.get("parity")))

# --------------------------------------------------------------------------- #
shutil.rmtree(WORK, ignore_errors=True)
allok = all(r["ok"] for r in results)
print("SELFTEST_SUMMARY %s" % json.dumps(
    {"total": len(results), "passed": sum(1 for r in results if r["ok"]),
     "all_ok": allok}))
sys.exit(0 if allok else 1)
