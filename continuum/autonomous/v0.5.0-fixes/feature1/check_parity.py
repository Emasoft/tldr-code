#!/usr/bin/env python3
"""FEATURE-1 d.0 -- differential parity gate (never-worse-than-name-match).

Re-runs `tldr calls` (and the cluster repros) on the CURRENT installed binary,
diffs the normalized edge set against the captured name-match baseline, and emits
a structured PASS/FAIL verdict. Exits non-zero on FAIL.

HARD FAIL conditions (the "never worse" rules):
  (a) flips_on_unique_name > 0
      A call-site (caller, callee-name) whose baseline callee NAME was UNIQUE
      across the repo baseline now resolves to a DIFFERENT definition file.
      Name-match was definitionally correct for a unique name, so a flip there
      is a regression.
  (b) new_low_or_unreviewed > 0
      `calls` exposes no confidence/resolution-kind field, so every NET-NEW edge
      at a previously-UNRESOLVED call-site (an ADDED (caller, callee-name) pair)
      is treated as REVIEW and FAILS unless it is on the --allow allowlist.
  (c) a POSITIVE-CONTROL cluster cell regressed (constructor-typed receiver lost
      its per-type resolution).

REPORTED but not auto-failing: removed edges, non-unique flips (broadcast
collapse is the whole point), and cluster still_buggy/improved/fixed progress.

Usage:
  python3 check_parity.py \
      --binary /Users/cosimo/.cargo/bin/tldr \
      --baseline-dir /Users/cosimo/.tldr-audit/feature1-baseline \
      --root /Users/cosimo/.tldr-audit/corpora \
      [--allow stage_expected.json] [--repos c-sds,rust-clap] [--runs 3]
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import parity_lib as pl  # noqa: E402


def load_summary(baseline_dir, summary_path):
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (summary_path,
                 os.path.join(baseline_dir, "baseline_summary.json"),
                 os.path.join(here, "baseline_summary.json")):
        if cand and os.path.exists(cand):
            return json.load(open(cand))
    raise SystemExit("no baseline_summary.json found (run capture_baseline.sh)")


def load_baseline_doc(baseline_dir, repo):
    path = os.path.join(baseline_dir, repo + ".calls.json")
    if not os.path.exists(path):
        return None
    return json.load(open(path))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default="/Users/cosimo/.cargo/bin/tldr")
    ap.add_argument("--baseline-dir", default="/Users/cosimo/.tldr-audit/feature1-baseline")
    ap.add_argument("--root", default="/Users/cosimo/.tldr-audit/corpora")
    ap.add_argument("--summary", default=None,
                    help="baseline_summary.json (default: <baseline-dir>/baseline_summary.json)")
    ap.add_argument("--goldens", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "cluster_goldens.json"))
    ap.add_argument("--allow", default=None, help="JSON file of expected deltas")
    ap.add_argument("--repos", default=None, help="comma list to restrict to")
    ap.add_argument("--runs", type=int, default=pl.DEFAULT_RUNS)
    ap.add_argument("--timeout", type=int, default=pl.DEFAULT_TIMEOUT)
    ap.add_argument("--json-out", default=None, help="write full verdict JSON here")
    ap.add_argument("--no-cluster", action="store_true",
                    help="skip cluster-golden evaluation (edge-diff gate only)")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    summary = load_summary(a.baseline_dir, a.summary)
    repo_filter = set(a.repos.split(",")) if a.repos else None
    allow_all = []
    if a.allow:
        allow_all = json.load(open(a.allow)).get("allow", [])

    totals = {"repos": 0, "baseline_edges": 0, "current_edges": 0,
              "removed": 0, "added": 0, "flipped": 0,
              "flips_on_unique_name": 0, "new_low_or_unreviewed": 0}
    repo_reports = []
    errors = []
    excluded_skipped = []

    for entry in summary.get("repos", []):
        repo = entry["repo"]
        if repo_filter and repo not in repo_filter:
            continue
        if entry.get("excluded"):
            excluded_skipped.append(repo)
            continue
        bdoc = load_baseline_doc(a.baseline_dir, repo)
        if bdoc is None:
            errors.append({"repo": repo, "error": "baseline edge file missing"})
            continue
        baseline_edges = frozenset(pl.edge_from_list(e) for e in bdoc.get("stable", []))
        cur = pl.stable_calls(a.binary, entry.get("captured_path",
                              os.path.join(a.root, repo)), a.root,
                              a.runs, a.timeout)
        if cur["status"] != "ok":
            errors.append({"repo": repo, "error": "current run " + cur["status"]})
            continue
        cur_edges = frozenset(pl.edge_from_list(e) for e in cur["stable"])
        # jitter immunity: skip deltas on any call-site that is unstable in
        # either the baseline or the current capture.
        ignore = (pl.callsite_keys_of(bdoc.get("unstable", []))
                  | pl.callsite_keys_of(cur.get("unstable", [])))
        allow_repo = [x for x in allow_all if x.get("repo") in (repo, "*")]
        d = pl.diff_repo(repo, baseline_edges, cur_edges, allow_repo,
                         ignore_callsites=ignore)
        for k in ("baseline_edges", "current_edges", "removed", "added",
                  "flipped", "flips_on_unique_name", "new_low_or_unreviewed"):
            totals[k] += d[k]
        totals["repos"] += 1
        repo_reports.append(d)

    # ---- cluster goldens vs current binary ----
    cluster = {"fixed": 0, "improved": 0, "still_buggy": 0,
               "correct": 0, "regressed": 0, "uncomputed": 0}
    cluster_cells = []
    posctl_regressed = []
    if not a.no_cluster:
        goldens = json.load(open(a.goldens))["cells"]
        feature1_dir = os.path.dirname(os.path.abspath(a.goldens))
        for g in goldens:
            r = pl.eval_cluster(a.binary, g, a.root, a.timeout,
                                feature1_dir=feature1_dir)
            cluster[r["status"]] = cluster.get(r["status"], 0) + 1
            cluster_cells.append(r)
            if r["status"] == "regressed":
                posctl_regressed.append(r["id"])

    # ---- verdict ----
    fail_reasons = []
    if totals["flips_on_unique_name"] > 0:
        fail_reasons.append("rule(a): %d flip(s) on a UNIQUE baseline callee name"
                            % totals["flips_on_unique_name"])
    if totals["new_low_or_unreviewed"] > 0:
        fail_reasons.append("rule(b): %d net-new edge(s) at previously-unresolved "
                            "call-sites not on allowlist" % totals["new_low_or_unreviewed"])
    if posctl_regressed:
        fail_reasons.append("rule(c): positive control regressed: "
                            + ",".join(posctl_regressed))
    passed = not fail_reasons

    counts = {
        "repos": totals["repos"],
        "baseline_edges": totals["baseline_edges"],
        "removed": totals["removed"],
        "added": totals["added"],
        "flipped": totals["flipped"],
        "flips_on_unique_name": totals["flips_on_unique_name"],
        "new_low_or_unreviewed": totals["new_low_or_unreviewed"],
        "cluster_fixed": cluster["fixed"],
        "cluster_still_buggy": cluster["still_buggy"],
    }

    verdict = {
        "binary": a.binary,
        "counts": counts,
        "cluster": cluster,
        "cluster_cells": cluster_cells,
        "errors": errors,
        "excluded_skipped": excluded_skipped,
        "fail_reasons": fail_reasons,
        "parity": "PASS" if passed else "FAIL",
    }
    if a.json_out:
        with open(a.json_out, "w") as fh:
            json.dump({**verdict, "repo_reports": repo_reports}, fh, indent=1)

    if not a.quiet:
        print("COUNTS " + json.dumps(counts))
        print("CLUSTER " + json.dumps({k: cluster[k] for k in
              ("fixed", "improved", "still_buggy", "correct", "regressed",
               "uncomputed")}))
        if excluded_skipped:
            print("EXCLUDED_REPOS " + json.dumps(excluded_skipped))
        if errors:
            print("ERRORS " + json.dumps(errors))
        # show the actual offending call-sites so a stage can triage / allowlist
        for d in repo_reports:
            if d["flips_on_unique_name"] or d["new_low_or_unreviewed"]:
                print("OFFENDERS[%s]" % d["repo"])
                for f in d["_flips_on_unique_name"]:
                    print("  FLIP_UNIQUE %s::%s -> %s  base=%s cur=%s" % (
                        f["src_file"], f["src_func"], f["dst_func"],
                        f["baseline_dst_files"], f["current_dst_files"]))
                for n in d["_new_low_or_unreviewed"]:
                    print("  NEW_UNREVIEWED %s::%s -> %s @ %s" % (
                        n["src_file"], n["src_func"], n["dst_func"], n["dst_files"]))
        for fr in fail_reasons:
            print("FAIL_REASON " + fr)
        print("PARITY: " + ("PASS" if passed else "FAIL"))

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
