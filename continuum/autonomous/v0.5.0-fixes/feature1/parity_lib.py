#!/usr/bin/env python3
"""FEATURE-1 d.0 -- differential parity harness shared library.

This module is the single source of truth for:
  * running `tldr calls` and NORMALIZING its edge set to deterministic tuples,
  * the determinism protocol (run N times, keep the STABLE INTERSECTION,
    exclude genuinely nondeterministic repos so jitter never causes a false
    regression),
  * the never-worse-than-name-match diff (removed / added / flipped, plus the
    two hard FAIL classes: flips_on_unique_name and new/unreviewed call-sites),
  * evaluating the FEATURE-1 cluster goldens against any binary's output.

The REAL `tldr calls --format json` schema (introspected on tldr 0.4.1, the
reference name-match binary) is:

    { "root": str, "language": str,
      "nodes": [ "file:func", ... ],
      "edges": [ { "src_file": str, "src_func": str,
                   "dst_file": str, "dst_func": str,
                   "call_type": "intra|direct|method|attr|ref" }, ... ],
      "truncated": bool, "total_edges": int, "shown_edges": int }

There is NO per-edge line number and NO confidence/resolution-kind field beyond
`call_type`. So:
  * the EDGE IDENTITY used for parity is (src_file, src_func, dst_file, dst_func)
    with paths normalized relative to the repo root; `call_type` is recorded as
    metadata but kept OUT of the identity (a resolution improvement may legitly
    reclassify method<->attr without being a regression),
  * the CALL-SITE proxy key is (src_file, src_func, dst_func) -- "caller invokes
    a callee named N"; its value is the set of dst_file definitions N binds to.
    A FLIP = same call-site key, different resolved dst_file set. This is the
    faithful stand-in for (caller,file,line)->callee given no line numbers.

This is TEST TOOLING; parsing JSON with python/regex here is intentional and
does not touch the analysis engine (no crates/*/src edits).
"""

import hashlib
import json
import os
import subprocess
import sys

EXTERNAL = "<external>"
DEFAULT_RUNS = 3
DEFAULT_TIMEOUT = 90
# A repo is EXCLUDED from the gate when more than this fraction of its observed
# edges are unstable across runs (genuine nondeterminism -> never gate on it).
UNSTABLE_EXCLUDE_FRAC = 0.02


# --------------------------------------------------------------------------- #
# subprocess + path helpers
# --------------------------------------------------------------------------- #
def run_tldr(binary, args, timeout_s):
    """Run `tldr <args> --format json`. Returns (status, parsed_json_or_None).

    status in {"ok", "timeout", "error", "empty", "badjson"}.
    """
    env = dict(os.environ)
    env["TLDR_NO_DAEMON"] = "1"
    cmd = [binary] + list(args) + ["--format", "json"]
    try:
        p = subprocess.run(
            cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return "timeout", None
    if p.returncode != 0:
        return "error", None
    out = p.stdout.decode("utf-8", "replace").strip()
    if not out:
        return "empty", None
    try:
        return "ok", json.loads(out)
    except json.JSONDecodeError:
        return "badjson", None


def relpath(path, root):
    """Normalize a file path to be relative to the repo root. `<external>` and
    already-relative paths pass through unchanged."""
    if not path or path == EXTERNAL or path.startswith("<"):
        return path
    root = root.rstrip("/")
    if path == root:
        return os.path.basename(path)
    pref = root + "/"
    if path.startswith(pref):
        return path[len(pref):]
    return path  # already relative (e.g. `calls` emits repo-relative paths)


# --------------------------------------------------------------------------- #
# edge normalization
# --------------------------------------------------------------------------- #
def edges_from_calls(doc, root):
    """Return a frozenset of normalized edge tuples
    (src_file, src_func, dst_file, dst_func) from a parsed `calls` document."""
    out = set()
    for e in doc.get("edges", []):
        out.add((
            relpath(e.get("src_file", ""), root),
            e.get("src_func", ""),
            relpath(e.get("dst_file", ""), root),
            e.get("dst_func", ""),
        ))
    return frozenset(out)


def edge_to_list(e):
    return [e[0], e[1], e[2], e[3]]


def edge_from_list(lst):
    return (lst[0], lst[1], lst[2], lst[3])


def sha_digest(edges):
    """Order-independent sha256 digest of a normalized edge set."""
    lines = sorted("\x1f".join(e) for e in edges)
    h = hashlib.sha256()
    for ln in lines:
        h.update(ln.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# determinism protocol: run N times, keep the STABLE INTERSECTION
# --------------------------------------------------------------------------- #
def stable_calls(binary, path, root, runs=DEFAULT_RUNS, timeout_s=DEFAULT_TIMEOUT):
    """Run `calls` on `path` `runs` times. Returns a dict:

      { status, captured_path, run_count, run_edge_counts, run_statuses,
        stable (sorted list of edge-lists), unstable (sorted list of edge-lists),
        unstable_frac, excluded(bool), reason }

    `stable` = intersection across all successful runs (jitter-proof baseline).
    `unstable` = union minus intersection (logged, never gated on).
    """
    sets = []
    statuses = []
    for _ in range(runs):
        st, doc = run_tldr(binary, ["calls", path], timeout_s)
        statuses.append(st)
        if st == "ok":
            sets.append(edges_from_calls(doc, root))
        else:
            sets.append(None)

    ok_sets = [s for s in sets if s is not None]
    if not ok_sets:
        return {
            "status": statuses[0] if statuses else "error",
            "captured_path": path, "run_count": runs, "run_statuses": statuses,
            "run_edge_counts": [], "stable": [], "unstable": [],
            "unstable_frac": 0.0, "excluded": True,
            "reason": "all runs failed (%s)" % ",".join(statuses),
        }

    inter = set(ok_sets[0])
    union = set(ok_sets[0])
    for s in ok_sets[1:]:
        inter &= s
        union |= s
    unstable = union - inter
    frac = (len(unstable) / len(union)) if union else 0.0

    excluded = False
    reason = ""
    if len(ok_sets) < runs:
        # at least one run failed/timed out -> still gate on the stable
        # intersection of the successful runs, but flag it.
        reason = "partial runs ok=%d/%d (%s)" % (
            len(ok_sets), runs, ",".join(statuses))
    if frac > UNSTABLE_EXCLUDE_FRAC:
        excluded = True
        reason = "nondeterministic: %d/%d edges unstable (%.3f > %.3f)" % (
            len(unstable), len(union), frac, UNSTABLE_EXCLUDE_FRAC)

    return {
        "status": "ok",
        "captured_path": path,
        "run_count": runs,
        "run_statuses": statuses,
        "run_edge_counts": [len(s) for s in ok_sets],
        "stable": sorted(edge_to_list(e) for e in inter),
        "unstable": sorted(edge_to_list(e) for e in unstable),
        "unstable_frac": round(frac, 5),
        "excluded": excluded,
        "reason": reason,
    }


def stable_calls_with_fallback(binary, primary, fallbacks, root,
                               runs=DEFAULT_RUNS, timeout_s=DEFAULT_TIMEOUT):
    """Capture at `primary`; on timeout/empty, try each fallback subdir in order.
    Records `captured_path` so the baseline documents exactly what was measured."""
    res = stable_calls(binary, primary, root, runs, timeout_s)
    if not (res["status"] != "ok" or "timeout" in res.get("run_statuses", [])):
        return res
    # primary timed out or failed -> try fallbacks
    for fb in fallbacks:
        if not os.path.isdir(fb):
            continue
        alt = stable_calls(binary, fb, root, runs, timeout_s)
        if alt["status"] == "ok" and "timeout" not in alt["run_statuses"]:
            alt["captured_path"] = fb
            alt["reason"] = ("primary timed out; fell back to subdir. "
                             + alt.get("reason", "")).strip()
            return alt
    return res  # nothing better; return primary result (likely excluded)


# --------------------------------------------------------------------------- #
# never-worse diff
# --------------------------------------------------------------------------- #
def name_cardinality(edges):
    """Map dst_func name -> set of dst_file it is defined-at across the baseline.
    cardinality == 1  ==>  the callee NAME is UNIQUE; name-match was
    definitionally correct, so any later flip there is a regression."""
    m = {}
    for (_sf, _sfn, dfile, dfunc) in edges:
        if dfile == EXTERNAL:
            continue
        m.setdefault(dfunc, set()).add(dfile)
    return m


def callsite_map(edges):
    """(src_file, src_func, dst_func) -> set(dst_file) resolved targets."""
    m = {}
    for (sf, sfn, dfile, dfunc) in edges:
        m.setdefault((sf, sfn, dfunc), set()).add(dfile)
    return m


def _dst_sig(dst_files):
    """Canonical, order-independent signature of a call-site's resolved-owner
    dst_file SET. Used inside the allowlist key so an allowlisted call-site is
    bound to the specific owner file(s) it was reviewed against."""
    return "\x1f".join(sorted(dst_files))


def _allow_index(allow_entries):
    """Index allow entries into a set of
       (type, repo, src_file, src_func, dst_func, dst_sig) tuples.

    Each entry: {repo, type:'added'|'removed'|'flipped', src_file, src_func,
    dst_func, dst_file}. `dst_file` is the resolved callee OWNER file(s) and is
    REQUIRED: it may be a single string or a list. Including it in the key means
    an allowlisted call-site can NOT silently absorb a future owner-flip to a
    DIFFERENT file (the owner-blind-key hole). `repo` may be '*' (any repo)."""
    idx = set()
    for a in allow_entries or []:
        df = a.get("dst_file", "")
        if isinstance(df, str):
            df = [df] if df else []
        idx.add((
            a.get("type", ""), a.get("repo", ""),
            a.get("src_file", ""), a.get("src_func", ""), a.get("dst_func", ""),
            _dst_sig(df),
        ))
    return idx


def _allow_has(idx, type_, repo, sf, sfn, dfunc, dst_files):
    """True iff this delta is explicitly allowlisted. Matches the CONCRETE repo
    OR '*' (fixes the latent '*'-never-matches scoping bug: entries stored under
    '*' were previously unreachable because the lookup used the concrete repo)
    AND requires the resolved dst_file OWNER set to match the reviewed entry."""
    sig = _dst_sig(dst_files)
    return ((type_, repo, sf, sfn, dfunc, sig) in idx
            or (type_, "*", sf, sfn, dfunc, sig) in idx)


def diff_repo(repo, baseline_edges, current_edges, allow_entries,
              ignore_callsites=None):
    """Categorize the per-repo delta. Returns a dict of counts + detail lists.

    Every channel is GATED: a delta must carry an explicit allowlist entry that
    pins the EXACT resolved owner file(s), else it FAILS.
      * added   call-sites -> new_low_or_unreviewed  (rule b)
      * flipped call-sites -> flipped_unreviewed      (rule a; unique OR not)
      * removed call-sites -> removed_unreviewed       (rule d)
    `flips_on_unique_name` is the louder sub-signal: a flip whose baseline callee
    NAME was UNIQUE is a definitional regression (name-match was provably right).

    `ignore_callsites` is a set of (src_file, src_func, dst_func) keys that are
    KNOWN-UNSTABLE (jitter) in the baseline and/or current capture; deltas on
    those keys are skipped entirely so nondeterminism never causes a false
    regression."""
    ignore = ignore_callsites or set()
    card = name_cardinality(baseline_edges)
    bmap = callsite_map(baseline_edges)
    cmap = callsite_map(current_edges)
    allow = _allow_index(allow_entries)

    removed, added, flipped = [], [], []
    removed_unreviewed = []
    flips_on_unique = []
    flipped_unreviewed = []
    new_unreviewed = []
    jitter_skipped = 0

    bkeys = set(bmap)
    ckeys = set(cmap)

    for k in sorted(bkeys - ckeys):
        if k in ignore:
            jitter_skipped += 1
            continue
        sf, sfn, dfunc = k
        rec = {"src_file": sf, "src_func": sfn, "dst_func": dfunc,
               "dst_files": sorted(bmap[k])}
        removed.append(rec)
        # rule (d): d.2 REMOVES edges (declining bad fuzzy matches). A removed
        # edge is only OK if it is an explicitly reviewed, owner-pinned entry;
        # an un-reviewed removal could be a genuine loss of a correct edge.
        if not _allow_has(allow, "removed", repo, sf, sfn, dfunc, bmap[k]):
            removed_unreviewed.append(rec)

    for k in sorted(ckeys - bkeys):
        if k in ignore:
            jitter_skipped += 1
            continue
        sf, sfn, dfunc = k
        rec = {"src_file": sf, "src_func": sfn, "dst_func": dfunc,
               "dst_files": sorted(cmap[k])}
        added.append(rec)
        # rule (b): confidence is NOT exposed -> every NET-NEW edge at a
        # previously-unresolved call-site is REVIEW; FAIL unless allowlisted for
        # the exact resolved OWNER file(s).
        if not _allow_has(allow, "added", repo, sf, sfn, dfunc, cmap[k]):
            new_unreviewed.append(rec)

    for k in sorted(bkeys & ckeys):
        if bmap[k] == cmap[k]:
            continue
        if k in ignore:
            jitter_skipped += 1
            continue
        sf, sfn, dfunc = k
        rec = {"src_file": sf, "src_func": sfn, "dst_func": dfunc,
               "baseline_dst_files": sorted(bmap[k]),
               "current_dst_files": sorted(cmap[k])}
        flipped.append(rec)
        # rule (a): d.2-d.4 RE-POINT ambiguous (non-unique) calls, so EVERY flip
        # -- unique or not -- must be allowlisted for its exact NEW resolved
        # owner set; an un-reviewed flip FAILS.
        if not _allow_has(allow, "flipped", repo, sf, sfn, dfunc, cmap[k]):
            flipped_unreviewed.append(rec)
            # louder sub-signal: a flip on a UNIQUE baseline callee name.
            if len(card.get(dfunc, set())) == 1:
                flips_on_unique.append(rec)

    return {
        "repo": repo,
        "baseline_edges": len(baseline_edges),
        "current_edges": len(current_edges),
        "removed": len(removed),
        "added": len(added),
        "flipped": len(flipped),
        "removed_unreviewed": len(removed_unreviewed),
        "flipped_unreviewed": len(flipped_unreviewed),
        "flips_on_unique_name": len(flips_on_unique),
        "new_low_or_unreviewed": len(new_unreviewed),
        "jitter_skipped": jitter_skipped,
        "_removed": removed,
        "_removed_unreviewed": removed_unreviewed,
        "_added": added,
        "_flipped": flipped,
        "_flipped_unreviewed": flipped_unreviewed,
        "_flips_on_unique_name": flips_on_unique,
        "_new_low_or_unreviewed": new_unreviewed,
    }


def callsite_keys_of(edge_lists):
    """Build a set of (src_file, src_func, dst_func) call-site keys from a list
    of [src_file, src_func, dst_file, dst_func] edge-lists."""
    return {(e[0], e[1], e[3]) for e in edge_lists}


# --------------------------------------------------------------------------- #
# cluster golden evaluation
# --------------------------------------------------------------------------- #
def _cmp(op, value, threshold):
    if value is None:
        return False
    if op == ">=":
        return value >= threshold
    if op == ">":
        return value > threshold
    if op == "<=":
        return value <= threshold
    if op == "<":
        return value < threshold
    if op == "==":
        return value == threshold
    if op == "!=":
        return value != threshold
    raise ValueError("bad op " + repr(op))


def _impact_targets(doc):
    return doc.get("targets", {}) if isinstance(doc, dict) else {}


def cluster_value(kind, params, doc):
    """Compute the numeric/boolean metric for a cluster cell from command JSON.
    Returns the value, or None if it could not be computed."""
    if doc is None:
        return None
    p = params or {}
    if kind == "impact_max_caller_count":
        t = _impact_targets(doc)
        return max((v.get("caller_count", 0) for v in t.values()), default=0)
    if kind == "impact_target_count":
        return doc.get("total_targets", len(_impact_targets(doc)))
    if kind == "impact_target_caller_count":
        sub = p["target_substr"]
        vals = [v.get("caller_count", 0) for k, v in _impact_targets(doc).items()
                if sub in k]
        return max(vals, default=None)
    if kind == "impact_has_target":
        sub = p["target_substr"]
        return 1 if any(sub in k for k in _impact_targets(doc)) else 0
    if kind == "impact_two_targets_equal_cc":
        a, b = p["target_a_substr"], p["target_b_substr"]
        ca = [v.get("caller_count") for k, v in _impact_targets(doc).items()
              if a in k]
        cb = [v.get("caller_count") for k, v in _impact_targets(doc).items()
              if b in k]
        if not ca or not cb:
            return 0
        # cross-attribution signature: the two distinct receiver classes report
        # an IDENTICAL caller_count (the same callers broadcast to both).
        return 1 if max(ca) == max(cb) else 0
    if kind == "impact_false_callers":
        sub = p["target_substr"]
        fsub = p["caller_file_substr"]
        total = 0
        found = False
        for k, v in _impact_targets(doc).items():
            if sub not in k:
                continue
            found = True
            for c in v.get("callers", []):
                if fsub in (c.get("file") or ""):
                    total += 1
        return total if found else None
    if kind == "whatbreaks_direct_callers":
        s = doc.get("summary", {}) if isinstance(doc, dict) else {}
        return s.get("direct_caller_count")
    if kind == "explain_self_edge":
        fn = p["func"]
        for c in doc.get("callees", []):
            if c.get("name") == fn and c.get("file") != EXTERNAL:
                return 1
        return 0
    if kind == "explain_callee_nonexternal":
        names = set(p["names"])
        return sum(1 for c in doc.get("callees", [])
                   if c.get("name") in names and c.get("file") != EXTERNAL)
    if kind == "calls_edge_assert":
        # positive control: 1 (regressed) if any forbidden edge present OR any
        # required edge missing; else 0 (correct).
        edges = {(e.get("src_func"), e.get("dst_func"),
                  os.path.basename(e.get("dst_file") or ""))
                 for e in doc.get("edges", [])}
        for f in p.get("forbidden", []):
            for (s, d, fl) in edges:
                if s == f["src_func"] and d == f["dst_func"]:
                    return 1
        for r in p.get("required", []):
            ok = any(s == r["src_func"] and d == r["dst_func"]
                     and (("dst_file" not in r) or fl == r["dst_file"])
                     for (s, d, fl) in edges)
            if not ok:
                return 1
        return 0
    raise ValueError("unknown cluster kind: " + kind)


def cluster_status(golden, value):
    """still_buggy | improved | fixed  (or for positive controls: correct |
    regressed)."""
    if golden.get("positive_control"):
        return "correct" if value == 0 else "regressed"
    buggy = golden["buggy"]
    fixed = golden["fixed"]
    if _cmp(buggy["op"], value, buggy["value"]):
        return "still_buggy"
    if _cmp(fixed["op"], value, fixed["value"]):
        return "fixed"
    return "improved"


def eval_cluster(binary, golden, root, timeout_s=DEFAULT_TIMEOUT, raw_out=None,
                 feature1_dir=None):
    """Run a golden's repro on `binary`, compute its value+status. Returns a dict.
    If raw_out is given, the raw command JSON is written there.

    Repro argv may use {repo} (-> root/<golden.repo>) and {feature1} (-> the
    harness dir, for in-tree fixtures like the positive control)."""
    repo_path = os.path.join(root, golden["repo"]) if golden.get("repo") else ""
    subs = {"{repo}": repo_path, "{feature1}": feature1_dir or ""}

    def _sub(a):
        for k, v in subs.items():
            a = a.replace(k, v)
        return a

    args = [_sub(a) for a in golden["repro"]]
    st, doc = run_tldr(binary, args, timeout_s)
    if raw_out is not None and doc is not None:
        with open(raw_out, "w") as fh:
            json.dump(doc, fh)
    value = cluster_value(golden["check"]["kind"],
                          golden["check"].get("params"), doc) if st == "ok" else None
    status = cluster_status(golden, value) if value is not None else "uncomputed"
    return {"id": golden["id"], "lang": golden["lang"], "repo": golden["repo"],
            "run_status": st, "value": value, "status": status}


# --------------------------------------------------------------------------- #
# CLI (used by capture_baseline.sh; importable by check_parity.py)
# --------------------------------------------------------------------------- #
def _cli_capture(argv):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--path", required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--fallbacks", default="")
    ap.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    fbs = [x for x in a.fallbacks.split(",") if x]
    res = stable_calls_with_fallback(a.binary, a.path, fbs, a.root,
                                     a.runs, a.timeout)
    digest = sha_digest(frozenset(edge_from_list(e) for e in res["stable"]))
    res["sha"] = digest
    res["edge_count"] = len(res["stable"])
    with open(a.out, "w") as fh:
        json.dump(res, fh)
    # compact one-line status for the shell to read
    print(json.dumps({
        "status": res["status"], "excluded": res["excluded"],
        "edge_count": res["edge_count"], "unstable": len(res["unstable"]),
        "unstable_frac": res["unstable_frac"], "captured_path": res["captured_path"],
        "sha": digest, "reason": res["reason"],
    }))


def _cli_cluster_baseline(argv):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--goldens", required=True)
    ap.add_argument("--raw-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    a = ap.parse_args(argv)
    goldens = json.load(open(a.goldens))["cells"]
    feature1_dir = os.path.dirname(os.path.abspath(a.goldens))
    os.makedirs(a.raw_dir, exist_ok=True)
    results = []
    for g in goldens:
        raw = os.path.join(a.raw_dir, g["id"] + ".json")
        r = eval_cluster(a.binary, g, a.root, a.timeout, raw_out=raw,
                         feature1_dir=feature1_dir)
        results.append(r)
    with open(a.out, "w") as fh:
        json.dump({"cells": results}, fh, indent=1)
    print(json.dumps({"cells": [
        {"id": r["id"], "status": r["status"], "value": r["value"]}
        for r in results]}, indent=1))


def _cli_summarize(argv):
    """Build the committed COMPACT baseline_summary.json from per-repo snapshots
    in the out-of-repo baseline dir. The big edge lists stay out of the repo;
    only counts + sha digests + capture provenance are committed."""
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline-dir", required=True)
    ap.add_argument("--repos", required=True, help="comma list of repo names")
    ap.add_argument("--root", required=True)
    ap.add_argument("--reference", default="tldr 0.4.1")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    repos = [r for r in a.repos.split(",") if r]
    out_repos = []
    total_edges = 0
    excluded = []
    for repo in repos:
        path = os.path.join(a.baseline_dir, repo + ".calls.json")
        if not os.path.exists(path):
            out_repos.append({"repo": repo, "excluded": True,
                              "reason": "no snapshot captured"})
            excluded.append(repo)
            continue
        doc = json.load(open(path))
        rel_cap = relpath(doc.get("captured_path", ""), a.root) or doc.get("captured_path", "")
        rec = {
            "repo": repo,
            "captured_path": doc.get("captured_path", os.path.join(a.root, repo)),
            "captured_path_rel": rel_cap,
            "edges": doc.get("edge_count", len(doc.get("stable", []))),
            "sha": doc.get("sha", sha_digest(frozenset(
                edge_from_list(e) for e in doc.get("stable", [])))),
            "unstable": len(doc.get("unstable", [])),
            "unstable_frac": doc.get("unstable_frac", 0.0),
            "run_statuses": doc.get("run_statuses", []),
            "excluded": doc.get("excluded", False),
            "reason": doc.get("reason", ""),
        }
        out_repos.append(rec)
        if rec["excluded"]:
            excluded.append(repo)
        else:
            total_edges += rec["edges"]
    summary = {
        "_about": "FEATURE-1 d.0 committed baseline summary. Full per-repo edge "
                  "sets live OUT of repo at the baseline-dir; here we keep counts "
                  "+ sha digests + capture provenance so the baseline is "
                  "documented in-tree. Excluded repos are nondeterministic and "
                  "NOT gated on.",
        "reference_binary": a.reference,
        "repos_captured": len([r for r in out_repos if not r.get("excluded")]),
        "repos_excluded": excluded,
        "total_edges": total_edges,
        "repos": out_repos,
    }
    with open(a.out, "w") as fh:
        json.dump(summary, fh, indent=1)
    print(json.dumps({"repos_captured": summary["repos_captured"],
                      "total_edges": total_edges, "excluded": excluded}))


def main(argv):
    if not argv:
        print("usage: parity_lib.py {capture|cluster-baseline|summarize} ...",
              file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "capture":
        return _cli_capture(rest) or 0
    if cmd == "cluster-baseline":
        return _cli_cluster_baseline(rest) or 0
    if cmd == "summarize":
        return _cli_summarize(rest) or 0
    print("unknown subcommand: " + cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) or 0)
