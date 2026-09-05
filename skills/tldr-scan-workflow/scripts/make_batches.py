#!/usr/bin/env python3
"""Deterministic line-budgeted batch planner for the tldr scan-and-fix workflow.

Reads a list of source files (stdin, or --list FILE), packs them into batches of
about --target lines, and writes one `<id>.txt` per batch plus an `index.json`,
in the exact shape `references/workflow.js` and the scan prompt expect:

    <out-dir>/b001.txt      one line per file: "<line count>\\t<absolute path>"
    <out-dir>/index.json    [{"id": "b001", "kind": "src", "lines": N, "nfiles": M}, ...]

Source batches are `bNNN`, test batches `tNNN`, so the workflow can run the test
batches as their own suite-gated wave.

Deterministic: the input list is sorted (unless --no-sort) and packed greedily,
so the same list always yields the same plan. Feed it a ranked list plus
--no-sort to scan hotspots first (`tldr hotspots <dir>`).

Gitignored files are excluded by construction when the list comes from
`git ls-files`; fixtures, docs and vendored trees are excluded with --exclude.

Example:

    git -C <repo> ls-files 'crates/*.rs' \\
      | uv run --quiet python3 make_batches.py --repo-root <repo> --out-dir <dir>

stdlib only; runs under `uv run` or a bare python3.
"""

import argparse
import fnmatch
import json
import os
import sys

DEFAULT_EXCLUDES = [
    "*/fixtures/*",
    "*/testdata/*",
    "*/vendor/*",
    "*/third_party/*",
    "*/node_modules/*",
    "target/*",
    "docs/*",
]
DEFAULT_TEST_GLOBS = ["*/tests/*"]


def count_lines(path):
    """Line count of one file. Fail fast: a listed file that is not there is a
    stale list, and silently dropping it would silently shrink the scan."""
    with open(path, "rb") as fh:
        data = fh.read()
    if not data:
        return 0
    return data.count(b"\n") + (0 if data.endswith(b"\n") else 1)


def pack(items, target):
    """Greedily pack (path, lines) pairs into batches of about `target` lines.

    A file at or above `target` gets a batch to itself — splitting one file
    across workers would give each an incomplete picture of it, which is the
    one thing the read-once-fix-in-place pass cannot recover from.
    """
    batches, cur, cur_lines = [], [], 0
    for path, lines in items:
        if cur and cur_lines + lines > target:
            batches.append(cur)
            cur, cur_lines = [], 0
        if lines >= target and not cur:
            batches.append([(path, lines)])
            continue
        cur.append((path, lines))
        cur_lines += lines
    if cur:
        batches.append(cur)
    return batches


def classify(rel, test_globs):
    return "test" if any(fnmatch.fnmatch(rel, g) for g in test_globs) else "src"


def plan(rel_paths, repo_root, target, excludes, test_globs, do_sort):
    kept = [p for p in rel_paths if not any(fnmatch.fnmatch(p, g) for g in excludes)]
    if do_sort:
        kept.sort()
    groups = {"src": [], "test": []}
    for rel in kept:
        abs_path = os.path.join(repo_root, rel)
        groups[classify(rel, test_globs)].append((abs_path, count_lines(abs_path)))

    out = []
    for kind, prefix in (("src", "b"), ("test", "t")):
        for i, batch in enumerate(pack(groups[kind], target), start=1):
            out.append(
                {
                    "id": "%s%03d" % (prefix, i),
                    "kind": kind,
                    "lines": sum(n for _, n in batch),
                    "nfiles": len(batch),
                    "files": batch,
                }
            )
    return out


def write_plan(batches, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    index = []
    for b in batches:
        with open(os.path.join(out_dir, b["id"] + ".txt"), "w", encoding="utf-8") as fh:
            for path, lines in b["files"]:
                fh.write("%d\t%s\n" % (lines, path))
        index.append({k: b[k] for k in ("id", "kind", "lines", "nfiles")})
    index_path = os.path.join(out_dir, "index.json")
    with open(index_path, "w", encoding="utf-8") as fh:
        json.dump(index, fh)
    return index, index_path


def self_check():
    b = pack([("a", 1000), ("b", 1000), ("c", 1500)], 3000)
    assert [len(x) for x in b] == [2, 1], b
    b = pack([("big", 5000), ("small", 100)], 3000)
    assert b == [[("big", 5000)], [("small", 100)]], b
    b = pack([("small", 100), ("big", 5000)], 3000)
    assert [len(x) for x in b] == [1, 1], b
    assert classify("crates/x/tests/a.rs", DEFAULT_TEST_GLOBS) == "test"
    assert classify("crates/x/src/a.rs", DEFAULT_TEST_GLOBS) == "src"
    print("self-check ok")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Plan deterministic ~N-line scan batches for the tldr scan-and-fix workflow.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Batch files hold '<lines>\\t<absolute path>' rows; index.json is the batch plan.",
    )
    ap.add_argument("--repo-root", default=".", help="repo root the listed paths are relative to (default: cwd)")
    ap.add_argument("--list", help="file holding the file list, one path per line (default: stdin)")
    ap.add_argument("--out-dir", help="directory to write <id>.txt and index.json into")
    ap.add_argument("--target", type=int, default=3000, help="target lines per batch (default: 3000)")
    ap.add_argument("--exclude", action="append", metavar="GLOB",
                    help="exclude paths matching GLOB (repeatable; replaces the defaults: %s)" % " ".join(DEFAULT_EXCLUDES))
    ap.add_argument("--test-glob", action="append", metavar="GLOB",
                    help="paths matching GLOB become 't' batches (repeatable; default: %s)" % " ".join(DEFAULT_TEST_GLOBS))
    ap.add_argument("--no-sort", action="store_true", help="keep the input order (use with a hotspot-ranked list)")
    ap.add_argument("--self-check", action="store_true", help="run the packer's assertions and exit")
    a = ap.parse_args(argv)

    if a.self_check:
        self_check()
        return 0
    if not a.out_dir:
        ap.error("--out-dir is required (or pass --self-check)")

    src = open(a.list, encoding="utf-8") if a.list else sys.stdin
    try:
        rel_paths = [ln.strip() for ln in src if ln.strip()]
    finally:
        if a.list:
            src.close()
    if not rel_paths:
        ap.error("empty file list")

    repo_root = os.path.abspath(a.repo_root)
    batches = plan(
        rel_paths,
        repo_root,
        a.target,
        a.exclude or DEFAULT_EXCLUDES,
        a.test_glob or DEFAULT_TEST_GLOBS,
        not a.no_sort,
    )
    index, index_path = write_plan(batches, a.out_dir)
    n_src = sum(1 for b in index if b["kind"] == "src")
    print("%d batches (%d src, %d test), %d files, %d lines -> %s"
          % (len(index), n_src, len(index) - n_src,
             sum(b["nfiles"] for b in index), sum(b["lines"] for b in index), index_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
