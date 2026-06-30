#!/usr/bin/env bash
# FEATURE-1 d.0 -- prove the parity gate has TEETH.
#
#  (i)  PASS path: the comparator passes the current binary against its OWN
#       baseline (re-run -> 0 unexpected deltas, PARITY: PASS, exit 0).
#  (ii) FAIL path: inject ONE synthetic flip into a COPY of the baseline -- mutate
#       one edge whose callee NAME is UNIQUE so it resolves to a different file --
#       and confirm the comparator reports PARITY: FAIL with
#       flips_on_unique_name >= 1 (exit non-zero).
#
# A gate that cannot fail is worthless; both conditions are mandatory.
# Bash 3.2 compatible. Usage: bash selftest_parity.sh [repo]
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
BINARY="${TLDR_BIN:-/Users/cosimo/.cargo/bin/tldr}"
CORPORA="${TLDR_CORPORA:-/Users/cosimo/.tldr-audit/corpora}"
BASELINE_DIR="${TLDR_BASELINE_DIR:-/Users/cosimo/.tldr-audit/feature1-baseline}"
SUMMARY="$HERE/baseline_summary.json"
REPO="${1:-c-sds}"   # small, deterministic repo for a fast, reliable proof

if [ ! -f "$BASELINE_DIR/$REPO.calls.json" ]; then
  echo "SELFTEST ERROR: no baseline for $REPO (run capture_baseline.sh first)" >&2
  exit 3
fi

PASS_I=0
PASS_II=0

echo "=============================================================="
echo "SELFTEST (i): current-vs-own-baseline MUST PASS    repo=$REPO"
echo "=============================================================="
python3 "$HERE/check_parity.py" \
  --binary "$BINARY" --baseline-dir "$BASELINE_DIR" --root "$CORPORA" \
  --summary "$SUMMARY" --repos "$REPO" --runs 3 --no-cluster
RC_I=$?
echo "exit=$RC_I"
if [ "$RC_I" -eq 0 ]; then PASS_I=1; fi

echo
echo "=============================================================="
echo "SELFTEST (ii): injected unique-name flip MUST FAIL  repo=$REPO"
echo "=============================================================="
MUT="$(mktemp -d /tmp/feature1_selftest.XXXXXX)"
cp "$BASELINE_DIR/$REPO.calls.json" "$MUT/$REPO.calls.json"

# Mutate one edge whose dst_func is UNIQUE -> point it at a different existing
# file. This is a flip on a unique baseline callee name == regression.
python3 - "$MUT/$REPO.calls.json" <<'PYEOF'
import json, sys, collections
path = sys.argv[1]
doc = json.load(open(path))
edges = doc["stable"]
files = sorted({df for _sf, _sfn, df, _dfunc in edges if df != "<external>"})
# Pick a callee NAME that occurs in EXACTLY ONE edge and is defined in exactly
# one file. Re-pointing that single edge to a different existing file keeps the
# name's definition-cardinality at 1 (still UNIQUE) -> a textbook rule-(a) flip.
edge_count = collections.Counter(dfunc for _sf, _sfn, _df, dfunc in edges)
def_files = collections.defaultdict(set)
for _sf, _sfn, df, dfunc in edges:
    if df != "<external>":
        def_files[dfunc].add(df)
chosen = None
for i, (sf, sfn, df, dfunc) in enumerate(edges):
    if df == "<external>":
        continue
    if edge_count[dfunc] != 1 or len(def_files[dfunc]) != 1:
        continue
    alt = [f for f in files if f != df]
    if not alt:
        continue
    edges[i] = [sf, sfn, alt[0], dfunc]   # FLIP: same UNIQUE name, new file
    chosen = (sf, sfn, df, dfunc, alt[0])
    break
if chosen is None:
    print("MUTATE_ERROR: no once-occurring unique-name edge to flip", file=sys.stderr)
    raise SystemExit(5)
doc["stable"] = edges
json.dump(doc, open(path, "w"))
print("INJECTED flip: %s::%s -> %s  was@%s now@%s" %
      (chosen[0], chosen[1], chosen[3], chosen[2], chosen[4]))
PYEOF

python3 "$HERE/check_parity.py" \
  --binary "$BINARY" --baseline-dir "$MUT" --root "$CORPORA" \
  --summary "$SUMMARY" --repos "$REPO" --runs 3 --no-cluster \
  --json-out "$MUT/verdict.json"
RC_II=$?
echo "exit=$RC_II"
FLIPS=$(python3 -c "import json;print(json.load(open('$MUT/verdict.json'))['counts']['flips_on_unique_name'])" 2>/dev/null || echo 0)
echo "flips_on_unique_name=$FLIPS"
if [ "$RC_II" -ne 0 ] && [ "$FLIPS" -ge 1 ]; then PASS_II=1; fi

rm -rf "$MUT"

echo
echo "=============================================================="
echo "SELFTEST RESULT"
echo "  (i)  current-vs-own-baseline PASS : $([ $PASS_I -eq 1 ] && echo OK || echo FAILED)"
echo "  (ii) injected-flip caught (FAIL)  : $([ $PASS_II -eq 1 ] && echo OK || echo FAILED)"
if [ "$PASS_I" -eq 1 ] && [ "$PASS_II" -eq 1 ]; then
  echo "SELFTEST: PASS (the gate has teeth)"
  exit 0
fi
echo "SELFTEST: FAIL"
exit 1
