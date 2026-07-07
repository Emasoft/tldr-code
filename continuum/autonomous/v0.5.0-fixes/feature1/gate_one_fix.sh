#!/bin/bash
# gate_one_fix.sh — the institutionalized ONE-FIX-ONE-GATE loop (precision-program-v1 iron rule).
#
# Runs the full orchestrator verification for a single uncommitted fix:
#   guard (only intended files changed) -> core+cli tests -> build -> codesign BOTH -> install -> parity gate
# Prints a single PASS/FAIL. Does NOT commit (orchestrator commits by hand after reading the verdict).
#
# Usage:
#   bash gate_one_fix.sh "<comma-separated allowed tracked files>" [--calls]
#     "<files>"  : exact `git diff --name-only` expected (guard fails on any other tracked change).
#     --calls    : (optional) also write full JSON verdict for a calls-touching fix to gate_verdict.json.
#
# Example:
#   bash gate_one_fix.sh "crates/tldr-core/src/inheritance/mod.rs"
#   bash gate_one_fix.sh "crates/tldr-core/src/callgraph/resolution.rs" --calls
#
# IRON RULE (calls-touching): PASS requires flips_on_unique_name==0 && removed_unreviewed==0.
# Restored-correct net-new edges are reviewed + allowlisted in expected_deltas.json BEFORE re-running.
set -o pipefail
cd /Users/cosimo/Desktop/PatchWork/tldr-code || exit 99
F1=continuum/autonomous/v0.5.0-fixes/feature1
ALLOWED="${1:?usage: gate_one_fix.sh \"<allowed tracked files csv>\" [--calls]}"
CALLS="${2:-}"

echo "=== GUARD: tracked diff must be exactly the intended file(s) ==="
CHANGED="$(git diff --name-only | paste -sd, -)"
echo "expected: $ALLOWED"
echo "actual:   $CHANGED"
if [ "$CHANGED" != "$ALLOWED" ]; then
  echo "GUARD_FAIL: unexpected tracked changes (fmt spillover? revert via git checkout-index)"; exit 10
fi
echo "GUARD_OK"

echo "=== core --lib ==="
env TLDR_NO_DAEMON=1 cargo test -p tldr-core --lib 2>&1 | tail -2 || { echo "CORE_TEST_FAIL"; exit 11; }
echo "=== cli --lib ==="
env TLDR_NO_DAEMON=1 cargo test -p tldr-cli --lib 2>&1 | tail -2 || { echo "CLI_TEST_FAIL"; exit 12; }

echo "=== build + codesign BOTH + install (macOS SIGKILLs unsigned) ==="
cargo build --release --bin tldr 2>&1 | tail -2 || { echo "BUILD_FAIL"; exit 1; }
codesign --force --sign - target/release/tldr || { echo "SIGN1_FAIL"; exit 2; }
cp target/release/tldr ~/.cargo/bin/tldr || { echo "COPY_FAIL"; exit 3; }
codesign --force --sign - ~/.cargo/bin/tldr || { echo "SIGN2_FAIL"; exit 4; }
echo "INSTALL_OK"

echo "=== parity gate (37-repo differential, never-worse) ==="
JSONOUT=""
[ "$CALLS" = "--calls" ] && JSONOUT="--json-out $F1/gate_verdict.json"
python3 "$F1/check_parity.py" \
  --binary ~/.cargo/bin/tldr \
  --baseline-dir ~/.tldr-audit/feature1-baseline \
  --root ~/.tldr-audit/corpora \
  --summary "$F1/baseline_summary.json" \
  --allow "$F1/expected_deltas.json" $JSONOUT 2>&1 | tail -8

echo "=== DONE ==="
