#!/bin/bash
# canary_smoke_gate.sh — FAST cross-language leak detector for a language-isolated fix.
#
# Runs the parity gate on ONLY: the fix's declared target-language repos + a fixed set of
# cross-language CANARIES. Any delta on a canary = the fix leaked past its declared language
# (a shared-mechanism / shape-heuristic bug, e.g. the reverted W2-29). Abort BEFORE the full 8-min gate.
#
# The canary set is deliberately the three languages the reverted subtractive W2-29 broke —
# rust (Clone.clone), kotlin (DispatchedTask.run), cpp (capacity) — plus python (the usual
# shape-heuristic false-positive source). These are the highest-signal tripwires for the
# is_python_style / PYTHON_BUILTINS bug class.
#
# Usage:
#   bash canary_smoke_gate.sh "<target-repo csv>"
# Example (a lua-only fix):
#   bash canary_smoke_gate.sh "lua-lsp,lua-luvit,luau,luau-roact"
#
# Requires the CURRENT binary already built+codesigned+installed (run gate_one_fix.sh's build first,
# or build+sign+install manually). Reads the same baseline + allowlist as the full gate.
set -o pipefail
cd /Users/cosimo/Desktop/PatchWork/tldr-code || exit 99
F1=continuum/autonomous/v0.5.0-fixes/feature1
TARGETS="${1:?usage: canary_smoke_gate.sh \"<target-repo csv>\"}"
CANARIES="rust-clap,kotlin-coroutines,cpp-fmt,python-flask"

REPOS="$TARGETS,$CANARIES"
echo "=== CANARY SMOKE-GATE ==="
echo "targets:  $TARGETS"
echo "canaries: $CANARIES  (ANY delta here = cross-language leak -> ABORT)"
echo

python3 "$F1/check_parity.py" \
  --binary ~/.cargo/bin/tldr \
  --baseline-dir ~/.tldr-audit/feature1-baseline \
  --root ~/.tldr-audit/corpora \
  --summary "$F1/baseline_summary.json" \
  --allow "$F1/expected_deltas.json" \
  --repos "$REPOS" 2>&1 | tail -8

echo "=== DONE (if PARITY:PASS the fix is isolated so far; still run the FULL gate before commit) ==="
