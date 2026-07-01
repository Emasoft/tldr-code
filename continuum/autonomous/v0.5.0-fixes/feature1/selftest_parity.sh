#!/usr/bin/env bash
# FEATURE-1 -- prove the parity gate has TEETH for EVERY rule.
#
# A gate that cannot fail is worthless; a gate whose INDIVIDUAL rules cannot
# fail is worthless per-rule. This harness injects exactly ONE synthetic defect
# per case and asserts the gate reacts correctly. All logic lives in the Python
# driver selftest_cases.py (JSON mutation + subprocess assertions); this wrapper
# runs it and prints the human-readable verdict.
#
# Cases (see selftest_cases.py):
#   clean                       0-delta current-vs-own-baseline        -> PASS
#   a  unique-name flip                                                -> FAIL
#   b  un-allowlisted ADDED edge                                       -> FAIL
#   c  positive-control regression                                     -> FAIL
#   d  NON-unique-name flip                                            -> FAIL
#   e  un-allowlisted REMOVED edge                                     -> FAIL
#   f  binary EMPTY calls output (status != ok)                        -> FAIL
#   f_crash  binary CRASH (exit != 0)                                  -> FAIL
#   g  UNEXPECTED missing baseline (non-excluded repo)                 -> FAIL
#   g_excluded  intentionally-excluded repo skipped cleanly            -> PASS
#   h  owner-flip at an ALLOWLISTED call-site (dst_file mutated)       -> FAIL
#   h_ok  correctly owner-pinned allowlist entry accepted              -> PASS
#
# Bash 3.2 compatible. Usage: bash selftest_parity.sh [repo]
# Env overrides: TLDR_BIN, TLDR_CORPORA, TLDR_SELFTEST_REPO.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
BINARY="${TLDR_BIN:-/Users/cosimo/.cargo/bin/tldr}"
CORPORA="${TLDR_CORPORA:-/Users/cosimo/.tldr-audit/corpora}"
REPO="${1:-${TLDR_SELFTEST_REPO:-c-sds}}"

export TLDR_BIN="$BINARY"
export TLDR_CORPORA="$CORPORA"
export TLDR_SELFTEST_REPO="$REPO"
export TLDR_NO_DAEMON=1

echo "=============================================================="
echo "FEATURE-1 parity gate self-test (per-rule teeth)   repo=$REPO"
echo "=============================================================="
python3 "$HERE/selftest_cases.py"
RC=$?

echo
echo "=============================================================="
if [ "$RC" -eq 0 ]; then
  echo "SELFTEST: PASS (every rule has teeth; clean + positive cases pass)"
else
  echo "SELFTEST: FAIL (a rule did not react as required -- see cases above)"
fi
echo "=============================================================="
exit "$RC"
