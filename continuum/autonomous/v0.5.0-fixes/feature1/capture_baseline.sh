#!/usr/bin/env bash
# FEATURE-1 d.0 -- capture the NAME-MATCH baseline from the reference binary.
#
# For each corpus repo: run `tldr calls` 3x, keep the STABLE INTERSECTION of the
# normalized edge set, write the full snapshot to the OUT-OF-REPO baseline dir,
# and record counts + sha + provenance in the committed compact summary.
# Genuinely nondeterministic repos are EXCLUDED (never gated on) and logged.
# Also captures the cluster goldens to <baseline>/cluster/ and the cluster
# baseline status.
#
# Bash 3.2 compatible (no associative arrays). Idempotent: re-run to refresh.
#
# Usage: bash capture_baseline.sh
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
LIB="$HERE/parity_lib.py"
GOLDENS="$HERE/cluster_goldens.json"

BINARY="${TLDR_BIN:-/Users/cosimo/.cargo/bin/tldr}"
CORPORA="${TLDR_CORPORA:-/Users/cosimo/.tldr-audit/corpora}"
BASELINE_DIR="${TLDR_BASELINE_DIR:-/Users/cosimo/.tldr-audit/feature1-baseline}"
RUNS="${TLDR_RUNS:-3}"
TIMEOUT="${TLDR_TIMEOUT:-90}"

mkdir -p "$BASELINE_DIR/cluster"

# All 38 corpus repos (the gate universe).
REPOS="c-redis c-sds cpp-fmt cpp-tinyxml2 csharp-newtonsoft-bson csharp-newtonsoft-json \
elixir-phoenix elixir-plug go-gin go-httprouter java-petclinic java-retrofit \
js-express js-lodash kotlin-coroutines kotlin-datetime lua-lsp lua-luvit luau \
luau-roact ocaml-dune ocaml-lwt php-guzzle php-symfony-console python-flask \
python-requests ruby-rubocop ruby-sinatra rust-clap rust-ripgrep scala-cats-effect \
scala-zio solidity-openzeppelin solidity-solmate swift-alamofire swift-collections \
typescript-axios typescript-nest"

# Generic representative-subdir fallbacks tried (in order) only if the whole-repo
# run TIMES OUT. Nonexistent dirs are skipped by parity_lib. Quote everything.
fallbacks_for() {
  repo="$1"
  base="$CORPORA/$repo"
  echo "$base/src,$base/lib,$base/Src,$base/Sources,$base/source,$base/core,$base/packages,$base/deps,$base/app"
}

echo "== FEATURE-1 baseline capture =="
echo "binary=$BINARY corpora=$CORPORA out=$BASELINE_DIR runs=$RUNS timeout=$TIMEOUT"
echo

for repo in $REPOS; do
  primary="$CORPORA/$repo"
  if [ ! -d "$primary" ]; then
    echo "SKIP  $repo (missing dir)"
    continue
  fi
  out="$BASELINE_DIR/$repo.calls.json"
  fbs="$(fallbacks_for "$repo")"
  printf '%-26s ' "$repo"
  python3 "$LIB" capture \
    --binary "$BINARY" \
    --path "$primary" \
    --root "$primary" \
    --fallbacks "$fbs" \
    --runs "$RUNS" \
    --timeout "$TIMEOUT" \
    --out "$out"
done

echo
echo "== cluster goldens baseline (raw -> $BASELINE_DIR/cluster) =="
python3 "$LIB" cluster-baseline \
  --binary "$BINARY" \
  --root "$CORPORA" \
  --goldens "$GOLDENS" \
  --raw-dir "$BASELINE_DIR/cluster" \
  --out "$BASELINE_DIR/cluster_baseline_status.json" \
  --timeout "$TIMEOUT" > "$BASELINE_DIR/cluster_baseline_status.compact.json"
echo "wrote $BASELINE_DIR/cluster_baseline_status.json"

echo
echo "== committed compact summary -> $HERE/baseline_summary.json =="
REPOS_CSV="$(echo $REPOS | tr ' ' ',')"
python3 "$LIB" summarize \
  --baseline-dir "$BASELINE_DIR" \
  --repos "$REPOS_CSV" \
  --root "$CORPORA" \
  --reference "$($BINARY --version 2>/dev/null || echo tldr)" \
  --out "$HERE/baseline_summary.json"

echo
echo "DONE. Baseline snapshot in $BASELINE_DIR ; committed summary in $HERE/baseline_summary.json"
