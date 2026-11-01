#!/bin/bash
# Run from the repository root: run-suite.sh <self-hosted: true|false> [INDEX/TOTAL]
# Keep the existing shard strategy, one retry, <=8 failed files and load wait.
# Force Node's TAP reporter; parse-suite-log.mjs validates completion on BOTH runs.
# Both runs go through test/support/bounded-run.mjs (the launcher's test action, and the retry directly): a hang is killed at
# its bound with status 124, which this script never reruns.
set -u
self_hosted=${1:-false}
shard=${2:-}
if [ "$#" -gt 2 ] || { [ "$self_hosted" != true ] && [ "$self_hosted" != false ]; }; then
  echo '::error::usage: run-suite.sh <true|false> [INDEX/TOTAL]'; exit 2
fi
shard_args=()
if [ -n "$shard" ]; then
  # Decimal, no leading zero, 1 <= INDEX <= TOTAL <= 99 (the existing total bound).
  if [[ ! "$shard" =~ ^([1-9][0-9]?)/([1-9][0-9]?)$ ]] ||
     [ "${BASH_REMATCH[1]:-100}" -gt "${BASH_REMATCH[2]:-0}" ]; then
    echo "::error::bad shard '$shard' (want 1 <= INDEX <= TOTAL <= 99)"; exit 2
  fi
  shard_args=(--test-shard="$shard")
  echo "shard $shard"
fi

# Mirror only the launcher's (./scopehaven) executable-selection order and runnable
# probe. The launcher remains the authority for its supported version range.
# Pin this selection in SCOPEHAVEN_NODE so the launcher and retry cannot diverge.
version_of() {
  [ -n "$1" ] && [ -f "$1" ] && [ -x "$1" ] || return 1
  "$1" -e 'process.stdout.write(process.versions.node)' 2>/dev/null
}
selected_node=''
if [ -n "${SCOPEHAVEN_NODE:-}" ]; then
  selected_node=$SCOPEHAVEN_NODE
else
  pinned_node="$PWD/.runtime/node-v24.22.2-darwin-arm64/bin/node"
  if [ -e "$pinned_node" ] && version_of "$pinned_node" >/dev/null; then
    selected_node=$pinned_node
  else
    selected_node=$(command -v node 2>/dev/null) || selected_node=''
  fi
fi
case $selected_node in /*) ;; '') ;; *) selected_node="$PWD/$selected_node" ;; esac
if ! version_of "$selected_node" >/dev/null; then
  echo "::error::selected Node runtime did not run: $selected_node"; exit 2
fi
export SCOPEHAVEN_NODE="$selected_node"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 2
scratch=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/suite.XXXXXX") || exit 2
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
log="$scratch/initial.log"
# The bounded runner appends a notice here, not to the log, when it stops processes a run left running; each becomes a warning.
notices="$scratch/notices"
export SCOPEHAVEN_TEST_NOTICES="$notices"
report_notices() {
  [ -s "$notices" ] || return 0
  while IFS= read -r line; do
    line=${line//%/%25}
    echo "::warning title=Processes left by the test run::$line"
  done < "$notices"
  : > "$notices"
}
load() { sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}'; }
wait_quiet() {
  for _ in $(seq 1 60); do
    awk -v l="$(load)" 'BEGIN { exit !(l < 30) }' && return 0
    sleep 20
  done
  return 1
}
run_attempt() {
  "$@" 2>&1 | tee "$log"
  # Save both immediately; a failed capture must never permit a retry or green.
  attempt_codes=("${PIPESTATUS[@]}")
  status=${attempt_codes[0]}
  capture_status=${attempt_codes[1]}
  report_notices
}
parse_attempt() {
  "$selected_node" "$script_dir/parse-suite-log.mjs" "$log" "$status" > "$scratch/files"
  parsed_status=$?
}
fail_status() {
  [ "$status" -ne 0 ] && exit "$status"
  exit 1
}
fail_capture() {
  echo '::error::test log capture failed'
  [ "$status" -ne 0 ] && exit "$status"
  exit "$capture_status"
}

[ "$self_hosted" = true ] && echo "load at start: $(load)"
# Empty-array expansion is safe under set -u in the laptop's Bash 3.2.
run_attempt ./scopehaven test --test-reporter=tap ${shard_args[@]+"${shard_args[@]}"}
first_load=$(load)
[ "$self_hosted" = true ] && echo "load at end: $first_load"
[ "$capture_status" -ne 0 ] && fail_capture
# 124: the run passed its wall-clock bound (test/support/bounded-run.mjs) and was killed as a hang. It stays red, never rerun.
if [ "$status" -eq 124 ]; then echo "::error::the test run passed its time bound and was killed as a hang; no rerun."; exit 124; fi
parse_attempt
[ "$parsed_status" -eq 0 ] && exit 0
[ "$parsed_status" -ne 10 ] && fail_status

files=()
while IFS= read -r f; do files+=("$f"); done < "$scratch/files"
if [ "${#files[@]}" -eq 0 ] || [ "${#files[@]}" -gt 8 ]; then
  echo "No rerun: ${#files[@]} failed test files named."; fail_status
fi
echo "Failed test files (${#files[@]}): ${files[*]}"
if [ "$self_hosted" = true ]; then
  wait_quiet || echo "::warning::1-minute load still $(load) after 20 minutes; rerunning anyway."
fi
rerun_load=$(load)
echo "Rerunning once at load $rerun_load"
log="$scratch/retry.log"
run_attempt "$selected_node" test/support/bounded-run.mjs --test-reporter=tap --test-concurrency=1 "${files[@]}"
[ "$capture_status" -ne 0 ] && fail_capture
parse_attempt
if [ "$parsed_status" -eq 0 ]; then
  echo "::warning title=Flaky test files::${files[*]} failed at 1-minute load $first_load and passed on one rerun at $rerun_load (self-hosted: $self_hosted). Treat as load-sensitive tests to fix, not as a pass to ignore."
  exit 0
fi
echo "::error::${files[*]} failed again or had incomplete evidence on the rerun at load $rerun_load."
fail_status
