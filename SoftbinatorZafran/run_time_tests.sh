#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# Time filter test runner for Zafran CrowdStrike integration
# ------------------------------------------------------------------------------

ROOT_DIR="$(pwd)"
START_SH="${ROOT_DIR}/start.sh"
OUT_DIR="${ROOT_DIR}/output"
TEST_ROOT="${ROOT_DIR}/test_runs_time_$(date +%Y%m%d_%H%M%S)"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: missing required command: $1" >&2
    exit 1
  }
}

require_cmd jq
require_cmd sort
require_cmd comm
require_cmd wc
require_cmd cp
require_cmd mkdir
require_cmd ls
require_cmd date

if [[ ! -x "${START_SH}" ]]; then
  echo "ERROR: ${START_SH} not found or not executable. Run: chmod +x ./start.sh" >&2
  exit 1
fi

if [[ ! -d "${OUT_DIR}" ]]; then
  echo "ERROR: ${OUT_DIR} not found. Your start.sh should write into ./output/." >&2
  exit 1
fi

mkdir -p "${TEST_ROOT}"

# Return newest matching file in ./output using safe globbing
latest_output_file() {
  local pattern="$1"
  local matches=()

  # Expand pattern safely
  # shellcheck disable=SC2206
  matches=( ${OUT_DIR}/${pattern} )

  if [[ ${#matches[@]} -eq 0 ]]; then
    echo ""
    return 0
  fi

  # Sort by mtime desc and return first
  # shellcheck disable=SC2012
  ls -1t ${OUT_DIR}/${pattern} 2>/dev/null | head -n 1 || true
}

snapshot_outputs() {
  local dest_dir="$1"

  local devices_file
  local vulns_file
  local runlog_file

  devices_file="$(latest_output_file 'devices_*.ndjson')"
  vulns_file="$(latest_output_file 'vulns_*.ndjson')"
  runlog_file="$(latest_output_file 'run_*.log')"

  if [[ -z "${devices_file}" || -z "${vulns_file}" || -z "${runlog_file}" ]]; then
    echo "ERROR: Could not find expected output files in ${OUT_DIR} after run." >&2
    echo "Expected: devices_*.ndjson, vulns_*.ndjson, run_*.log" >&2
    echo "DEBUG: newest files in ${OUT_DIR}:" >&2
    # shellcheck disable=SC2012
    ls -1t "${OUT_DIR}" | head -n 20 >&2 || true
    exit 1
  fi

  cp -f "${devices_file}" "${dest_dir}/devices.ndjson"
  cp -f "${vulns_file}"   "${dest_dir}/vulns.ndjson"
  cp -f "${runlog_file}"  "${dest_dir}/run.log"
}

run_test() {
  local name="$1"; shift
  local dir="${TEST_ROOT}/${name}"
  mkdir -p "${dir}"

  {
    echo "=== TEST: ${name} ==="
    echo "Timestamp: $(date -Iseconds)"
    echo "Command: ${START_SH} $*"
    echo
  } | tee "${dir}/command.txt"

  "${START_SH}" "$@" 2>&1 | tee "${dir}/stdout_stderr.txt"

  snapshot_outputs "${dir}"

  {
    echo "devices lines: $(wc -l < "${dir}/devices.ndjson")"
    echo "vulns   lines: $(wc -l < "${dir}/vulns.ndjson")"
  } | tee "${dir}/counts.txt"

  echo "OK: ${name} completed. Artifacts in: ${dir}"
}

extract_keyset() {
  local vulns_file="$1"
  jq -r '.instance_id + "|" + .cve' "${vulns_file}" | sort -u
}

subset_check() {
  local a_file="$1"
  local b_file="$2"
  local out_file="$3"

  local diff
  diff="$(comm -23 "${a_file}" "${b_file}" || true)"
  if [[ -n "${diff}" ]]; then
    {
      echo "FAIL: subset check failed (A has elements not in B)"
      echo "A: ${a_file}"
      echo "B: ${b_file}"
      echo
      echo "Examples (up to 50):"
      echo "${diff}" | head -n 50
    } | tee "${out_file}"
    return 1
  fi

  echo "PASS: subset check OK (A ⊆ B)" | tee "${out_file}"
  return 0
}

# ------------------------------------------------------------------------------
# Run time tests
# ------------------------------------------------------------------------------

run_test "T1_now_1d"  --device-filter "platform_name:'Windows'" --vuln-filter "updated_timestamp:>'now-1d'"
run_test "T1_now_7d"  --device-filter "platform_name:'Windows'" --vuln-filter "updated_timestamp:>'now-7d'"
run_test "T1_now_30d" --device-filter "platform_name:'Windows'" --vuln-filter "updated_timestamp:>'now-30d'"

extract_keyset "${TEST_ROOT}/T1_now_1d/vulns.ndjson"  > "${TEST_ROOT}/T1_now_1d.keys"
extract_keyset "${TEST_ROOT}/T1_now_7d/vulns.ndjson"  > "${TEST_ROOT}/T1_now_7d.keys"
extract_keyset "${TEST_ROOT}/T1_now_30d/vulns.ndjson" > "${TEST_ROOT}/T1_now_30d.keys"

subset_check "${TEST_ROOT}/T1_now_1d.keys" "${TEST_ROOT}/T1_now_7d.keys"  "${TEST_ROOT}/T1_subset_1d_in_7d.txt"
subset_check "${TEST_ROOT}/T1_now_7d.keys" "${TEST_ROOT}/T1_now_30d.keys" "${TEST_ROOT}/T1_subset_7d_in_30d.txt"

run_test "T2_now_7d_to_1d" --device-filter "platform_name:'Windows'" --vuln-filter "updated_timestamp:>'now-7d'+updated_timestamp<'now-1d'"

extract_keyset "${TEST_ROOT}/T2_now_7d_to_1d/vulns.ndjson" > "${TEST_ROOT}/T2_now_7d_to_1d.keys"
subset_check "${TEST_ROOT}/T2_now_7d_to_1d.keys" "${TEST_ROOT}/T1_now_7d.keys" "${TEST_ROOT}/T2_subset_7to1_in_7d.txt"

run_test "T3_future_now_plus_1d" --device-filter "platform_name:'Windows'" --vuln-filter "updated_timestamp:>'now+1d'"

v3_lines="$(wc -l < "${TEST_ROOT}/T3_future_now_plus_1d/vulns.ndjson")"
if [[ "${v3_lines}" -ne 0 ]]; then
  {
    echo "FAIL: T3 expected 0 vulns, got ${v3_lines}"
    echo "See: ${TEST_ROOT}/T3_future_now_plus_1d/vulns.ndjson"
  } | tee "${TEST_ROOT}/T3_future_expected_empty.txt"
else
  echo "PASS: T3 future window produced 0 vulns" | tee "${TEST_ROOT}/T3_future_expected_empty.txt"
fi

run_test "T4_updated_now_7d" --device-filter "platform_name:'Windows'" --vuln-filter "updated_timestamp:>'now-7d'"
run_test "T4_created_now_7d" --device-filter "platform_name:'Windows'" --vuln-filter "created_timestamp:>'now-7d'"

c_updated="$(wc -l < "${TEST_ROOT}/T4_updated_now_7d/vulns.ndjson")"
c_created="$(wc -l < "${TEST_ROOT}/T4_created_now_7d/vulns.ndjson")"
{
  echo "updated(now-7d) lines: ${c_updated}"
  echo "created(now-7d) lines: ${c_created}"
  if [[ "${c_updated}" -ne "${c_created}" ]]; then
    echo "PASS: counts differ (field is honored / behavior differs)"
  else
    echo "NOTE: counts equal (still possible, but less informative)"
  fi
} | tee "${TEST_ROOT}/T4_created_vs_updated_counts.txt"

echo
echo "============================================================"
echo "All tests completed. Root folder:"
echo "  ${TEST_ROOT}"
echo "Key PASS/FAIL summaries:"
echo "  ${TEST_ROOT}/T1_subset_1d_in_7d.txt"
echo "  ${TEST_ROOT}/T1_subset_7d_in_30d.txt"
echo "  ${TEST_ROOT}/T2_subset_7to1_in_7d.txt"
echo "  ${TEST_ROOT}/T3_future_expected_empty.txt"
echo "  ${TEST_ROOT}/T4_created_vs_updated_counts.txt"
echo "============================================================"
