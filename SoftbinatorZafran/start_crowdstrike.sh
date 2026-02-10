#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# start_crowdstrike.sh — runner wrapper (CrowdStrike)
#
# Responsibilities:
#  - Run the CrowdStrike Starlark integration using the local starlark runner
#  - Log all output to ./output/run_<timestamp>.log
#  - Extract NDJSON exports from tokenized stdout lines into files:
#       EXPORT_DEVICE_JSON <json>
#       EXPORT_VULN_JSON   <json>
#       UNMAPPED_VULN_JSON <json>
#
# Param forwarding:
#  - Base params are: api_url, api_key, api_secret
#  - If EXTRA_PARAMS is set (from start.sh), append it as comma-delimited k=v pairs
#
# IMPORTANT CONSTRAINT:
#  - Runner parses -params as a single comma-delimited string "k=v,k=v"
#  - Therefore values MUST NOT contain commas.
#  - start.sh escapes FQL commas as "__OR__"; crowdstrike.star must decode them.
# ==============================================================================

# -------------------------
# Configurable paths
# -------------------------
OUTDIR="${OUTDIR:-./output}"
SCRIPT="${SCRIPT:-./dev/crowdstrike.star}"
RUNNER="${RUNNER:-./starlark-runner-linux}"

# -------------------------
# Required credentials / API URL
# -------------------------
API_URL="${API_URL:-https://api.us-2.crowdstrike.com}"
API_KEY="${API_KEY:-}"
API_SECRET="${API_SECRET:-}"

if [[ -z "${API_KEY}" || -z "${API_SECRET}" ]]; then
  echo "ERROR: API_KEY and API_SECRET must be set (env vars), or run via ./start.sh." >&2
  exit 2
fi

# -------------------------
# Validate required files exist
# -------------------------
if [[ ! -f "${SCRIPT}" ]]; then
  echo "ERROR: Starlark script not found: ${SCRIPT}" >&2
  exit 2
fi

if [[ ! -x "${RUNNER}" ]]; then
  echo "ERROR: Runner not found or not executable: ${RUNNER}" >&2
  echo "Hint: set RUNNER=... or chmod +x ${RUNNER}" >&2
  exit 2
fi

# -------------------------
# Build params string
# -------------------------
PARAMS="api_url=${API_URL},api_key=${API_KEY},api_secret=${API_SECRET}"

# Append forwarded filter params (from start.sh)
if [[ -n "${EXTRA_PARAMS:-}" ]]; then
  PARAMS="${PARAMS},${EXTRA_PARAMS}"
fi

# -------------------------
# Output files
# -------------------------
mkdir -p "${OUTDIR}"
TS="$(date +%Y%m%d_%H%M%S)"

RUNLOG="${OUTDIR}/run_${TS}.log"
DEVF="${OUTDIR}/devices_${TS}.ndjson"
VULNF="${OUTDIR}/vulns_${TS}.ndjson"
UNMAPF="${OUTDIR}/unmapped_vulns_${TS}.ndjson"

: > "${RUNLOG}"
: > "${DEVF}"
: > "${VULNF}"
: > "${UNMAPF}"

# -------------------------
# Header
# -------------------------
echo "Starting integration..."
echo "API URL : ${API_URL}"
echo "Script  : ${SCRIPT}"
echo "Runner  : ${RUNNER}"
echo "Logs    : ${RUNLOG}"
echo "Devices : ${DEVF}"
echo "Vulns   : ${VULNF}"
echo "Unmapped: ${UNMAPF}"
echo "Params  : ${PARAMS}"

# -------------------------
# Run and export tokens to files
# -------------------------
# The runner prefixes output, so match tokens anywhere in the line.
# Write JSON payload after the token + space into corresponding NDJSON file.
#
# Example lines:
#   [Starlark Script] "EXPORT_DEVICE_JSON {...}"
#   [Starlark Script] "EXPORT_VULN_JSON {...}"
#   [Starlark Script] "UNMAPPED_VULN_JSON {...}"
#
# We do NOT attempt to parse JSON here; we just append raw lines after the token.
"${RUNNER}" -script "${SCRIPT}" -params "${PARAMS}" 2>&1 \
  | tee -a "${RUNLOG}" \
  | awk -v devf="${DEVF}" -v vulnf="${VULNF}" -v unmapf="${UNMAPF}" '
      function write_after_token(line, token, file,   pos, payload) {
        pos = index(line, token " ")
        if (pos > 0) {
          payload = substr(line, pos + length(token) + 1)
          print payload >> file
        }
      }
      {
        write_after_token($0, "EXPORT_DEVICE_JSON", devf)
        write_after_token($0, "EXPORT_VULN_JSON", vulnf)
        write_after_token($0, "UNMAPPED_VULN_JSON", unmapf)
      }
    '

echo "Done."
echo "Log      : ${RUNLOG}"
echo "Devices  : ${DEVF}"
echo "Vulns    : ${VULNF}"
echo "Unmapped : ${UNMAPF}"
