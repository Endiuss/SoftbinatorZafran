#!/usr/bin/env bash
set -euo pipefail

# =========================
# EDIT THESE 3 VALUES
# =========================
API_URL="https://api.us-2.crowdstrike.com"
API_KEY="API_KEY"
API_SECRET="API_SECRET"


# -------------------------
# Derived runner params
# -------------------------
PARAMS="api_url=${API_URL},api_key=${API_KEY},api_secret=${API_SECRET}"

OUTDIR="./output"
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

SCRIPT="./dev/crowdstrike.star"
RUNNER="./starlark-runner-linux"

echo "Starting CrowdStrike integration..."
echo "API URL : ${API_URL}"
echo "Script  : ${SCRIPT}"
echo "Runner  : ${RUNNER}"
echo "Output  : ${OUTDIR}"
echo "TS      : ${TS}"

# IMPORTANT: runner prefixes log lines, so match tokens ANYWHERE in the line (not ^EXPORT_...)
"${RUNNER}" -script "${SCRIPT}" -params "${PARAMS}" 2>&1 \
  | tee -a "${RUNLOG}" \
  | awk -v devf="${DEVF}" -v vulnf="${VULNF}" -v unmapf="${UNMAPF}" '
      function write_after_token(line, token, file,   pos, jsonstr) {
        pos = index(line, token " ")
        if (pos > 0) {
          jsonstr = substr(line, pos + length(token) + 1)
          print jsonstr >> file
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
