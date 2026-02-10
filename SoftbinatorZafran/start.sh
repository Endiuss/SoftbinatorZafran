#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# start.sh — user-facing launcher for CrowdStrike integration
#
# Goals:
#  - Expose ALL supported filters/knobs as shell variables (empty by default)
#  - Accept CLI overrides (human-readable; NO URL-encoding required)
#  - Forward ONLY non-empty params to start_crowdstrike.sh via EXTRA_PARAMS
#
# Critical constraint:
#  - Zafran runner parses -params as "k=v,k=v"
#  - Therefore commas inside values would break parsing
#  - FQL uses commas for OR → we escape commas in start.sh and restore in Starlark:
#      ","  => "__OR__"
#
# NOTE: You must implement _decode_fql() in crowdstrike.star:
#   def _decode_fql(s):
#       if not s:
#           return s
#       return s.replace("__OR__", ",")
# and apply it to device_filter/device_sort/vuln_filter/vuln_sort (and facets if used).
# ==============================================================================

# -----------------------
# REQUIRED (set these via env or flags)
# -----------------------
API_URL="${API_URL:-https://api.us-2.crowdstrike.com}"
API_KEY="${API_KEY:-}"
API_SECRET="${API_SECRET:-}"

# -----------------------
# OPTIONAL knobs (empty by default)
# -----------------------

# Devices (FQL)
DEVICE_FILTER="${DEVICE_FILTER:-}"         # e.g. "platform_name:'Windows',platform_name:'Linux'"
DEVICE_SORT="${DEVICE_SORT:-}"             # e.g. "last_seen.desc"
DEVICES_LIMIT="${DEVICES_LIMIT:-}"         # e.g. "5000"

# Vulnerabilities (FQL)
VULN_FILTER="${VULN_FILTER:-}"             # e.g. "updated_timestamp:>='now-15d'+updated_timestamp<'now'"
VULN_SORT="${VULN_SORT:-}"                 # e.g. "updated_timestamp.desc"
VULN_FACETS="${VULN_FACETS:-}"             # e.g. "cve,host_info,remediation" (commas will be escaped safely)
VULNS_LIMIT="${VULNS_LIMIT:-}"             # e.g. "500"
FLUSH_EVERY="${FLUSH_EVERY:-}"             # e.g. "250"
INCLUDE_UNMAPPED="${INCLUDE_UNMAPPED:-}"   # "true" / "false"

# -----------------------
# CLI parsing (no external deps)
# -----------------------
# Supported flags:
#   ./start.sh --api-url ... --api-key ... --api-secret ...
#             --device-filter "..." --device-sort "..." --devices-limit 5000
#             --vuln-filter "..." --vuln-sort "..." --vuln-facets "..."
#             --vulns-limit 500 --flush-every 250 --include-unmapped false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-url) API_URL="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    --api-secret) API_SECRET="$2"; shift 2 ;;

    --device-filter) DEVICE_FILTER="$2"; shift 2 ;;
    --device-sort) DEVICE_SORT="$2"; shift 2 ;;
    --devices-limit) DEVICES_LIMIT="$2"; shift 2 ;;

    --vuln-filter) VULN_FILTER="$2"; shift 2 ;;
    --vuln-sort) VULN_SORT="$2"; shift 2 ;;
    --vuln-facets) VULN_FACETS="$2"; shift 2 ;;
    --vulns-limit) VULNS_LIMIT="$2"; shift 2 ;;
    --flush-every) FLUSH_EVERY="$2"; shift 2 ;;
    --include-unmapped) INCLUDE_UNMAPPED="$2"; shift 2 ;;

    -h|--help)
      cat <<'EOF'
Usage:
  ./start.sh [options]

Required (env or flags):
  --api-url URL
  --api-key KEY
  --api-secret SECRET

Devices:
  --device-filter "FQL"
  --device-sort "SORT"
  --devices-limit N

Vulnerabilities:
  --vuln-filter "FQL"
  --vuln-sort "SORT"
  --vuln-facets "cve,host_info,remediation"
  --vulns-limit N
  --flush-every N
  --include-unmapped true|false

Notes:
  - Write NORMAL human-readable FQL (no %3A%27).
  - You can use OR with commas in FQL:
      platform_name:'Windows',platform_name:'Linux'
    start.sh will safely escape commas and crowdstrike.star must decode them.

Examples:
  # Devices: Windows OR Linux seen in last 7 days
  ./start.sh --api-key "$API_KEY" --api-secret "$API_SECRET" \
    --device-filter "platform_name:'Windows',platform_name:'Linux'+last_seen:>='now-7d'" \
    --device-sort "last_seen.desc" --devices-limit 5000

  # Vulns: updated last 15 days
  ./start.sh --api-key "$API_KEY" --api-secret "$API_SECRET" \
    --vuln-filter "updated_timestamp:>='now-15d'+updated_timestamp<'now'" \
    --vuln-sort "updated_timestamp.desc" --vulns-limit 500

EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${API_KEY}" || -z "${API_SECRET}" ]]; then
  echo "ERROR: API_KEY and API_SECRET must be provided (env vars or flags)." >&2
  exit 2
fi

# -----------------------
# Helpers: escape commas for runner-safe -params
# -----------------------
escape_for_params() {
  # Escape commas (FQL OR) because runner uses commas as param separators.
  # Starlark will convert __OR__ back to commas.
  # Also escape literal "__OR__" if user uses it (rare), to avoid ambiguity:
  #   "__OR__" -> "__OR_ESC__" first, then "," -> "__OR__"
  local s="$1"
  s="${s//__OR__/__OR_ESC__}"
  s="${s//,/__OR__}"
  echo "$s"
}

# -----------------------
# Build EXTRA_PARAMS (comma-delimited) ONLY from non-empty vars
# -----------------------
extra_params=""

append_param() {
  local k="$1"
  local v="$2"
  if [[ -n "$v" ]]; then
    v="$(escape_for_params "$v")"
    if [[ -n "$extra_params" ]]; then
      extra_params+=","
    fi
    extra_params+="${k}=${v}"
  fi
}

append_param "device_filter"      "$DEVICE_FILTER"
append_param "device_sort"        "$DEVICE_SORT"
append_param "devices_limit"      "$DEVICES_LIMIT"

append_param "vuln_filter"        "$VULN_FILTER"
append_param "vuln_sort"          "$VULN_SORT"
append_param "vuln_facets"        "$VULN_FACETS"
append_param "vulns_limit"        "$VULNS_LIMIT"
append_param "flush_every"        "$FLUSH_EVERY"
append_param "include_unmapped"   "$INCLUDE_UNMAPPED"

export API_URL API_KEY API_SECRET
export EXTRA_PARAMS="$extra_params"

exec ./start_crowdstrike.sh
