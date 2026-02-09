#!/usr/bin/env bash
set -euo pipefail

RUNNER="./starlark-runner-linux"
SCRIPT="./dev/crowdstrike.star"

API_URL="https://api.us-2.crowdstrike.com"
API_KEY="API_KEY"
API_SECRET="API_SECRET"

echo "Starting CrowdStrike REPL..."
echo "Runner:  $RUNNER"
echo "Script:  $SCRIPT"
echo "API URL: $API_URL"
echo
echo "Inside REPL, run:"
echo "  params"
echo "  repl_smoke_from_params(**params)"
echo "  repl_collect_sample_from_params(**params)"
echo "  show_collected()"
echo "  # full run: repl_run_full_from_params(**params)"
echo

# IMPORTANT: comma-separated kv pairs (prevents api_url swallowing the rest)
PARAMS="api_url=$API_URL,api_key=$API_KEY,api_secret=$API_SECRET"

exec "$RUNNER" -repl -script "$SCRIPT" -params "$PARAMS"
