#!/usr/bin/env bash
set -Eeuo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/hh-cleanup.XXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT INT TERM HUP
artifact_root="$fixture/.artifacts"
mkdir -p "$artifact_root/release/$(printf 'a%.0s' {1..40})/evidence/security/cache" \
  "$artifact_root/summary" "$artifact_root/unit/raw" "$artifact_root/qualification"
printf '{"status":"passed"}\n' > "$artifact_root/summary/verify-local.json"
printf '{"status":"passed"}\n' > "$artifact_root/summary/build.json"
printf '{"passed":true}\n' > "$artifact_root/unit/coverage-summary.json"
printf 'bulk\n' > "$artifact_root/unit/raw/events.jsonl"
printf 'cache\n' > "$artifact_root/release/$(printf 'a%.0s' {1..40})/evidence/security/cache/db"
plan="$artifact_root/retention/cleanup-plan.json"
"$repo_root/scripts/release/prepare-artifact-cleanup.sh" "$artifact_root" "$plan"
python3 - "$plan" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert "unit" in [target["relativePath"] for target in value["targets"]]
paths = {item["sourceRelativePath"] for item in value["receipts"]}
assert {"summary/build.json", "summary/verify-local.json"} <= paths
assert value["retainedReceiptBytes"] <= value["budgetBytes"]
PY
HH_CLEANUP_TEST_MODE=1 "$repo_root/scripts/release/apply-artifact-cleanup.sh" \
  --plan "$plan" DELETE-CLASSIFIED-ARTIFACTS
[[ ! -e "$artifact_root/unit" ]]
[[ -f "$artifact_root/summary/verify-local.json" ]]
[[ -f "$artifact_root/summary/build.json" ]]
[[ -f "$artifact_root/retention/receipt-history/summary/verify-local.json" ]]
[[ -f "$artifact_root/retention/receipt-history/summary/build.json" ]]
[[ -f "$artifact_root/retention/receipt-history/unit/coverage-summary.json" ]]
[[ -f "$plan" ]]
