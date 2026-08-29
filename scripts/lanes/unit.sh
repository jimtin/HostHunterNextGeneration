#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly repo_root
cd -- "$repo_root"

artifact_root="${HH_ARTIFACT_ROOT:-.artifacts}"
mode="${1:-smoke}"

case "$mode" in
  smoke)
    unit_artifacts="$artifact_root/unit-smoke"
    summary="$unit_artifacts/unit-summary.json"
    printf 'Running fast unit smoke: one container, one PowerShell process, one Pester invocation\n'
    pwsh -NoLogo -NoProfile -NonInteractive \
      -File scripts/coverage/Invoke-HHUnitSmoke.ps1 \
      -SourceRoot src/HostHunterNextGeneration \
      -ClientSourceRoot client/HostHunter.Client \
      -TestPath tests/unit \
      -ArtifactRoot "$unit_artifacts" \
      -PesterVersion 6.1.0
    ;;
  coverage)
    unit_artifacts="$artifact_root/unit"
    summary="$unit_artifacts/coverage-summary.json"
    printf 'Running release-only native coverage: one container, one PowerShell process, one Pester invocation\n'
    pwsh -NoLogo -NoProfile -NonInteractive \
      -File scripts/coverage/Invoke-HHUnitCoverage.ps1 \
      -SourceRoot src/HostHunterNextGeneration \
      -TestPath tests/unit \
      -ArtifactRoot "$unit_artifacts" \
      -Minimum 90 \
      -PesterVersion 6.1.0
    ;;
  *)
    printf 'Unsupported unit lane mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac

[[ -s "$summary" ]] || {
  printf 'Unit lane failed closed: missing terminal receipt %s\n' "$summary" >&2
  exit 1
}
python3 - "$summary" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    receipt = json.load(handle)
assert receipt.get("status") == "passed", "unit lane status is not passed"
assert receipt.get("passed") is True, "unit lane pass flag is not true"
assert receipt.get("invocationCount") == 1, "unit lane invocation count is not one"
PY

printf 'Unit %s validation passed\n' "$mode"
