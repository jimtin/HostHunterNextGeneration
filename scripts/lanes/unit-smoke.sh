#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly repo_root
cd -- "$repo_root"

artifact_root="${HH_ARTIFACT_ROOT:-.artifacts}"
unit_artifacts="$artifact_root/unit-smoke"
mkdir -p -- "$unit_artifacts"
exec > >(tee "$unit_artifacts/unit-smoke.log") 2>&1

pwsh -NoLogo -NoProfile -NonInteractive \
  -File scripts/testing/Invoke-HHPesterLane.ps1 \
  -TestPath tests/unit \
  -Tag Unit \
  -ResultPath "$unit_artifacts/unit-smoke.xml" \
  -PesterVersion 6.1.0

printf 'Unit smoke validation passed\n'
