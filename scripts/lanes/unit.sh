#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly repo_root
cd -- "$repo_root"

artifact_root="${HH_ARTIFACT_ROOT:-.artifacts}"
unit_artifacts="$artifact_root/unit"
mkdir -p -- "$unit_artifacts"

printf 'Running the two-pass unit coverage gate\n'
pwsh -NoLogo -NoProfile -NonInteractive \
  -File scripts/coverage/Invoke-HHUnitCoverage.ps1 \
  -SourceRoot src/HostHunterNextGeneration \
  -TestPath tests/unit \
  -ArtifactRoot "$unit_artifacts" \
  -Minimum 90 \
  -PesterVersion 6.1.0

printf 'Unit and coverage validation passed\n'
