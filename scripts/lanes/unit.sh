#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly repo_root
cd -- "$repo_root"

artifact_root="${HH_ARTIFACT_ROOT:-.artifacts}"
unit_artifacts="$artifact_root/unit"
mkdir -p -- "$unit_artifacts"

exec > >(tee "$unit_artifacts/unit.log") 2>&1

printf 'Running coverage-foundation self-tests\n'
pwsh -NoLogo -NoProfile -NonInteractive \
  -File tests/coverage/Invoke-BranchCoverageSpike.ps1 \
  -ArtifactRoot "$unit_artifacts/branch"

pwsh -NoLogo -NoProfile -NonInteractive \
  -File tests/coverage/Invoke-CoverageThresholdSelfTest.ps1 \
  -ArtifactRoot "$unit_artifacts/threshold-self-test"

printf 'Running Pester unit tests and four-metric coverage gate\n'
pwsh -NoLogo -NoProfile -NonInteractive \
  -File scripts/coverage/Invoke-HHUnitCoverage.ps1 \
  -SourcePath tests/coverage/fixtures/BranchFixture.ps1 \
  -TestPath tests/coverage/BranchFixture.Tests.ps1 \
  -BranchReportPath "$unit_artifacts/branch/branch-report.json" \
  -ArtifactRoot "$unit_artifacts" \
  -ExpectedMetricsPath tests/coverage/fixtures/BranchFixture.metrics.expected.json \
  -Minimum 90 \
  -PesterVersion 6.1.0

if [[ -d src/HostHunterNextGeneration/Public ]]; then
  printf 'Running production module four-metric coverage gate\n'
  pwsh -NoLogo -NoProfile -NonInteractive \
    -File tests/coverage/Invoke-ProductCoverage.ps1 \
    -ArtifactRoot "$unit_artifacts/product" \
    -Minimum 90 \
    -PesterVersion 6.1.0
fi

printf 'Unit and coverage validation passed\n'
