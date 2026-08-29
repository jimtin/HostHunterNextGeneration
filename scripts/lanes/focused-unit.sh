#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly repo_root
cd -- "$repo_root"

[[ -n "${HH_FOCUSED_TESTS:-}" ]] || {
  printf 'HH_FOCUSED_TESTS must contain at least one repository-relative test path.\n' >&2
  exit 64
}

artifact_root="${HH_ARTIFACT_ROOT:-.artifacts}"
unit_artifacts="$artifact_root/focused-unit"
mkdir -p -- "$unit_artifacts"
exec > >(tee "$unit_artifacts/focused-unit.log") 2>&1

export HH_TEST_SOURCE_ROOT="$repo_root/src/HostHunterNextGeneration"
export HH_TEST_CLIENT_SOURCE_ROOT="$repo_root/client/HostHunter.Client"
pwsh -NoLogo -NoProfile -NonInteractive \
  -File scripts/testing/Invoke-HHPesterLane.ps1 \
  -TestPath "$HH_FOCUSED_TESTS" \
  -Tag Unit \
  -ResultPath "$unit_artifacts/focused-unit.xml" \
  -PesterVersion 6.1.0

printf 'Focused unit validation passed\n'
