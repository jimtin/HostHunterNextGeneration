#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly repo_root
cd -- "${repo_root}"

printf 'Running true PowerShell branch-outcome coverage feasibility proof\n'
pwsh -NoLogo -NoProfile -NonInteractive \
    -File tests/coverage/Invoke-BranchCoverageSpike.ps1 \
    -ArtifactRoot "${HH_ARTIFACT_ROOT:-.artifacts}/coverage-spike"
