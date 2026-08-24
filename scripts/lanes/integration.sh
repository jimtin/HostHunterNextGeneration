#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly repo_root
cd -- "$repo_root"

artifact_root="${HH_ARTIFACT_ROOT:-.artifacts}"
integration_artifacts="$artifact_root/integration"
mkdir -p -- "$integration_artifacts"
exec > >(tee "$integration_artifacts/integration.log") 2>&1

module_path_file="$artifact_root/build/module-path.txt"
if [[ ! -f "$module_path_file" ]]; then
  printf 'Packaged module path receipt is missing; run the build lane first.\n' >&2
  exit 2
fi
HH_TEST_MODULE_PATH="$(<"$module_path_file")"
export HH_TEST_MODULE_PATH

export HH_DATA_ROOT="/tmp/hosthunter-integration-${RANDOM}-${RANDOM}"
cleanup() {
  if [[ "$HH_DATA_ROOT" == /tmp/hosthunter-integration-* ]]; then
    rm -rf -- "$HH_DATA_ROOT"
  fi
}
trap cleanup EXIT INT TERM HUP

pwsh -NoLogo -NoProfile -NonInteractive \
  -File scripts/testing/Invoke-HHPesterLane.ps1 \
  -TestPath tests/integration \
  -Tag Integration \
  -ResultPath "$integration_artifacts/integration-tests.xml" \
  -PesterVersion 6.1.0

printf 'Integration validation passed\n'
