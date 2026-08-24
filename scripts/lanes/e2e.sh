#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly repo_root
cd -- "$repo_root"

artifact_root="${HH_ARTIFACT_ROOT:-.artifacts}"
e2e_artifacts="$artifact_root/e2e"
mkdir -p -- "$e2e_artifacts"
exec > >(tee "$e2e_artifacts/e2e.log") 2>&1

module_path_file="$artifact_root/build/module-path.txt"
if [[ ! -f "$module_path_file" ]]; then
  printf 'Packaged module path receipt is missing; run the build lane first.\n' >&2
  exit 2
fi
HH_TEST_MODULE_PATH="$(<"$module_path_file")"
export HH_TEST_MODULE_PATH

export HH_DATA_ROOT="/tmp/hosthunter-e2e-${RANDOM}-${RANDOM}"
cleanup() {
  if [[ "$HH_DATA_ROOT" == /tmp/hosthunter-e2e-* ]]; then
    rm -rf -- "$HH_DATA_ROOT"
  fi
}
trap cleanup EXIT INT TERM HUP

pwsh -NoLogo -NoProfile -NonInteractive \
  -File scripts/testing/Invoke-HHPesterLane.ps1 \
  -TestPath tests/e2e \
  -Tag E2E \
  -ResultPath "$e2e_artifacts/e2e-tests.xml" \
  -PesterVersion 6.1.0

printf 'CLI E2E validation passed\n'
