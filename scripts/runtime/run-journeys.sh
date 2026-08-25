#!/usr/bin/env bash
# shellcheck disable=SC2016

set -Eeuo pipefail

readonly test_root='/opt/hosthunter-runtime-tests'
readonly result_path='/tmp/hosthunter-runtime-e2e.xml'
readonly expected_journeys=23

: "${HH_RUNTIME_MODULE_PATH:?HH_RUNTIME_MODULE_PATH is required}"
: "${HH_SSH_RUNTIME_DIR:?HH_SSH_RUNTIME_DIR is required}"

[[ -f "$HH_RUNTIME_MODULE_PATH" ]] || {
  printf 'The production package manifest is missing.\n' >&2
  exit 2
}
[[ -r "$HH_SSH_RUNTIME_DIR/username" ]] || {
  printf 'The disposable SSH fixture is not ready.\n' >&2
  exit 2
}

journey_count="$(grep -cE "^[[:space:]]+It '" \
  "$test_root/tests/e2e/TargetAndCommandJourneys.Tests.ps1")"
[[ "$journey_count" == "$expected_journeys" ]] || {
  printf 'Expected %s existing CLI journeys but found %s.\n' \
    "$expected_journeys" "$journey_count" >&2
  exit 2
}

export HH_TEST_MODULE_PATH="$HH_RUNTIME_MODULE_PATH"
pwsh -NoLogo -NoProfile -NonInteractive \
  -File "$test_root/scripts/testing/Invoke-HHPesterLane.ps1" \
  -TestPath "$test_root/tests/e2e" \
  -Tag E2E \
  -ResultPath "$result_path" \
  -PesterVersion 6.1.0

actual_journeys="$(
  RESULT_PATH="$result_path" pwsh -NoLogo -NoProfile -NonInteractive -Command '
    $document = [xml](Get-Content -LiteralPath $env:RESULT_PATH -Raw)
    [int]$document."test-results".total
  '
)"
[[ "$actual_journeys" == "$expected_journeys" ]] || {
  printf 'The production-image lane executed %s of %s CLI journeys.\n' \
    "$actual_journeys" "$expected_journeys" >&2
  exit 2
}

printf '{"status":"passed","journeys":%s,"modulePath":"%s","spaceContainingDataRootVerified":true,"testToolingInProduction":false}\n' \
  "$actual_journeys" "$HH_RUNTIME_MODULE_PATH"
