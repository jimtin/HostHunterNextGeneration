#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly repo_root
cd -- "$repo_root"

artifact_root="${HH_ARTIFACT_ROOT:-.artifacts}"
receipt_root="$artifact_root/sqlite-integration"
mkdir -p -- "$receipt_root"
module_path='/artifacts/build/HostHunterNextGeneration/0.2.0/HostHunterNextGeneration.psd1'

test -f "$artifact_root/build/HostHunterNextGeneration/0.2.0/HostHunterNextGeneration.psd1"

docker compose -f compose.test.yml run --rm --no-deps \
  -e "HH_TEST_MODULE_PATH=$module_path" \
  test pwsh -NoLogo -NoProfile -NonInteractive -Command \
  '$paths=@(
    "tests/integration/SqliteFaultRecovery.Tests.ps1"
    "tests/integration/SqliteFaultConcurrency.Tests.ps1"
    "tests/integration/SqliteFaultAnchor.Tests.ps1"
  )
  $result=Invoke-Pester -Path $paths -PassThru
  if ($result.FailedCount -gt 0) { exit 1 }'

docker run --rm \
  --tmpfs /fault:rw,size=64m,mode=0700,uid=10001,gid=10001 \
  --volume "$repo_root:/workspace:ro" \
  --volume "$repo_root/$artifact_root:/artifacts" \
  --workdir /workspace \
  --env "HH_TEST_MODULE_PATH=$module_path" \
  --env HH_SQLITE_FAULT_ROOT=/fault \
  hosthunter-next-generation-test:local \
  pwsh -NoLogo -NoProfile -NonInteractive -Command \
  '$result=Invoke-Pester -Path tests/integration/SqliteFaultCapacity.Tests.ps1 -PassThru
  if ($result.FailedCount -gt 0) { exit 1 }'

receipt_path="$receipt_root/receipt.json"
# shellcheck disable=SC2016
HH_SQLITE_RECEIPT_PATH="$receipt_path" \
  pwsh -NoLogo -NoProfile -NonInteractive -Command \
  '$receipt=[ordered]@{
    schemaVersion=1
    result="passed"
    redacted=$true
    lane="sqlite-integration"
    scenarios=@(
      "unarmed-kill"
      "armed-kill-no-retry"
      "live-operation-owner"
      "wal-writer-contention"
      "anchor-commit-ahead"
      "database-rollback"
      "database-tamper"
      "predispatch-capacity-refusal"
      "external-sqlite-full"
    )
  }
  $json=$receipt|ConvertTo-Json -Depth 4
  [IO.File]::WriteAllText(
    $env:HH_SQLITE_RECEIPT_PATH,$json,[Text.UTF8Encoding]::new($false)
  )'

printf 'SQLite fault integration passed; receipt: %s\n' "$receipt_path"
