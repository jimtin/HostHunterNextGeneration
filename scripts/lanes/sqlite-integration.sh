#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly repo_root
cd -- "$repo_root"

artifact_mount_root="$repo_root/.artifacts"
release_artifact_root="${HH_SQLITE_RELEASE_ARTIFACT_ROOT:-$artifact_mount_root}"
[[ -d "$release_artifact_root" && ! -L "$release_artifact_root" ]] || {
  printf 'SQLite release artifact root is missing or unsafe: %s\n' \
    "$release_artifact_root" >&2
  exit 2
}
release_artifact_root="$(cd -- "$release_artifact_root" && pwd -P)"
case "$release_artifact_root" in
  "$artifact_mount_root"|"$artifact_mount_root"/*) ;;
  *) printf 'SQLite release artifacts must remain under %s\n' "$artifact_mount_root" >&2; exit 2 ;;
esac
receipt_root="$release_artifact_root/sqlite-integration"
mkdir -p -- "$receipt_root"
module_path="$(tr -d '\r\n' <"$artifact_mount_root/build/module-path.txt")"

test -f "$module_path"

docker compose -f compose.test.yml run --rm --no-deps \
  -e "HH_TEST_MODULE_PATH=$module_path" \
  persistence pwsh -NoLogo -NoProfile -NonInteractive -Command \
  '$paths=@(
    "tests/integration/SqliteFaultRecovery.Tests.ps1"
    "tests/integration/SqliteFaultConcurrency.Tests.ps1"
    "tests/integration/SqliteFaultAnchor.Tests.ps1"
  )
  $result=Invoke-Pester -Path $paths -PassThru
  if ($result.FailedCount -gt 0) { exit 1 }'

docker run --rm \
  --read-only --network none --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 128 --memory 512m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
  --tmpfs /fault:rw,size=64m,mode=0700,uid=10001,gid=10001 \
  --volume "$repo_root:/workspace:ro" \
  --volume "$artifact_mount_root/build:/artifacts/build:ro" \
  --workdir /workspace \
  --env "HH_TEST_MODULE_PATH=$module_path" \
  --env HH_SQLITE_FAULT_ROOT=/fault \
  "${HH_TEST_IMAGE:-hosthunter-next-generation-test:local}" \
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
