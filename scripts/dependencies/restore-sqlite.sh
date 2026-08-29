#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly repo_root
cd -- "$repo_root"

if [[ "${HH_SQLITE_RESTORE_INSIDE:-0}" != 1 ]]; then
  bounded="$repo_root/scripts/lib/run-bounded.sh"
  scripts/lib/prepare-artifacts.sh "$repo_root"
  mkdir -p .artifacts/logs
  "$bounded" sqlite-dependency-image 900 240 \
    .artifacts/logs/sqlite-dependency-image.log \
    scripts/compose-run.sh build test
  "$bounded" sqlite-dependency-export 180 120 \
    .artifacts/logs/sqlite-dependency-export.log \
    scripts/compose-run.sh run --rm \
      --env HH_SQLITE_RESTORE_INSIDE=1 \
      test bash scripts/dependencies/restore-sqlite.sh
  exit 0
fi

provider_source='/opt/hosthunter-sqlite'
artifact_root="${HH_ARTIFACT_ROOT:-.artifacts}"
dependency_root="$artifact_root/dependencies/sqlite"
provider_destination="$dependency_root/provider"

[[ -d "$provider_source/lib" ]] || {
  printf 'SQLite provider root is missing from the locked test image: %s\n' \
    "$provider_source" >&2
  exit 2
}

mkdir -p -- "$dependency_root"
if [[ -e "$provider_destination" ]]; then
  rm -rf -- "$provider_destination"
fi
mkdir -p -- "$provider_destination"
cp -R "$provider_source/." "$provider_destination/"

cp eng/sqlite/packages.lock.json "$provider_destination/packages.lock.json"
cp eng/sqlite/THIRD-PARTY-NOTICES.md \
  "$provider_destination/THIRD-PARTY-NOTICES.md"
cp eng/sqlite/sqlite-dependencies.cdx.json \
  "$provider_destination/sqlite-dependencies.cdx.json"

(cd "$provider_destination" && sha256sum --check asset-sha256.txt)

expected_rids=(linux-arm64 linux-x64)
expected_assets=(
  Humanizer.dll
  Json.More.dll
  JsonPointer.Net.dll
  JsonSchema.Net.dll
  Microsoft.Data.Sqlite.dll
  SQLitePCLRaw.batteries_v2.dll
  SQLitePCLRaw.core.dll
  SQLitePCLRaw.provider.e_sqlite3.dll
  libe_sqlite3.so
)
actual_rids=()
while IFS= read -r actual_rid; do
  [[ -z "$actual_rid" ]] || actual_rids+=("$actual_rid")
done < <(find "$provider_destination/lib" -mindepth 1 -maxdepth 1 -type d \
  -printf '%f\n' | LC_ALL=C sort)
[[ "${actual_rids[*]}" == "${expected_rids[*]}" ]] || {
  printf 'Unexpected staged SQLite RID set: %s\n' "${actual_rids[*]}" >&2
  exit 2
}
for rid in "${expected_rids[@]}"; do
  rid_root="$provider_destination/lib/$rid"
  [[ -d "$rid_root" ]] || {
    printf 'Missing staged SQLite RID: %s\n' "$rid" >&2
    exit 2
  }
  [[ "$(find "$rid_root" -maxdepth 1 -type f | wc -l)" -eq "${#expected_assets[@]}" ]] || {
    printf 'Unexpected SQLite asset count for RID: %s\n' "$rid" >&2
    exit 2
  }
  for asset in "${expected_assets[@]}"; do
    [[ -f "$rid_root/$asset" ]] || {
      printf 'Missing SQLite asset for RID %s: %s\n' "$rid" "$asset" >&2
      exit 2
    }
  done
done

printf '%s\n' \
  '{' \
  '  "status": "passed",' \
  '  "targetFramework": "net8.0",' \
  '  "managedProviderVersion": "10.0.11",' \
  '  "sqlitePclRawVersion": "3.0.5",' \
  '  "nativeSqliteVersion": "3.53.4",' \
  "  \"providerRoot\": \"$provider_destination\"," \
  '  "runtimeIdentifiers": ["linux-arm64", "linux-x64"]' \
  '}' > "$dependency_root/restore-receipt.json"

printf 'Locked SQLite provider assets exported to %s\n' "$provider_destination"
