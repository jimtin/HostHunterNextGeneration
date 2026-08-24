#!/usr/bin/env bash

set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s PACKAGE_DIRECTORY\n' "$0" >&2
  exit 64
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/security/common.sh
source "$script_dir/common.sh"
hh_security_init
hh_require_docker

requested_package="$1"
[[ -d "$requested_package" ]] || {
  printf 'release package must be an existing directory: %s\n' \
    "$requested_package" >&2
  exit 2
}
package_root="$(cd -- "$requested_package" && pwd -P)"
case "$package_root" in
  "$HH_SECURITY_REPO_ROOT/.artifacts/"*) ;;
  *)
    printf 'release package must be below the repository .artifacts root: %s\n' \
      "$package_root" >&2
    exit 2
    ;;
esac

report_root="$HH_SECURITY_ARTIFACT_DIR/release-package"
mkdir -p -- "$report_root"

lock_path="$package_root/dependencies/sqlite/packages.lock.json"
sbom_path="$package_root/dependencies/sqlite/sqlite-dependencies.cdx.json"
notice_path="$package_root/dependencies/sqlite/THIRD-PARTY-NOTICES.md"
durability_helper_path="$package_root/Private/Interop/HostHunter.Persistence.Durability.dll"
for required_path in "$lock_path" "$sbom_path" "$notice_path"; do
  [[ -f "$required_path" ]] || {
    printf 'release package metadata is missing: %s\n' "$required_path" >&2
    exit 2
  }
done
[[ -f "$durability_helper_path" ]] || {
  printf 'release package is missing the durable publication helper\n' >&2
  exit 2
}
if [[ "$(find "$package_root" -type f \
    -name 'HostHunter.Persistence.Durability.dll' | wc -l | tr -d '[:space:]')" -ne 1 ]]; then
  printf 'release package must contain exactly one durable publication helper\n' >&2
  exit 2
fi
durability_helper_sha256="$(shasum -a 256 "$durability_helper_path" | awk '{print $1}')"

expected_packages=(
  Microsoft.Data.Sqlite.Core
  SQLite
  SQLitePCLRaw.bundle_e_sqlite3
  SQLitePCLRaw.config.e_sqlite3
  SQLitePCLRaw.core
  SQLitePCLRaw.provider.e_sqlite3
)
actual_package_list="$(
  jq -r '.dependencies["net8.0"] | keys[]' "$lock_path" |
    LC_ALL=C sort |
    paste -s -d ' ' -
)"
if [[ "$actual_package_list" != "${expected_packages[*]}" ]]; then
  printf 'release package lockfile does not contain the exact approved graph\n' >&2
  exit 2
fi

expected_rids=(linux-arm64 linux-x64 osx-arm64 win-x64)
for rid in "${expected_rids[@]}"; do
  rid_root="$package_root/lib/$rid"
  [[ -d "$rid_root" && "$(find "$rid_root" -maxdepth 1 -type f | wc -l)" -eq 5 ]] || {
    printf 'release package has an invalid provider inventory for RID: %s\n' \
      "$rid" >&2
    exit 2
  }
  native_name='libe_sqlite3.so'
  [[ "$rid" == osx-arm64 ]] && native_name='libe_sqlite3.dylib'
  [[ "$rid" == win-x64 ]] && native_name='e_sqlite3.dll'
  expected_asset_list="$(
    printf '%s\n' \
      Microsoft.Data.Sqlite.dll \
      SQLitePCLRaw.batteries_v2.dll \
      SQLitePCLRaw.core.dll \
      SQLitePCLRaw.provider.e_sqlite3.dll \
      "$native_name" |
      LC_ALL=C sort |
      paste -s -d ' ' -
  )"
  actual_asset_list="$(
    find "$rid_root" -maxdepth 1 -type f -exec basename {} \; |
      LC_ALL=C sort |
      paste -s -d ' ' -
  )"
  [[ "$actual_asset_list" == "$expected_asset_list" ]] || {
    printf 'release package asset names drifted for RID: %s\n' "$rid" >&2
    exit 2
  }
done

(cd "$package_root" && shasum -a 256 --check \
  dependencies/sqlite/asset-sha256.txt)

(cd "$package_root" && find . -type f -exec shasum -a 256 {} \; | LC_ALL=C sort -k2) \
  > "$report_root/package-sha256.txt"

host_uid="$(id -u)"
host_gid="$(id -g)"
gitleaks_image='ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f'
osv_image='ghcr.io/google/osv-scanner:v2.5.1@sha256:8108ae94eadea5a02c9bec6e646909d5b790b44bd62d7f5b7f0b1d6d0ffc7734'
trivy_image='ghcr.io/aquasecurity/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969'
bounded="$HH_SECURITY_REPO_ROOT/scripts/lib/run-bounded.sh"

"$bounded" release-package-gitleaks 660 180 "$report_root/gitleaks.log" \
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --user "$host_uid:$host_gid" \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m \
  --mount "type=bind,src=$package_root,dst=/package,readonly" \
  --mount "type=bind,src=$report_root,dst=/out" \
  --mount "type=bind,src=$HH_SECURITY_REPO_ROOT/.gitleaks.toml,dst=/gitleaks.toml,readonly" \
  "$gitleaks_image" dir /package \
    --config /gitleaks.toml --no-banner --no-color --redact=100 \
    --report-format json --report-path /out/gitleaks.json --timeout 600

"$bounded" release-package-osv 900 240 "$report_root/osv.log" \
docker run --rm --read-only --cap-drop ALL \
  --security-opt no-new-privileges --user "$host_uid:$host_gid" \
  --env HOME=/tmp --tmpfs /tmp:rw,nosuid,nodev,noexec,size=128m \
  --mount "type=bind,src=$package_root,dst=/package,readonly" \
  --mount "type=bind,src=$report_root,dst=/out" \
  "$osv_image" scan source --recursive --format json \
    --output-file /out/osv.json /package

"$bounded" release-package-trivy 1200 240 "$report_root/trivy.log" \
docker run --rm --read-only --cap-drop ALL \
  --security-opt no-new-privileges --user "$host_uid:$host_gid" \
  --env HOME=/tmp --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m \
  --mount "type=bind,src=$package_root,dst=/package,readonly" \
  --mount "type=bind,src=$report_root,dst=/out" \
  --mount "type=bind,src=$HH_SECURITY_CACHE_DIR,dst=/cache" \
  "$trivy_image" filesystem --cache-dir /cache --disable-telemetry \
    --exit-code 1 --format json --no-progress --output /out/trivy.json \
    --scanners vuln,misconfig --severity HIGH,CRITICAL /package

jq -e '
  .bomFormat == "CycloneDX" and
  ([.components[].purl] | length == 6) and
  ([.components[].purl] | unique | length == 6)
' "$sbom_path" > /dev/null

jq -n \
  --arg packageRoot "$package_root" \
  --arg durabilityHelperSha256 "$durability_helper_sha256" \
  '{
    status: "passed",
    packageRoot: $packageRoot,
    lockedPackageCount: 6,
    runtimeIdentifierCount: 4,
    durabilityHelper: {
      relativePath: "Private/Interop/HostHunter.Persistence.Durability.dll",
      sha256: $durabilityHelperSha256,
      thirdPartyPackageCount: 0
    }
  }' > "$report_root/receipt.json"

printf 'Release-package security scan passed: %s\n' "$package_root"
