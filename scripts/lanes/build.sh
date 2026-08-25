#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly repo_root
cd -- "$repo_root"

artifact_root="${HH_ARTIFACT_ROOT:-.artifacts}"
build_artifacts="$artifact_root/build"
mkdir -p -- "$build_artifacts"
exec > >(tee "$build_artifacts/build.log") 2>&1

HH_SQLITE_RESTORE_INSIDE=1 \
  bash scripts/dependencies/restore-sqlite.sh

provider_root="$artifact_root/dependencies/sqlite/provider"
durability_helper_root="${HH_DURABILITY_HELPER_ROOT:-/opt/hosthunter-durability}"
evtx_parser_root="${HH_EVTX_PARSER_ROOT:-/opt/hosthunter-evtx}"

pwsh -NoLogo -NoProfile -NonInteractive \
  -File scripts/build/Test-HHModulePackage.ps1 \
  -SourceRoot src/HostHunterNextGeneration \
  -ArtifactRoot "$build_artifacts" \
  -ProviderRoot "$provider_root" \
  -MetadataRoot eng/sqlite \
  -DurabilityHelperRoot "$durability_helper_root" \
  -EvtxParserRoot "$evtx_parser_root" \
  -EvtxMetadataRoot eng/forensics

printf 'Module package validation passed\n'
