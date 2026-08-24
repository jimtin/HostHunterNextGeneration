#!/usr/bin/env bash

set -euo pipefail

HH_SECURITY_REPO_ROOT=''
HH_SECURITY_ARTIFACT_DIR=''
HH_SECURITY_CACHE_DIR=''

hh_security_init() {
  local common_dir
  local discovered_root
  local requested_root

  common_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
  discovered_root="$(git -C "$common_dir/../.." rev-parse --show-toplevel)"
  discovered_root="$(cd -- "$discovered_root" && pwd -P)"
  requested_root="${HH_REPO_ROOT:-$discovered_root}"
  requested_root="$(cd -- "$requested_root" && pwd -P)"

  if [[ "$discovered_root" == "/" ]] ||
    ! git -C "$discovered_root" rev-parse --git-dir >/dev/null 2>&1; then
    echo "Security lane refused an invalid repository root: $discovered_root" >&2
    return 2
  fi

  if [[ "$requested_root" != "$discovered_root" ]]; then
    echo "Security lane refuses to scan outside its own repository root." >&2
    echo "Expected: $discovered_root" >&2
    echo "Requested: $requested_root" >&2
    return 2
  fi

  export HH_SECURITY_REPO_ROOT="$discovered_root"
  export HH_SECURITY_ARTIFACT_DIR="$discovered_root/.artifacts/security"
  export HH_SECURITY_CACHE_DIR="$HH_SECURITY_ARTIFACT_DIR/cache"
  mkdir -p -- "$HH_SECURITY_ARTIFACT_DIR" "$HH_SECURITY_CACHE_DIR"
}

hh_require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required for the container-only security lane." >&2
    return 2
  fi

  if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed but its daemon is unavailable." >&2
    return 2
  fi
}
