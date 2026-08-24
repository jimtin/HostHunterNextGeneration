#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly repo_root
cd -- "${repo_root}"
scripts/lib/prepare-artifacts.sh "${repo_root}"
mkdir -p .artifacts/logs
HH_HOST_GID="$(id -g)"
export HH_HOST_GID

exec docker compose --file compose.test.yml "$@"
