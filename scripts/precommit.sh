#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly bounded="${repo_root}/scripts/lib/run-bounded.sh"
readonly repo_root
cd -- "${repo_root}"
scripts/lib/prepare-artifacts.sh "${repo_root}"
mkdir -p .artifacts/logs
HH_HOST_GID="$(id -g)"
export HH_HOST_GID

"${repo_root}/scripts/security/scan-secrets.sh"
"${bounded}" precommit-build 300 180 .artifacts/logs/precommit-build.log \
    docker compose --file compose.test.yml build test
"${bounded}" precommit-static 300 120 .artifacts/logs/precommit-static.log \
    docker compose --file compose.test.yml run --rm test bash scripts/lanes/static.sh
"${bounded}" precommit-unit-smoke 180 120 .artifacts/logs/precommit-unit-smoke.log \
    docker compose --file compose.test.yml run --rm test bash scripts/lanes/unit-smoke.sh
