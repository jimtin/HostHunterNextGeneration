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

cleanup() {
    docker compose --file compose.test.yml down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM HUP

"${repo_root}/scripts/security/scan-secrets.sh"
"${repo_root}/scripts/security/scan-dependencies.sh"
"${bounded}" prepush-build 300 180 .artifacts/logs/prepush-build.log \
    docker compose --file compose.test.yml build test ssh-target
"${bounded}" prepush-static 300 120 .artifacts/logs/prepush-static.log \
    docker compose --file compose.test.yml run --rm test bash scripts/lanes/static.sh
"${bounded}" prepush-toolchain 180 120 .artifacts/logs/prepush-toolchain.log \
    docker compose --file compose.test.yml run --rm test bash scripts/lanes/toolchain.sh
"${bounded}" prepush-module-build 300 120 .artifacts/logs/prepush-module-build.log \
    docker compose --file compose.test.yml run --rm test bash scripts/lanes/build.sh
"${bounded}" prepush-unit-smoke 300 120 .artifacts/logs/prepush-unit-smoke.log \
    docker compose --file compose.test.yml run --rm test bash scripts/lanes/unit-smoke.sh
"${bounded}" prepush-ssh-start 180 120 .artifacts/logs/prepush-ssh-start.log \
    docker compose --file compose.test.yml up --detach --wait ssh-target
"${bounded}" prepush-critical-ssh 300 120 .artifacts/logs/prepush-critical-ssh.log \
    docker compose --file compose.test.yml run --rm test \
        pwsh -NoLogo -NoProfile -NonInteractive -File tests/fixtures/ssh/Invoke-FixtureContract.ps1
"${bounded}" prepush-critical-integration 600 240 .artifacts/logs/prepush-critical-integration.log \
    docker compose --file compose.test.yml run --rm test bash scripts/lanes/integration.sh
"${repo_root}/scripts/verify-cmdlets.sh"
