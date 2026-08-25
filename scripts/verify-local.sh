#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly bounded="${repo_root}/scripts/lib/run-bounded.sh"
readonly repo_root
cd -- "${repo_root}"
scripts/lib/prepare-artifacts.sh "${repo_root}"
mkdir -p .artifacts/logs .artifacts/summary
HH_HOST_GID="$(id -g)"
export HH_HOST_GID

cleanup() {
    docker compose --file compose.test.yml down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM HUP

"${repo_root}/scripts/security/scan-secrets.sh"
"${bounded}" full-build 600 240 .artifacts/logs/full-build.log \
    docker compose --file compose.test.yml build test controller-floor ssh-target
"${bounded}" full-toolchain 180 120 .artifacts/logs/full-toolchain.log \
    docker compose --file compose.test.yml run --rm test bash scripts/lanes/toolchain.sh
"${bounded}" full-static 300 120 .artifacts/logs/full-static.log \
    docker compose --file compose.test.yml run --rm test bash scripts/lanes/static.sh
"${bounded}" full-module-build 300 120 .artifacts/logs/full-module-build.log \
    docker compose --file compose.test.yml run --rm test bash scripts/lanes/build.sh
"${bounded}" controller-floor 300 120 .artifacts/logs/controller-floor.log \
    docker compose --file compose.test.yml run --rm controller-floor \
        pwsh -NoLogo -NoProfile -NonInteractive \
        -File scripts/qualification/Test-HHControllerMatrix.ps1 \
        -PowerShellVersion 7.4.19
"${bounded}" full-unit-coverage 720 300 .artifacts/logs/full-unit-coverage.log \
    docker compose --file compose.test.yml run --rm test bash scripts/lanes/unit.sh
"${bounded}" full-ssh-start 180 120 .artifacts/logs/full-ssh-start.log \
    docker compose --file compose.test.yml up --detach --wait ssh-target
"${bounded}" full-ssh-contract 300 120 .artifacts/logs/full-ssh-contract.log \
    docker compose --file compose.test.yml run --rm test \
        pwsh -NoLogo -NoProfile -NonInteractive -File tests/fixtures/ssh/Invoke-FixtureContract.ps1
"${bounded}" controller-floor-spaced-ssh 300 120 \
    .artifacts/logs/controller-floor-spaced-ssh.log \
    docker compose --file compose.test.yml run --rm controller-floor \
        pwsh -NoLogo -NoProfile -NonInteractive \
        -File scripts/testing/Invoke-HHPesterLane.ps1 \
        -TestPath tests/integration/SshTransport.Tests.ps1 \
        -Tag Integration \
        -ResultPath /artifacts/integration/controller-floor-spaced-ssh.xml \
        -PesterVersion 6.1.0
"${bounded}" full-integration 900 240 .artifacts/logs/full-integration.log \
    docker compose --file compose.test.yml run --rm test bash scripts/lanes/integration.sh
"${bounded}" full-sqlite-fault-integration 1200 240 \
    .artifacts/logs/full-sqlite-fault-integration.log \
    bash scripts/lanes/sqlite-integration.sh
"${bounded}" full-e2e 1200 240 .artifacts/logs/full-e2e.log \
    docker compose --file compose.test.yml run --rm test bash scripts/lanes/e2e.sh
"${repo_root}/scripts/lanes/security.sh" \
    hosthunter-next-generation-test:local \
    hosthunter-next-generation-controller-floor:local \
    hosthunter-next-generation-ssh-fixture:local

printf '{"status":"passed","scope":"full-product"}\n' \
    >.artifacts/summary/verify-local.json
printf 'HostHunterNextGeneration full local product proof passed\n'
