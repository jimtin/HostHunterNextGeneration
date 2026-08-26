#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
bounded="${repo_root}/scripts/lib/run-bounded.sh"
readonly repo_root bounded
cd -- "${repo_root}"

artifact_root=".artifacts/release-proof"
mkdir -p "${artifact_root}" .artifacts/logs .artifacts/summary
export HH_ARTIFACT_ROOT="/artifacts/release-proof"
export HH_HOST_GID
HH_HOST_GID="$(id -g)"
export HH_RUNTIME_PROJECT="hosthunter-release-${HH_CANDIDATE_SHA:-local}"
export HH_RUNTIME_CONTROLLER_IMAGE="hosthunter-next-generation-controller:local"
export HH_RUNTIME_DATA_VOLUME="${HH_RUNTIME_PROJECT}-data"
export HH_RUNTIME_SECRET_VOLUME="${HH_RUNTIME_PROJECT}-secrets"
export HH_RUNTIME_ANCHOR_VOLUME="${HH_RUNTIME_PROJECT}-anchors"
export HH_RUNTIME_SSH_VOLUME="${HH_RUNTIME_PROJECT}-ssh"
export HH_RUNTIME_EVIDENCE_VOLUME="${HH_RUNTIME_PROJECT}-evidence"

cleanup() {
  docker compose --file compose.test.yml down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM HUP

"${bounded}" release-build 900 180 .artifacts/logs/release-build.log \
  docker compose --file compose.test.yml build test ssh-target
"${bounded}" release-static 300 120 .artifacts/logs/release-static.log \
  docker compose --file compose.test.yml run --rm --no-deps test bash scripts/lanes/static.sh
"${bounded}" release-module 300 120 .artifacts/logs/release-module.log \
  docker compose --file compose.test.yml run --rm --no-deps test bash scripts/lanes/build.sh
"${bounded}" release-unit-coverage 1800 300 .artifacts/logs/release-unit-coverage.log \
  docker compose --file compose.test.yml run --rm --no-deps test bash scripts/lanes/unit.sh
"${bounded}" release-ssh-start 180 120 .artifacts/logs/release-ssh-start.log \
  docker compose --file compose.test.yml up --detach --wait ssh-target
"${bounded}" release-critical-integration 900 240 .artifacts/logs/release-critical-integration.log \
  docker compose --file compose.test.yml run --rm test bash scripts/lanes/integration.sh
"${bounded}" release-sqlite-faults 1200 240 .artifacts/logs/release-sqlite-faults.log \
  bash scripts/lanes/sqlite-integration.sh
"${bounded}" release-production-build 900 180 .artifacts/logs/release-production-build.log \
  docker compose --file compose.runtime.yml build controller

controller_image_id="$(docker image inspect --format '{{.Id}}' hosthunter-next-generation-controller:local)"
"${repo_root}/scripts/lanes/security.sh" \
  hosthunter-next-generation-test:local \
  hosthunter-next-generation-ssh-fixture:local \
  "${controller_image_id}"

jq -n \
  --arg sha "${HH_CANDIDATE_SHA:-$(git rev-parse HEAD)}" \
  --arg imageId "${controller_image_id}" \
  '{
    status: "passed",
    scope: "release-only-coverage-integration-scans-and-production-build",
    candidateSha: $sha,
    controllerImageId: $imageId,
    cmdletVerdictExcluded: true
  }' >.artifacts/summary/verify-local.json

printf 'Release-only heavy proof passed once for %s\n' "${HH_CANDIDATE_SHA:-$(git rev-parse HEAD)}"
