#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
bounded="$repo_root/scripts/lib/run-bounded.sh"
candidate_sha="${HH_CANDIDATE_SHA:-$(git -C "$repo_root" rev-parse HEAD)}"
artifact_root="$repo_root/.artifacts/release-proof"
receipt="$repo_root/.artifacts/summary/verify-local.json"
test_image="${HH_TEST_IMAGE:-hosthunter-next-generation-test:local}"
ssh_image="${HH_SSH_FIXTURE_IMAGE:-hosthunter-next-generation-ssh-fixture:local}"
controller_image="${HH_RUNTIME_CONTROLLER_IMAGE:-hosthunter-next-generation-controller:local}"
started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
phase_results='[]'
overall_exit=0
interrupted=false

readonly repo_root bounded candidate_sha artifact_root receipt test_image ssh_image controller_image
cd -- "$repo_root"
scripts/lib/prepare-artifacts.sh "$repo_root"
mkdir -p -- "$artifact_root" .artifacts/logs .artifacts/summary
rm -f -- "$receipt.tmp"

export HH_ARTIFACT_ROOT=/artifacts/release-proof
export HH_CANDIDATE_SHA="$candidate_sha"
export HH_CANDIDATE_TREE
HH_CANDIDATE_TREE="$(git -C "$repo_root" show -s --format=%T "$candidate_sha")"
export HH_HOST_GID
HH_HOST_GID="$(id -g)"
export HH_TEST_IMAGE="$test_image"
export HH_SSH_FIXTURE_IMAGE="$ssh_image"
export HH_RUNTIME_PROJECT="hosthunter-release-${candidate_sha:0:12}"
export HH_RUNTIME_CONTROLLER_IMAGE="$controller_image"
export HH_RUNTIME_DATA_VOLUME="${HH_RUNTIME_PROJECT}-data"
export HH_RUNTIME_SECRET_VOLUME="${HH_RUNTIME_PROJECT}-secrets"
export HH_RUNTIME_ANCHOR_VOLUME="${HH_RUNTIME_PROJECT}-anchors"
export HH_RUNTIME_SSH_VOLUME="${HH_RUNTIME_PROJECT}-ssh"
export HH_RUNTIME_EVIDENCE_VOLUME="${HH_RUNTIME_PROJECT}-evidence"

append_phase() {
  local name="$1" status="$2" exit_code="$3" reason="$4"
  phase_results="$(jq -c \
    --arg name "$name" --arg status "$status" --arg reason "$reason" \
    --argjson exitCode "$exit_code" \
    '. + [{name:$name,status:$status,exitCode:$exitCode,reason:(if $reason=="" then null else $reason end)}]' \
    <<<"$phase_results")"
}

run_phase() {
  local name="$1" timeout="$2" stall="$3" log="$4"
  shift 4
  local exit_code
  set +e
  "$bounded" "$name" "$timeout" "$stall" "$log" "$@"
  exit_code=$?
  set -e
  if ((exit_code == 0)); then
    append_phase "$name" passed 0 ''
  else
    append_phase "$name" failed "$exit_code" "Phase exited $exit_code; see $log"
    overall_exit=1
  fi
}

skip_phase() {
  append_phase "$1" not-run 0 "$2"
  overall_exit=1
}

phase_passed() {
  jq -e --arg name "$1" 'any(.[]; .name==$name and .status=="passed")' \
    <<<"$phase_results" >/dev/null
}

write_receipt() {
  local status=failed
  local reason='One or more release-only phases failed or could not run'
  local controller_image_id=''
  local coverage='null'
  if ((overall_exit == 0)) && [[ "$interrupted" == false ]]; then
    status=passed
    reason=''
  elif [[ "$interrupted" == true ]]; then
    status=aborted
    reason='Release-only proof was interrupted; no phase is retried'
  fi
  controller_image_id="$(docker image inspect --format '{{.Id}}' "$controller_image" 2>/dev/null || true)"
  if [[ -f "$artifact_root/unit/coverage-summary.json" ]]; then
    coverage="$(jq -c '{status,minimum,invocationCount,testCount,durationMs,
      candidateSha,candidateTree,sourceHash,sourceFileCount,sourceInventory,metrics,uncovered}' \
      "$artifact_root/unit/coverage-summary.json" 2>/dev/null || printf 'null')"
  fi
  jq -n \
    --arg sha "$candidate_sha" --arg status "$status" --arg reason "$reason" \
    --arg started "$started_at" --arg finished "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg imageId "$controller_image_id" --argjson phases "$phase_results" \
    --argjson coverage "$coverage" '
      {
        schemaVersion: 2, candidateSha:$sha, status:$status,
        scope:"release-only-coverage-integration-scans",
        startedAtUtc:$started, finishedAtUtc:$finished,
        reason:(if $reason=="" then null else $reason end),
        controllerImageId:(if $imageId=="" then null else $imageId end),
        cmdletVerdictExcluded:true, retryCount:0,
        phases:$phases, coverage:$coverage
      }' >"$receipt.tmp"
  chmod 0400 "$receipt.tmp"
  mv -- "$receipt.tmp" "$receipt"
}

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM HUP
  docker compose --file compose.test.yml down --volumes --remove-orphans >/dev/null 2>&1 || true
  [[ -f "$receipt" ]] || {
    overall_exit=1
    write_receipt
  }
  exit "$exit_status"
}

abort_signal() {
  interrupted=true
  overall_exit=1
  exit 130
}

trap cleanup EXIT
trap abort_signal INT TERM HUP

for image in "$test_image" "$ssh_image" "$controller_image"; do
  docker image inspect "$image" >/dev/null
done
if [[ -n "${HH_RELEASE_CONTROLLER_IMAGE_ID:-}" ]]; then
  actual_controller_id="$(docker image inspect --format '{{.Id}}' "$controller_image")"
  [[ "$actual_controller_id" == "$HH_RELEASE_CONTROLLER_IMAGE_ID" ]] || {
    printf 'Controller tag does not match the exact-SHA build receipt.\n' >&2
    exit 2
  }
fi

run_phase release-static 300 120 .artifacts/logs/release-static.log \
  docker compose --file compose.test.yml run --rm --no-deps test \
    bash scripts/lanes/static.sh

run_phase release-module 300 120 .artifacts/logs/release-module.log \
  docker compose --file compose.test.yml run --rm --no-deps test \
    bash scripts/lanes/build.sh

run_phase release-unit-coverage 300 120 .artifacts/logs/release-unit-coverage.log \
  docker compose --file compose.test.yml run --rm --no-deps coverage

run_phase release-ssh-start 180 120 .artifacts/logs/release-ssh-start.log \
  docker compose --file compose.test.yml up --detach --wait --no-build ssh-target

if phase_passed release-module && phase_passed release-ssh-start; then
  run_phase release-critical-integration 900 240 .artifacts/logs/release-critical-integration.log \
    docker compose --file compose.test.yml run --rm test \
      bash scripts/lanes/integration.sh
else
  skip_phase release-critical-integration 'not_run_due_to_release-module_or_release-ssh-start'
fi

if phase_passed release-module; then
  run_phase release-sqlite-faults 1200 240 .artifacts/logs/release-sqlite-faults.log \
    bash scripts/lanes/sqlite-integration.sh
else
  skip_phase release-sqlite-faults 'not_run_due_to_release-module'
fi

run_phase release-security 1800 300 .artifacts/logs/release-security.log \
  "$repo_root/scripts/lanes/security.sh" "$test_image" "$ssh_image" "$controller_image"

write_receipt
final_status="$(jq -r .status "$receipt")"
printf 'Release-only proof is terminal: %s; receipt: %s\n' "$final_status" "$receipt"
[[ "$final_status" == passed ]]
