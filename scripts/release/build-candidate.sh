#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
candidate_sha="${HH_CANDIDATE_SHA:-$(git -C "$repo_root" rev-parse HEAD)}"
candidate_tree="$(git -C "$repo_root" show -s --format=%T "$candidate_sha")"
short_sha="${candidate_sha:0:12}"
artifact_root="$repo_root/.artifacts/summary"
receipt="$artifact_root/build.json"
controller_image="hosthunter-controller-release:$short_sha"
test_image="hosthunter-test-release:$short_sha"
ssh_image="hosthunter-ssh-release:$short_sha"
verifier_image="hosthunter-verifier-release:$short_sha"
phase=initialization
status=failed
failure='Candidate image build did not complete'
started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

[[ "$candidate_sha" =~ ^[a-f0-9]{40}$ ]] || exit 64
[[ "$(git -C "$repo_root" rev-parse HEAD)" == "$candidate_sha" ]] || exit 2
mkdir -p -- "$artifact_root"
rm -f -- "$receipt.tmp"

write_receipt() {
  local exit_status="${1:-$?}"
  local controller_id='' test_id='' ssh_id='' verifier_id=''
  if [[ "$status" == passed ]]; then
    controller_id="$(docker image inspect --format '{{.Id}}' "$controller_image")"
    test_id="$(docker image inspect --format '{{.Id}}' "$test_image")"
    ssh_id="$(docker image inspect --format '{{.Id}}' "$ssh_image")"
    verifier_id="$(docker image inspect --format '{{.Id}}' "$verifier_image")"
  fi
  jq -n \
    --arg sha "$candidate_sha" --arg tree "$candidate_tree" \
    --arg status "$status" --arg phase "$phase" --arg reason "$failure" \
    --arg started "$started_at" --arg finished "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg controllerTag "$controller_image" --arg controllerId "$controller_id" \
    --arg testTag "$test_image" --arg testId "$test_id" \
    --arg sshTag "$ssh_image" --arg sshId "$ssh_id" \
    --arg verifierTag "$verifier_image" --arg verifierId "$verifier_id" \
    --argjson exitCode "$exit_status" '
      {
        schemaVersion: 1, candidateSha: $sha, candidateTree: $tree,
        status: $status, failedPhase: (if $status == "passed" then null else $phase end),
        reason: (if $status == "passed" then null else $reason end),
        exitCode: $exitCode, startedAtUtc: $started, finishedAtUtc: $finished,
        images: {
          controller: {tag: $controllerTag, id: (if $controllerId == "" then null else $controllerId end)},
          test: {tag: $testTag, id: (if $testId == "" then null else $testId end)},
          sshFixture: {tag: $sshTag, id: (if $sshId == "" then null else $sshId end)},
          verifier: {tag: $verifierTag, id: (if $verifierId == "" then null else $verifierId end)}
        },
        buildCount: 4, retryCount: 0
      }' >"$receipt.tmp"
  chmod 0400 "$receipt.tmp"
  mv -- "$receipt.tmp" "$receipt"
}

finish() {
  local exit_status=$?
  trap - EXIT INT TERM HUP
  [[ -f "$receipt" ]] || write_receipt "$exit_status"
  exit "$exit_status"
}
trap finish EXIT
trap 'phase=interrupted; failure="Candidate image build was interrupted"; exit 130' INT TERM HUP

phase=controller
failure='Production controller image build failed'
docker build --file "$repo_root/Dockerfile.runtime" --target production \
  --tag "$controller_image" "$repo_root"

phase='test'
failure='Release test image build failed'
docker build --file "$repo_root/Dockerfile.test" --tag "$test_image" "$repo_root"

phase=ssh-fixture
failure='SSH fixture image build failed'
docker build --file "$repo_root/tests/fixtures/ssh/Dockerfile" \
  --tag "$ssh_image" "$repo_root/tests/fixtures/ssh"

phase=cmdlet-verifier
failure='Production-derived cmdlet verifier image build failed'
docker build --build-arg "HH_CONTROLLER_IMAGE=$controller_image" \
  --file "$repo_root/Dockerfile.cmdlets" --tag "$verifier_image" "$repo_root"

phase=production-probe-check
failure='Coverage instrumentation leaked into the production package'
docker run --rm --network none --entrypoint sh "$controller_image" -c \
  '! grep -R -E "Invoke-HHBranchProbe|HH_BRANCH_COVERAGE" /opt/hosthunter/module'

status=passed
failure=''
write_receipt 0
printf 'Exact candidate images built once: %s\n' "$receipt"
