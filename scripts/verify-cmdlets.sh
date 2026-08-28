#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly repo_root
source_sha="$(git -C "${repo_root}" rev-parse HEAD)"
readonly source_sha
readonly short_sha="${source_sha:0:12}"
readonly project="hosthunter-cmdlets-${short_sha}-$RANDOM"
readonly controller_image="${HH_RELEASE_CONTROLLER_IMAGE:-hosthunter-controller-cmdlets:${short_sha}}"
readonly verifier_image="${HH_RELEASE_VERIFIER_IMAGE:-hosthunter-verifier:${short_sha}}"
readonly ssh_image="${HH_RELEASE_SSH_IMAGE:-hosthunter-ssh-fixture:${short_sha}}"
readonly artifact_root="${repo_root}/.artifacts/cmdlets/${source_sha}"
readonly receipt_path="${artifact_root}/cmdlets/receipt.json"

cleanup() {
  HH_CMDLET_PROJECT="${project}" \
  HH_SOURCE_SHA="${source_sha}" \
  HH_VERIFIER_IMAGE_ID="unused" \
  HH_CMDLET_VERIFIER_IMAGE="${verifier_image}" \
  HH_CMDLET_SSH_IMAGE="${ssh_image}" \
  HH_CMDLET_ARTIFACT_ROOT="${artifact_root}" \
    docker compose --file "${repo_root}/compose.cmdlets.yml" down \
      --remove-orphans --volumes >/dev/null 2>&1 || true
}

finish() {
  local exit_status=$?
  trap - EXIT INT TERM
  if [[ "${exit_status}" -ne 0 && ! -f "${receipt_path}" ]]; then
    jq -n --arg sha "${source_sha}" --arg error \
      'The verifier stopped before the packaged cmdlet journey could run.' '
      {
        schema: "HostHunter.CmdletVerifierReceipt.v1",
        status: "failed",
        sourceSha: $sha,
        verifierImageId: null,
        moduleManifestSha256: null,
        expectedCommands: [
          "Enable-HHSshKeyAuthentication", "Get-HHAuditOutput", "Get-HHAuditRecord",
          "Get-HHEscalationPreference", "Get-HHTarget", "Get-TargetHostDetails", "Invoke-HHCommand",
          "Remove-HHTarget", "Set-HHEscalationPreference", "Set-HHTarget",
          "Set-HHWindowsProcessAuditPolicy", "Test-HHTarget"
        ],
        observedCommands: [], rowCount: 12, failedCount: 12,
        infrastructureFailure: $error,
        rows: ([
          "Get-HHTarget", "Set-HHTarget", "Get-TargetHostDetails", "Test-HHTarget", "Invoke-HHCommand",
          "Get-HHAuditRecord", "Get-HHAuditOutput", "Enable-HHSshKeyAuthentication",
          "Set-HHWindowsProcessAuditPolicy", "Set-HHEscalationPreference",
          "Get-HHEscalationPreference", "Remove-HHTarget"
        ] | to_entries | map({
          index: (.key + 1), cmdlet: .value, expected: "journey prerequisite",
          status: "not-run", durationMs: 0, observation: null, error: $error,
          databaseBefore: null, databaseAfter: null, databaseDelta: null
        }))
      }
    ' >"${receipt_path}.tmp" && mv -- "${receipt_path}.tmp" "${receipt_path}" || true
  fi
  cleanup
  exit "${exit_status}"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p -- "${artifact_root}/cmdlets"
rm -f -- "${receipt_path}"

if [[ "${HH_RELEASE_IMAGES_PREBUILT:-0}" != 1 ]]; then
  docker build --file "${repo_root}/Dockerfile.runtime" --target production \
    --tag "${controller_image}" "${repo_root}"
  docker build --build-arg "HH_CONTROLLER_IMAGE=${controller_image}" \
    --file "${repo_root}/Dockerfile.cmdlets" --tag "${verifier_image}" "${repo_root}"
  docker build --file "${repo_root}/tests/fixtures/ssh/Dockerfile" \
    --tag "${ssh_image}" "${repo_root}/tests/fixtures/ssh"
fi

verifier_image_id="$(docker image inspect --format '{{.Id}}' "${verifier_image}")"
readonly verifier_image_id
[[ "${verifier_image_id}" =~ ^sha256:[a-f0-9]{64}$ ]]
if [[ -n "${HH_RELEASE_VERIFIER_IMAGE_ID:-}" && \
      "${verifier_image_id}" != "${HH_RELEASE_VERIFIER_IMAGE_ID}" ]]; then
  printf 'Prebuilt verifier image does not match the exact-SHA build receipt.\n' >&2
  exit 2
fi

set +e
HH_CMDLET_PROJECT="${project}" \
HH_SOURCE_SHA="${source_sha}" \
HH_VERIFIER_IMAGE_ID="${verifier_image_id}" \
HH_CMDLET_VERIFIER_IMAGE="${verifier_image}" \
HH_CMDLET_SSH_IMAGE="${ssh_image}" \
HH_CMDLET_ARTIFACT_ROOT="${artifact_root}" \
  "${repo_root}/scripts/lib/run-bounded.sh" cmdlet-verifier 300 120 \
    "${artifact_root}/cmdlets/verifier.log" \
    docker compose --file "${repo_root}/compose.cmdlets.yml" run --rm verifier
readonly verifier_exit=$?
set -e

[[ -f "${receipt_path}" ]] || {
  printf 'Cmdlet verifier did not emit %s\n' "${receipt_path}" >&2
  exit 2
}
jq --exit-status \
  --arg sha "${source_sha}" \
  --arg image "${verifier_image_id}" \
  '.schema == "HostHunter.CmdletVerifierReceipt.v1" and
    .sourceSha == $sha and .verifierImageId == $image and
    .rowCount == 12 and (.rows | length) == 12 and
    ([.rows[].cmdlet] | unique | length) == 12' \
  "${receipt_path}" >/dev/null

if [[ "${verifier_exit}" -ne 0 ]]; then
  jq '{status, failedCount, rows: [.rows[] | select(.status != "passed") | {cmdlet, error}]}' \
    "${receipt_path}" >&2
  exit "${verifier_exit}"
fi
jq --exit-status '.status == "passed" and .failedCount == 0' \
  "${receipt_path}" >/dev/null
printf 'HostHunter 12-cmdlet verifier passed: %s\n' "${receipt_path}"
