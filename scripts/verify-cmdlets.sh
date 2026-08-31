#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly repo_root
source_sha="$(git -C "${repo_root}" rev-parse HEAD)"
readonly source_sha
readonly short_sha="${source_sha:0:12}"
readonly project="hosthunter-cmdlets-${short_sha}-$RANDOM"
source_fingerprint="$(pwsh -NoLogo -NoProfile -NonInteractive \
  -File "${repo_root}/scripts/client/Get-HHSourceFingerprint.ps1" \
  -RepoRoot "${repo_root}")"
readonly source_fingerprint
[[ "${source_fingerprint}" =~ ^[a-f0-9]{64}$ ]]
dirty_tree=false
if [[ -n "$(git -C "${repo_root}" status --porcelain=v1 --untracked-files=all)" ]]; then
  dirty_tree=true
fi
readonly dirty_tree
source_manifest="${repo_root}/src/HostHunterNextGeneration/HostHunterNextGeneration.psd1"
# The embedded PowerShell must receive its dollar-prefixed variables literally.
# shellcheck disable=SC2016
expected_commands_json="$(HH_SOURCE_MANIFEST="${source_manifest}" \
  pwsh -NoLogo -NoProfile -NonInteractive -Command '
    $manifest = Import-PowerShellDataFile -LiteralPath $env:HH_SOURCE_MANIFEST
    $declared = @($manifest.FunctionsToExport)
    $expected = @($declared | Sort-Object -Unique)
    if ($expected.Count -eq 0 -or $declared.Count -ne $expected.Count) { exit 2 }
    ConvertTo-Json -InputObject $expected -Compress
  ')"
readonly expected_commands_json
expected_count="$(jq 'length' <<<"${expected_commands_json}")"
readonly expected_count
[[ "${expected_count}" =~ ^[1-9][0-9]*$ ]]
if [[ "${HH_RELEASE_IMAGES_PREBUILT:-0}" == 1 ]]; then
  controller_image="${HH_RELEASE_CONTROLLER_IMAGE:?Prebuilt controller image is required}"
  verifier_image="${HH_RELEASE_VERIFIER_IMAGE:?Prebuilt verifier image is required}"
  ssh_image="${HH_RELEASE_SSH_IMAGE:?Prebuilt SSH fixture image is required}"
else
  controller_image="${HH_CMDLET_CONTROLLER_IMAGE:-hosthunter-next-generation-runtime-controller:local}"
  verifier_image="$controller_image"
  ssh_image="${HH_CMDLET_SSH_IMAGE:-hosthunter-next-generation-ssh-fixture:local}"
fi
readonly controller_image verifier_image ssh_image
if [[ "${HH_RELEASE_IMAGES_PREBUILT:-0}" == 1 ]]; then
  run_id="release-${short_sha}"
  artifact_root="${repo_root}/.artifacts/cmdlets/${source_sha}"
else
  run_id="${HH_CMDLET_RUN_ID:-$(date -u '+%Y%m%dT%H%M%SZ')-$$-${RANDOM}}"
  artifact_root="${repo_root}/.artifacts/cmdlets/${source_fingerprint}/${run_id}"
fi
readonly run_id artifact_root
[[ "${run_id}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{2,95}$ ]]
readonly receipt_path="${artifact_root}/cmdlets/receipt.json"
readonly verifier_log="${artifact_root}/cmdlets/verifier.log"
HH_FIXTURE_SECRET_GID=10002
HH_HOST_ARTIFACT_GID="$(id -g)"
readonly HH_FIXTURE_SECRET_GID HH_HOST_ARTIFACT_GID
[[ "${HH_FIXTURE_SECRET_GID}" =~ ^[1-9][0-9]*$ &&
  "${HH_HOST_ARTIFACT_GID}" =~ ^[0-9]+$ &&
  "${HH_FIXTURE_SECRET_GID}" != "${HH_HOST_ARTIFACT_GID}" ]]
export HH_FIXTURE_SECRET_GID HH_HOST_ARTIFACT_GID
export HH_SOURCE_FINGERPRINT="${source_fingerprint}"
export HH_CMDLET_RUN_ID="${run_id}"
export HH_DIRTY_TREE="${dirty_tree}"
failure_phase=preflight
failure_message='The verifier wrapper stopped before container execution.'
verifier_image_id=''

cleanup() {
  HH_CMDLET_PROJECT="${project}" \
  HH_SOURCE_SHA="${source_sha}" \
  HH_VERIFIER_IMAGE_ID="unused" \
  HH_CMDLET_VERIFIER_IMAGE="${verifier_image}" \
  HH_CMDLET_SSH_IMAGE="${ssh_image}" \
  HH_CMDLET_REPO_ROOT="${repo_root}" \
  HH_CMDLET_ARTIFACT_ROOT="${artifact_root}" \
    docker compose --file "${repo_root}/compose.cmdlets.yml" down \
      --remove-orphans --volumes >/dev/null 2>&1 || true
}

finish() {
  local exit_status=$?
  local receipt_error="${failure_message}"
  trap - EXIT INT TERM
  if [[ "${exit_status}" -ne 0 && ! -f "${receipt_path}" ]]; then
    if [[ -s "${verifier_log}" ]]; then
      receipt_error="$(tail -n 8 "${verifier_log}" | tr '\r\n' '  ' | cut -c1-2048)"
    fi
    jq -n --arg sha "${source_sha}" \
      --arg fingerprint "${source_fingerprint}" \
      --arg runId "${run_id}" \
      --arg dirty "${dirty_tree}" \
      --arg phase "${failure_phase}" \
      --arg image "${verifier_image_id}" \
      --arg error "${receipt_error}" \
      --argjson expected "${expected_commands_json}" '
      {
        schema: "HostHunter.CmdletVerifierReceipt.v1",
        status: "failed",
        failurePhase: $phase,
        infrastructureFailure: $error,
        journeyFailure: null,
        sourceSha: $sha,
        sourceFingerprint: $fingerprint,
        runId: $runId,
        dirtyTree: ($dirty == "true"),
        verifierImageId: (if $image == "" then null else $image end),
        moduleManifestSha256: null,
        expectedCommands: $expected,
        observedCommands: [],
        rowCount: ($expected | length),
        failedCount: 0,
        migrationCount: 0,
        database: null,
        rows: ($expected | to_entries | map({
          index: (.key + 1), cmdlet: .value, expected: "journey prerequisite",
          status: "not-run", durationMs: 0, observation: null, error: $error,
          databaseBefore: null, databaseAfter: null, databaseDelta: null
        })),
        completedAtUtc: (now | todateiso8601)
      }
    ' >"${receipt_path}.tmp" && mv -- "${receipt_path}.tmp" "${receipt_path}" || true
  fi
  cleanup
  exit "${exit_status}"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"${repo_root}/scripts/lib/prepare-artifacts.sh" "${repo_root}"
mkdir -p -- "${artifact_root}/cmdlets"
chmod 2770 "${artifact_root}" "${artifact_root}/cmdlets"
rm -f -- "${receipt_path}"

if [[ "${HH_RELEASE_IMAGES_PREBUILT:-0}" != 1 ]]; then
  actual_fingerprint="$(docker image inspect --format \
    '{{ index .Config.Labels "com.hosthunter.source-fingerprint" }}' \
    "${controller_image}")"
  if [[ "${actual_fingerprint}" != "${source_fingerprint}" ]]; then
    failure_message='The cached HostHunter controller fingerprint is stale.'
    printf 'The cached HostHunter controller is stale; load HostHunter once to synchronize it before testing.\n' >&2
    exit 2
  fi
  docker image inspect "${ssh_image}" >/dev/null
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
failure_phase=journey
failure_message='The verifier container stopped without an authoritative receipt.'
HH_CMDLET_PROJECT="${project}" \
HH_SOURCE_SHA="${source_sha}" \
HH_VERIFIER_IMAGE_ID="${verifier_image_id}" \
HH_CMDLET_VERIFIER_IMAGE="${verifier_image}" \
HH_CMDLET_SSH_IMAGE="${ssh_image}" \
HH_CMDLET_REPO_ROOT="${repo_root}" \
HH_CMDLET_ARTIFACT_ROOT="${artifact_root}" \
  "${repo_root}/scripts/lib/run-bounded.sh" cmdlet-verifier 90 60 \
    "${verifier_log}" \
    docker compose --file "${repo_root}/compose.cmdlets.yml" run --rm verifier
readonly verifier_exit=$?
set -e

[[ -f "${receipt_path}" ]] || {
  printf 'Cmdlet verifier did not emit %s\n' "${receipt_path}" >&2
  exit 2
}
jq --exit-status \
  --arg sha "${source_sha}" \
  --arg fingerprint "${source_fingerprint}" \
  --arg runId "${run_id}" \
  --arg image "${verifier_image_id}" \
  --argjson expected "${expected_commands_json}" \
  --argjson expectedCount "${expected_count}" \
  '.schema == "HostHunter.CmdletVerifierReceipt.v1" and
    .sourceSha == $sha and .sourceFingerprint == $fingerprint and
    .runId == $runId and .verifierImageId == $image and
    .expectedCommands == $expected and
    .rowCount == $expectedCount and (.rows | length) == $expectedCount and
    ([.rows[].cmdlet] | unique | length) == $expectedCount' \
  "${receipt_path}" >/dev/null

if [[ "${verifier_exit}" -ne 0 ]]; then
  jq '{status, failedCount, rows: [.rows[] | select(.status != "passed") | {cmdlet, error}]}' \
    "${receipt_path}" >&2
  exit "${verifier_exit}"
fi
jq --exit-status '.status == "passed" and .failedCount == 0' \
  "${receipt_path}" >/dev/null
printf 'HostHunter %s-cmdlet verifier passed: %s\n' "${expected_count}" "${receipt_path}"
