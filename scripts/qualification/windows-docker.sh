#!/usr/bin/env bash

set -Eeuo pipefail

if [[ $# -lt 5 || $# -gt 7 ]]; then
  printf 'usage: %s CANDIDATE_SHA PACKAGE_ARCHIVE SSH_HOST USER_NAME HOST_KEY_FINGERPRINT [PORT] [RECEIPT_PATH]\n' \
    "$0" >&2
  exit 64
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(git -C "$script_dir/../.." rev-parse --show-toplevel)"
repo_root="$(cd -- "$repo_root" && pwd -P)"
candidate_sha="$1"
package_archive="$(cd -- "$(dirname -- "$2")" && pwd -P)/$(basename -- "$2")"
ssh_host="$3"
user_name="$4"
host_key_fingerprint="$5"
port="${6:-22}"

[[ "$candidate_sha" =~ ^[a-f0-9]{40}$ ]] || {
  printf 'Candidate SHA must be exactly 40 lowercase hexadecimal characters.\n' >&2
  exit 64
}
[[ "$ssh_host" =~ ^[A-Za-z0-9._-]+$ ]] || {
  printf 'SSH host contains unsupported characters.\n' >&2
  exit 64
}
[[ "$user_name" =~ ^[A-Za-z0-9._-]+$ ]] || {
  printf 'SSH user contains unsupported characters.\n' >&2
  exit 64
}
[[ "$host_key_fingerprint" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]] || {
  printf 'Host-key fingerprint is invalid.\n' >&2
  exit 64
}
if [[ ! "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
  printf 'SSH port must be between 1 and 65535.\n' >&2
  exit 64
fi
[[ -f "$package_archive" ]] || {
  printf 'Candidate package archive is missing.\n' >&2
  exit 66
}

candidate_receipt="$repo_root/.artifacts/release/$candidate_sha/receipt.json"
runtime_receipt="$repo_root/.artifacts/release/$candidate_sha/evidence/runtime/runtime-container.json"
receipt_path="${7:-$repo_root/.artifacts/qualification/windows/$candidate_sha/receipt.json}"
[[ -f "$candidate_receipt" && -f "$runtime_receipt" ]] || {
  printf 'Exact candidate or runtime-controller evidence is missing.\n' >&2
  exit 66
}

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  printf 'Docker is unavailable.\n' >&2
  exit 69
fi
command -v jq >/dev/null 2>&1 || {
  printf 'jq is required.\n' >&2
  exit 69
}
[[ -t 0 && -t 1 ]] || {
  printf 'Windows qualification requires an interactive terminal.\n' >&2
  exit 69
}

actual_head="$(git -C "$repo_root" rev-parse HEAD)"
[[ "$actual_head" == "$candidate_sha" ]] || {
  printf 'Qualification requires repository HEAD to equal the exact candidate.\n' >&2
  exit 2
}
[[ -z "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)" ]] || {
  printf 'Qualification requires a clean exact-candidate repository.\n' >&2
  exit 2
}

package_sha256="$(shasum -a 256 "$package_archive" | awk '{print $1}')"
jq -e --arg sha "$candidate_sha" --arg package_sha "$package_sha256" '
  .status == "passed" and .candidateSha == $sha and
  .packageArchiveSha256 == $package_sha and
  (.packageInventorySha256 | test("^[a-f0-9]{64}$"))
' "$candidate_receipt" >/dev/null || {
  printf 'Package archive is not bound to the exact-candidate receipt.\n' >&2
  exit 2
}

controller_image_id="$(jq -r '.controller.imageId' "$runtime_receipt")"
[[ "$controller_image_id" =~ ^sha256:[a-f0-9]{64}$ ]] || {
  printf 'Runtime receipt has no immutable controller image ID.\n' >&2
  exit 2
}
observed_image_id="$(docker image inspect --format '{{.Id}}' "$controller_image_id" 2>/dev/null)" || {
  printf 'The exact runtime controller image is unavailable locally.\n' >&2
  exit 69
}
[[ "$observed_image_id" == "$controller_image_id" ]] || {
  printf 'The runtime controller image ID does not match its proof receipt.\n' >&2
  exit 2
}

project="hosthunter-winqual-${candidate_sha:0:8}-$$"
container_name="${project}-controller"
volume_roles=(data secrets anchors ssh evidence parser-socket)
volume_names=()
for role in "${volume_roles[@]}"; do
  volume_names+=("${project}-${role}")
done
temp_root="$(mktemp -d "${TMPDIR:-/tmp}/hosthunter-winqual.XXXXXX")"
provisional_receipt="$temp_root/controller-receipt.json"
cleanup_finished=false

destroy_exact_state() {
  local cleanup_status=0
  docker rm --force "$container_name" >/dev/null 2>&1 || true
  local volume_name
  for volume_name in "${volume_names[@]}"; do
    if docker volume inspect "$volume_name" >/dev/null 2>&1; then
      docker volume rm "$volume_name" >/dev/null 2>&1 || cleanup_status=1
    fi
  done
  for volume_name in "${volume_names[@]}"; do
    if docker volume inspect "$volume_name" >/dev/null 2>&1; then
      cleanup_status=1
    fi
  done
  return "$cleanup_status"
}

cleanup() {
  local exit_status=$?
  if [[ "$cleanup_finished" != true ]]; then
    destroy_exact_state || exit_status=1
  fi
  rm -rf -- "$temp_root"
  exit "$exit_status"
}
trap cleanup EXIT INT TERM HUP

for index in "${!volume_names[@]}"; do
  volume_name="${volume_names[$index]}"
  role="${volume_roles[$index]}"
  if docker volume inspect "$volume_name" >/dev/null 2>&1; then
    printf 'Fresh qualification volume already exists; refusing reuse.\n' >&2
    exit 2
  fi
  docker volume create \
    --label "com.hosthunter.runtime.project=$project" \
    --label "com.hosthunter.runtime.role=$role" \
    "$volume_name" >/dev/null
done

docker run --name "$container_name" --interactive --tty \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 128 \
  --memory 512m \
  --cpus 1.0 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
  --log-driver none \
  --init \
  --network bridge \
  --env HOME=/tmp \
  --env HH_DATA_ROOT=/var/lib/hosthunter-data \
  --env HH_SECRET_PROVIDER=DockerVolume \
  --env HH_SECRET_ROOT=/var/lib/hosthunter-secrets \
  --env HH_ANCHOR_ROOT=/var/lib/hosthunter-anchors \
  --env HH_SSH_ROOT=/var/lib/hosthunter-ssh \
  --env HH_EVIDENCE_ROOT=/var/lib/hosthunter-evidence \
  --env HH_PARSER_SOCKET=/run/hosthunter-parser/parser.sock \
  --env HH_QUALIFICATION_VOLUME_COUNT=6 \
  --volume "${volume_names[0]}:/var/lib/hosthunter-data" \
  --volume "${volume_names[1]}:/var/lib/hosthunter-secrets" \
  --volume "${volume_names[2]}:/var/lib/hosthunter-anchors" \
  --volume "${volume_names[3]}:/var/lib/hosthunter-ssh" \
  --volume "${volume_names[4]}:/var/lib/hosthunter-evidence" \
  --volume "${volume_names[5]}:/run/hosthunter-parser" \
  --volume "$script_dir/Test-HHWindowsController.ps1:/qualification/Test-HHWindowsController.ps1:ro" \
  --volume "$candidate_receipt:/qualification/candidate-receipt.json:ro" \
  --volume "$package_archive:/qualification/package.tar.gz:ro" \
  --entrypoint /opt/microsoft/powershell/7/pwsh \
  "$controller_image_id" \
  -NoLogo -NoProfile -File /qualification/Test-HHWindowsController.ps1 \
  -CandidateSha "$candidate_sha" \
  -PackageArchivePath /qualification/package.tar.gz \
  -CandidateReceiptPath /qualification/candidate-receipt.json \
  -ModuleManifestPath /opt/hosthunter/module/HostHunterNextGeneration.psd1 \
  -ControllerMode LinuxDockerVolume \
  -ControllerImageId "$controller_image_id" \
  -ControllerVolumeProject "$project" \
  -SshHost "$ssh_host" \
  -UserName "$user_name" \
  -HostKeyFingerprint "$host_key_fingerprint" \
  -Port "$port" \
  -ReceiptPath /var/lib/hosthunter-evidence/windows-controller-receipt.json

docker cp \
  "$container_name:/var/lib/hosthunter-evidence/windows-controller-receipt.json" \
  "$provisional_receipt"
docker rm "$container_name" >/dev/null

jq -e \
  --arg sha "$candidate_sha" \
  --arg package_sha "$package_sha256" \
  --arg image_id "$controller_image_id" \
  --arg project "$project" '
  .status == "controller-passed" and
  .candidateSha == $sha and .packageArchiveSha256 == $package_sha and
  .controllerMode == "LinuxDockerVolume" and
  .controllerImageId == $image_id and .controllerVolumeProject == $project and
  .controllerVolumeCount == 6 and
  .controllerVolumeCleanupComplete == false and
  .stablePackagedModuleVerified == true and
  .targetPlatform == "Windows" and
  .directRuntime == "PowerShell7" and .directEdition == "Core" and
  .directExecutionMode == "Direct" and
  .compatibilityRuntime == "WindowsPowerShell51" and
  .compatibilityEdition == "Desktop" and
  .compatibilityExecutionMode == "WindowsPowerShellCompatibility" and
  .mixedTargetCount == 2 and .restartPersistenceVerified == true and
  .escalationPreferenceVerified == true and
  .processAuditPowerShell7Verified == true and
  .processAuditWindowsPowerShell51Verified == true and
  .commandLineEnabledEventVerified == true and
  .commandLineDisabledEventVerified == true and
  .processAuditPolicyRestored == true and
  .keyTransitionSucceeded == true and
  .runScopedSshAgentVerified == true and
  .runScopedSshAgentIdentityRemoved == true and
  .runScopedSshAgentStopped == true and
  .passwordAuthenticationPreserved == true and
  .remoteQualificationKeyRemoved == true and
  .cleanupComplete == true and .redacted == true
' "$provisional_receipt" >/dev/null || {
  printf 'The container qualification receipt is incomplete.\n' >&2
  exit 2
}

destroy_exact_state || {
  printf 'Exact six-volume qualification cleanup could not be proven.\n' >&2
  exit 1
}
cleanup_finished=true

mkdir -p -- "$(dirname -- "$receipt_path")"
receipt_tmp="$receipt_path.tmp.$$"
jq --arg finished_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" '
  .status = "passed" |
  .controllerVolumeCleanupComplete = true |
  .controllerVolumesDestroyed = 6 |
  .controllerVolumeDestructionVerifiedBy = "windows-docker.sh" |
  .finishedAtUtc = $finished_at
' "$provisional_receipt" >"$receipt_tmp"
mv -f -- "$receipt_tmp" "$receipt_path"

printf 'Docker-canonical Windows qualification passed: %s\n' "$receipt_path"
