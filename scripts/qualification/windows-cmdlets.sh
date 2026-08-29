#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
mode=run
candidate_sha=''
if [[ "${1:-}" == --preflight ]]; then
  mode=preflight
  shift
  if [[ $# -gt 1 ]]; then
    printf 'usage: %s --preflight [SOURCE_RUNTIME_PROJECT]\n' "$0" >&2
    exit 64
  fi
  source_project="${1:-${HH_RUNTIME_PROJECT:-hosthunter-next-generation-runtime}}"
else
  if [[ $# -lt 1 || $# -gt 2 ]]; then
    printf 'usage: %s CANDIDATE_SHA [SOURCE_RUNTIME_PROJECT]\n' "$0" >&2
    exit 64
  fi
  candidate_sha="$1"
  source_project="${2:-${HH_RUNTIME_PROJECT:-hosthunter-next-generation-runtime}}"
fi
target_name="${HH_WINDOWS_QUALIFICATION_TARGET:-}"
[[ "$source_project" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]] || {
  printf 'The source runtime project name is invalid.\n' >&2
  exit 64
}

roles=(data secrets anchors ssh evidence)
source_volumes=()
source_controller=''

for role in "${roles[@]}"; do
  source_volume="$source_project-$role"
  expected_project="$(docker volume inspect "$source_volume" \
    --format '{{ index .Labels "com.hosthunter.runtime.project" }}' 2>/dev/null || true)"
  expected_role="$(docker volume inspect "$source_volume" \
    --format '{{ index .Labels "com.hosthunter.runtime.role" }}' 2>/dev/null || true)"
  if [[ "$expected_project" != "$source_project" || "$expected_role" != "$role" ]]; then
    printf 'Source runtime volume is missing or has invalid ownership: %s\n' \
      "$source_volume" >&2
    exit 65
  fi
  source_volumes+=("$source_volume")
done

source_controllers=()
while IFS= read -r controller_id; do
  [[ -z "$controller_id" ]] || source_controllers+=("$controller_id")
done < <(docker ps --format '{{.ID}}' \
  --filter "label=com.docker.compose.project=$source_project" \
  --filter 'label=com.docker.compose.service=controller')
if [[ ${#source_controllers[@]} -ne 1 ]]; then
  printf 'Exactly one source HostHunter runtime controller must be active; observed %s.\n' \
    "${#source_controllers[@]}" >&2
  exit 65
fi
source_controller="${source_controllers[0]}"

for source_volume in "${source_volumes[@]}"; do
  source_users=()
  while IFS= read -r user_id; do
    [[ -z "$user_id" ]] || source_users+=("$user_id")
  done < <(docker ps --format '{{.ID}}' --filter "volume=$source_volume")
  if [[ ${#source_users[@]} -ne 1 || "${source_users[0]}" != "$source_controller" ]]; then
    printf 'Source runtime volume has an unexpected active user: %s\n' \
      "$source_volume" >&2
    exit 65
  fi
done

if ! eligible_output="$(docker exec \
  --env "HH_QUALIFICATION_TARGET_NAME=$target_name" \
  "$source_controller" pwsh -NoLogo -NoProfile -NonInteractive -Command '
    $ErrorActionPreference = "Stop"
    Import-Module /opt/hosthunter/module/HostHunterNextGeneration.psd1 -Force
    $selected = @(Get-HHTarget | Where-Object {
        $_.IsActive -and $_.Transport -ceq "SSH" -and
        $_.Authentication -ceq "PublicKey" -and
        [IO.File]::Exists($_.KeyPath) -and
        ([string]::IsNullOrWhiteSpace($env:HH_QUALIFICATION_TARGET_NAME) -or
            $_.Name -ieq $env:HH_QUALIFICATION_TARGET_NAME)
    })
    $selected.Count
  ' 2>&1)"; then
  printf 'Unable to inspect saved-key Windows qualification state.\n%s\n' \
    "$eligible_output" >&2
  exit 65
fi
eligible_count="$(printf '%s\n' "$eligible_output" | tail -n 1 | tr -d '\r')"
if [[ "$eligible_count" != 1 ]]; then
  printf 'Windows qualification requires exactly one selected active SSH public-key target; observed %s.\n' \
    "$eligible_count" >&2
  exit 65
fi

if [[ "$mode" == preflight ]]; then
  printf 'Windows qualification source state is ready: %s\n' "$source_project"
  exit 0
fi

receipt_dir="$repo_root/.artifacts/qualification/windows/$candidate_sha"
receipt="$receipt_dir/receipt.json"
build_receipt="${HH_RELEASE_BUILD_RECEIPT:-$repo_root/.artifacts/summary/build.json}"
[[ "$candidate_sha" =~ ^[a-f0-9]{40}$ ]] || exit 64
[[ "$(git -C "$repo_root" rev-parse HEAD)" == "$candidate_sha" ]] || exit 2
[[ -z "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)" ]] || exit 2
[[ ! -e "$receipt" ]] || {
  printf 'Windows qualification receipt already exists; refusing rerun.\n' >&2
  exit 73
}
[[ -f "$build_receipt" ]] || {
  printf 'Exact-SHA build receipt is missing.\n' >&2
  exit 66
}

image_id="$(jq -r --arg sha "$candidate_sha" '
  select(.status=="passed" and .candidateSha==$sha) | .images.controller.id
' "$build_receipt")"
[[ "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]] || {
  printf 'Build receipt has no exact controller image.\n' >&2
  exit 2
}
[[ "$(docker image inspect --format '{{.Id}}' "$image_id")" == "$image_id" ]] || exit 2

project="hosthunter-windows-${candidate_sha:0:12}-$$"
container="$project-controller"
volumes=()
source_paused=false

cleanup() {
  local status=$?
  if [[ "$source_paused" == true && -n "$source_controller" ]]; then
    docker unpause "$source_controller" >/dev/null 2>&1 || status=1
    source_paused=false
  fi
  docker rm --force "$container" >/dev/null 2>&1 || true
  if [[ ${#volumes[@]} -gt 0 ]]; then
    docker volume rm "${volumes[@]}" >/dev/null 2>&1 || status=1
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM HUP

for role in "${roles[@]}"; do
  qualification_volume="$project-$role"
  volumes+=("$qualification_volume")
  docker volume create --label "com.hosthunter.runtime.project=$project" \
    --label "com.hosthunter.runtime.role=$role" "$qualification_volume" >/dev/null
done
docker pause "$source_controller" >/dev/null
source_paused=true
for index in "${!roles[@]}"; do
  docker run --rm --network none --read-only --workdir / --user 0:0 \
    --cap-drop ALL --cap-add CHOWN \
    --security-opt no-new-privileges:true \
    --volume "${volumes[$index]}:/destination" \
    --entrypoint sh "$image_id" -ceu '
      chmod 0700 /destination
      chown 10001:10001 /destination
    '
  docker run --rm --network none --read-only --workdir / --user 10001:10001 \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --volume "${source_volumes[$index]}:/source:ro" \
    --volume "${volumes[$index]}:/destination" \
    --entrypoint sh "$image_id" -ceu '
      test -z "$(find /destination -mindepth 1 -print -quit)"
      cp -a /source/. /destination/
    '
done
docker unpause "$source_controller" >/dev/null
source_paused=false

mkdir -p -- "$receipt_dir"
qualification_arguments=(
  -NoLogo -NoProfile -NonInteractive
  -File /qualification/Test-HHWindowsCmdlets.ps1
  -ModuleManifestPath /opt/hosthunter/module/HostHunterNextGeneration.psd1
  -CandidateSha "$candidate_sha"
  -ControllerImageId "$image_id"
  -ReceiptPath /var/lib/hosthunter-evidence/windows-receipt.json
)
if [[ -n "$target_name" ]]; then
  qualification_arguments+=(-TargetName "$target_name")
fi

container_status=0
docker run --name "$container" --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 128 --memory 512m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 --network bridge \
  --env HOME=/tmp --env HH_DATA_ROOT=/var/lib/hosthunter-data \
  --env HH_SECRET_PROVIDER=DockerVolume \
  --env HH_SECRET_ROOT=/var/lib/hosthunter-secrets \
  --env HH_ANCHOR_ROOT=/var/lib/hosthunter-anchors \
  --env HH_SSH_ROOT=/var/lib/hosthunter-data/keys \
  --env HH_EVIDENCE_ROOT=/var/lib/hosthunter-evidence \
  --volume "${volumes[0]}:/var/lib/hosthunter-data" \
  --volume "${volumes[1]}:/var/lib/hosthunter-secrets" \
  --volume "${volumes[2]}:/var/lib/hosthunter-anchors" \
  --volume "${volumes[3]}:/var/lib/hosthunter-data/keys" \
  --volume "${volumes[4]}:/var/lib/hosthunter-evidence" \
  --volume "$repo_root/scripts/qualification/Test-HHWindowsCmdlets.ps1:/qualification/Test-HHWindowsCmdlets.ps1:ro" \
  --entrypoint pwsh "$image_id" "${qualification_arguments[@]}" || container_status=$?

if ! docker cp "$container:/var/lib/hosthunter-evidence/windows-receipt.json" \
  "$receipt.tmp"; then
  printf 'Windows qualification did not emit its terminal receipt.\n' >&2
  exit "${container_status:-1}"
fi
if ((container_status != 0)); then
  jq -e --arg sha "$candidate_sha" --arg image "$image_id" '
    (.status=="failed" or .status=="blocked" or .status=="aborted") and
    .candidateSha==$sha and .controllerImageId==$image
  ' "$receipt.tmp" >/dev/null || {
    printf 'Windows qualification emitted an incoherent failure receipt.\n' >&2
    exit 1
  }
  chmod 0400 "$receipt.tmp"
  mv -- "$receipt.tmp" "$receipt"
  jq '{status, failure, policyRestored, operatorStateCloned, rows}' "$receipt" >&2
  exit "$container_status"
fi
jq -e --arg sha "$candidate_sha" --arg image "$image_id" '
  .status=="passed" and .candidateSha==$sha and .controllerImageId==$image and
  .targetPlatform=="Windows" and .targetRuntime=="PowerShell7" and
  .noAutomaticRetries==true and .policyRestored==true and
  .authenticationMode=="existing-public-key" and .operatorStateCloned==true and
  .cloneMissionPaused==true and .windowsAuditEventVerified==true and
  (.rows|length)==12 and
  ([.rows[].cmdlet]|unique|length)==12 and ([.rows[].status]|unique)==["passed"]
' "$receipt.tmp" >/dev/null
chmod 0400 "$receipt.tmp"
mv -- "$receipt.tmp" "$receipt"
printf 'Windows cmdlet qualification passed: %s\n' "$receipt"
