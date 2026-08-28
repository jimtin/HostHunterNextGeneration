#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -lt 5 || $# -gt 6 ]]; then
  printf 'usage: %s HOST USER FINGERPRINT RESTORE_STATE CANDIDATE_SHA [PORT]\n' "$0" >&2
  exit 64
fi

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
host="$1"
user_name="$2"
fingerprint="$3"
restore_state="$4"
candidate_sha="$5"
port="${6:-22}"
receipt_dir="$repo_root/.artifacts/qualification/windows/$candidate_sha"
receipt="$receipt_dir/receipt.json"
build_receipt="${HH_RELEASE_BUILD_RECEIPT:-$repo_root/.artifacts/summary/build.json}"

[[ -t 0 && -t 1 ]] || { printf 'Windows qualification requires an interactive terminal.\n' >&2; exit 69; }
[[ "$candidate_sha" =~ ^[a-f0-9]{40}$ ]] || exit 64
[[ "$fingerprint" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]] || exit 64
[[ "$restore_state" == Enabled || "$restore_state" == Disabled ]] || exit 64
[[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)) || exit 64
[[ "$(git -C "$repo_root" rev-parse HEAD)" == "$candidate_sha" ]] || exit 2
[[ -z "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)" ]] || exit 2
[[ ! -e "$receipt" ]] || { printf 'Windows qualification receipt already exists; refusing rerun.\n' >&2; exit 73; }
[[ -f "$build_receipt" ]] || { printf 'Exact-SHA build receipt is missing.\n' >&2; exit 66; }

image_id="$(jq -r --arg sha "$candidate_sha" '
  select(.status=="passed" and .candidateSha==$sha) | .images.controller.id
' "$build_receipt")"
[[ "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]] || { printf 'Build receipt has no exact controller image.\n' >&2; exit 2; }
[[ "$(docker image inspect --format '{{.Id}}' "$image_id")" == "$image_id" ]] || exit 2

project="hosthunter-windows-${candidate_sha:0:12}-$$"
container="$project-controller"
roles=(data secrets anchors ssh evidence)
volumes=()
for role in "${roles[@]}"; do
  volumes+=("$project-$role")
  docker volume create --label "com.hosthunter.runtime.project=$project" \
    --label "com.hosthunter.runtime.role=$role" "$project-$role" >/dev/null
done

cleanup() {
  local status=$?
  docker rm --force "$container" >/dev/null 2>&1 || true
  docker volume rm "${volumes[@]}" >/dev/null 2>&1 || status=1
  exit "$status"
}
trap cleanup EXIT INT TERM HUP

mkdir -p -- "$receipt_dir"
container_status=0
docker run --name "$container" --interactive --tty --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 128 --memory 512m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 --network bridge \
  --env HOME=/tmp --env HH_DATA_ROOT=/var/lib/hosthunter-data \
  --env HH_SECRET_PROVIDER=DockerVolume --env HH_SECRET_ROOT=/var/lib/hosthunter-secrets \
  --env HH_ANCHOR_ROOT=/var/lib/hosthunter-anchors \
  --env HH_SSH_ROOT=/var/lib/hosthunter-data/keys \
  --env HH_EVIDENCE_ROOT=/var/lib/hosthunter-evidence \
  --volume "${volumes[0]}:/var/lib/hosthunter-data" \
  --volume "${volumes[1]}:/var/lib/hosthunter-secrets" \
  --volume "${volumes[2]}:/var/lib/hosthunter-anchors" \
  --volume "${volumes[3]}:/var/lib/hosthunter-data/keys" \
  --volume "${volumes[4]}:/var/lib/hosthunter-evidence" \
  --volume "$repo_root/scripts/qualification/Test-HHWindowsCmdlets.ps1:/qualification/Test-HHWindowsCmdlets.ps1:ro" \
  --entrypoint pwsh "$image_id" -NoLogo -NoProfile \
  -File /qualification/Test-HHWindowsCmdlets.ps1 \
  -ModuleManifestPath /opt/hosthunter/module/HostHunterNextGeneration.psd1 \
  -SshHost "$host" -UserName "$user_name" -HostKeyFingerprint "$fingerprint" \
  -Port "$port" -RestoreProcessCreationState "$restore_state" \
  -CandidateSha "$candidate_sha" -ControllerImageId "$image_id" \
  -ReceiptPath /var/lib/hosthunter-evidence/windows-receipt.json || container_status=$?

if ! docker cp "$container:/var/lib/hosthunter-evidence/windows-receipt.json" "$receipt.tmp"; then
  printf 'Windows qualification did not emit its terminal receipt.\n' >&2
  exit "${container_status:-1}"
fi
if ((container_status != 0)); then
  jq '{status, failure, policyRestored, remoteQualificationKeyRemoved, rows}' "$receipt.tmp" >&2
  exit "$container_status"
fi
jq -e --arg sha "$candidate_sha" --arg image "$image_id" '
  .status=="passed" and .candidateSha==$sha and .controllerImageId==$image and
  .targetPlatform=="Windows" and .targetRuntime=="PowerShell7" and
  .noAutomaticRetries==true and .policyRestored==true and
  .remoteQualificationKeyRemoved==true and .windowsAuditEventVerified==true and
  (.rows|length)==12 and
  ([.rows[].cmdlet]|unique|length)==12 and ([.rows[].status]|unique)==["passed"]
' "$receipt.tmp" >/dev/null
chmod 0400 "$receipt.tmp"
mv -- "$receipt.tmp" "$receipt"
printf 'Windows cmdlet qualification passed: %s\n' "$receipt"
