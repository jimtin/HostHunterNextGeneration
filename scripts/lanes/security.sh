#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
security_dir="$(cd -- "$script_dir/../security" && pwd -P)"

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <test-image> [<additional-image> ...]" >&2
  exit 2
fi

test_image="$1"

"$script_dir/../../tests/security/scan-secrets-contract.sh"
"$security_dir/scan-secrets.sh"
"$security_dir/scan-dependencies.sh"
"$security_dir/scan-filesystem.sh"

# shellcheck source=scripts/security/common.sh
source "$security_dir/common.sh"
hh_security_init
hh_require_docker

test_image_id="$(docker image inspect --format '{{.Id}}' "$test_image")"
if [[ ! "$test_image_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "Docker returned an invalid immutable image ID for: $test_image" >&2
  exit 2
fi

host_uid="$(id -u)"
host_gid="$(id -g)"

docker run \
  --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user "$host_uid:$host_gid" \
  --env HOME=/tmp \
  --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=64m" \
  --mount "type=bind,src=$HH_SECURITY_REPO_ROOT,dst=/workspace,readonly" \
  --mount "type=bind,src=$HH_SECURITY_ARTIFACT_DIR,dst=/out" \
  --entrypoint pwsh \
  "$test_image_id" \
    -NoLogo \
    -NoProfile \
    -NonInteractive \
    -File /workspace/scripts/security/Test-ModulePins.ps1 \
    -ReportPath /out/module-pins.json

"$security_dir/scan-images.sh" "$@"

echo "Security validation passed"
