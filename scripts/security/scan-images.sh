#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/security/common.sh
source "$script_dir/common.sh"

hh_security_init
hh_require_docker

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <locally-built-image> [<locally-built-image> ...]" >&2
  exit 2
fi

trivy_image='ghcr.io/aquasecurity/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969'
host_uid="$(id -u)"
host_gid="$(id -g)"
temp_base="${TMPDIR:-/tmp}"
temp_base="${temp_base%/}"
image_temp_dir="$(mktemp -d "$temp_base/hh-image-scan.XXXXXX")"

cleanup_image_temp() {
  if [[ -n "${image_temp_dir:-}" && -d "$image_temp_dir" ]]; then
    rm -f -- "$image_temp_dir/image.tar"
    rmdir -- "$image_temp_dir"
  fi
}
trap cleanup_image_temp EXIT

printf 'index\trequested_ref\tresolved_image_id\n' > "$HH_SECURITY_ARTIFACT_DIR/image-inventory.tsv"

image_index=0
for requested_image in "$@"; do
  image_index=$((image_index + 1))
  image_id="$(docker image inspect --format '{{.Id}}' "$requested_image")"

  if [[ ! "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "Docker returned an invalid immutable image ID for: $requested_image" >&2
    exit 2
  fi

  printf '%s\t%s\t%s\n' "$image_index" "$requested_image" "$image_id" \
    >> "$HH_SECURITY_ARTIFACT_DIR/image-inventory.tsv"

  docker image save --output "$image_temp_dir/image.tar" "$image_id"

  docker run \
    --rm \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user "$host_uid:$host_gid" \
    --env HOME=/tmp \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=2g \
    --mount "type=bind,src=$image_temp_dir,dst=/scan,readonly" \
    --mount "type=bind,src=$HH_SECURITY_ARTIFACT_DIR,dst=/out" \
    --mount "type=bind,src=$HH_SECURITY_CACHE_DIR,dst=/cache" \
    "$trivy_image" image \
      --cache-dir /cache \
      --disable-telemetry \
      --exit-code 1 \
      --format json \
      --input /scan/image.tar \
      --no-progress \
      --output "/out/trivy-image-${image_index}.json" \
      --scanners vuln,misconfig \
      --severity HIGH,CRITICAL

  rm -f -- "$image_temp_dir/image.tar"
done

echo "Trivy image scans passed for $image_index image(s)"
