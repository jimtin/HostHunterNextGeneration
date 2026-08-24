#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/security/common.sh
source "$script_dir/common.sh"

hh_security_init
hh_require_docker

trivy_image='ghcr.io/aquasecurity/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969'
host_uid="$(id -u)"
host_gid="$(id -g)"

docker run \
  --rm \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user "$host_uid:$host_gid" \
  --env HOME=/tmp \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m \
  --mount "type=bind,src=$HH_SECURITY_REPO_ROOT,dst=/repo,readonly" \
  --mount "type=bind,src=$HH_SECURITY_ARTIFACT_DIR,dst=/out" \
  --mount "type=bind,src=$HH_SECURITY_CACHE_DIR,dst=/cache" \
  "$trivy_image" filesystem \
    --cache-dir /cache \
    --disable-telemetry \
    --exit-code 1 \
    --format json \
    --ignorefile /repo/.trivyignore.yaml \
    --no-progress \
    --output /out/trivy-filesystem.json \
    --scanners vuln,misconfig \
    --severity HIGH,CRITICAL \
    --show-suppressed \
    --skip-dirs /repo/.artifacts \
    --skip-dirs /repo/.git \
    /repo

echo "Trivy filesystem scan passed"
