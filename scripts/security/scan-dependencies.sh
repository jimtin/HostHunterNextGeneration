#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/security/common.sh
source "$script_dir/common.sh"

hh_security_init
hh_require_docker

osv_image='ghcr.io/google/osv-scanner:v2.5.1@sha256:8108ae94eadea5a02c9bec6e646909d5b790b44bd62d7f5b7f0b1d6d0ffc7734'
host_uid="$(id -u)"
host_gid="$(id -g)"

docker run \
  --rm \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user "$host_uid:$host_gid" \
  --env HOME=/tmp \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=128m \
  --mount "type=bind,src=$HH_SECURITY_REPO_ROOT,dst=/repo,readonly" \
  --mount "type=bind,src=$HH_SECURITY_ARTIFACT_DIR,dst=/out" \
  "$osv_image" scan source \
    --recursive \
    --allow-no-lockfiles \
    --experimental-exclude .git \
    --experimental-exclude .artifacts \
    --format json \
    --output-file /out/osv.json \
    /repo

echo "OSV dependency scan passed"
