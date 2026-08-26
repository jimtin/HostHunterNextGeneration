#!/usr/bin/env bash

set -Eeuo pipefail

# shellcheck source=scripts/runtime/lib.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/lib.sh"

runtime_require_docker
runtime_require_complete_volume_set
controller_id="$(runtime_service_id controller)"
[[ -n "$controller_id" ]] || {
  printf 'The HostHunter controller is not running.\n' >&2
  exit 69
}

inspect() {
  docker inspect --format "$1" "$controller_id"
}
assert_equal() {
  [[ "$1" == "$2" ]] || {
    printf 'Runtime contract failed for %s: expected %s, got %s.\n' "$3" "$2" "$1" >&2
    exit 78
  }
}

assert_equal "$(inspect '{{ .State.Status }}')" running 'controller state'
assert_equal "$(inspect '{{ .State.Health.Status }}')" healthy 'controller health'
assert_equal "$(inspect '{{ .HostConfig.ReadonlyRootfs }}')" true 'read-only root'
assert_equal "$(inspect '{{ json .HostConfig.CapDrop }}')" '["ALL"]' 'capability drop'
assert_equal "$(inspect '{{ json .HostConfig.SecurityOpt }}')" '["no-new-privileges:true"]' 'security options'
assert_equal "$(inspect '{{ .Config.User }}')" '10001:10001' 'runtime identity'
assert_equal "$(inspect '{{ .HostConfig.LogConfig.Type }}')" none 'logging driver'

mounts="$(inspect '{{ range .Mounts }}{{ printf "%s|%s|%t\n" .Name .Destination .RW }}{{ end }}')"
expected_mounts=(
  "$HH_RUNTIME_DATA_VOLUME|/var/lib/hosthunter-data|true"
  "$HH_RUNTIME_SECRET_VOLUME|/var/lib/hosthunter-secrets|true"
  "$HH_RUNTIME_ANCHOR_VOLUME|/var/lib/hosthunter-anchors|true"
  "$HH_RUNTIME_SSH_VOLUME|/var/lib/hosthunter-data/keys|true"
  "$HH_RUNTIME_EVIDENCE_VOLUME|/var/lib/hosthunter-evidence|true"
)
for expected in "${expected_mounts[@]}"; do
  grep --fixed-strings --line-regexp --quiet -- "$expected" <<<"$mounts" || {
    printf 'The controller is missing exact mount %s.\n' "$expected" >&2
    exit 78
  }
done
assert_equal "$(grep -c . <<<"$mounts")" 5 'mount count'
grep --fixed-strings --quiet '/var/run/docker.sock' <<<"$mounts" && {
  printf 'The controller must not mount the Docker socket.\n' >&2
  exit 78
}

printf '{"status":"ready","project":"%s","serviceCount":1,"volumeCount":5,"imageId":"%s"}\n' \
  "$HH_RUNTIME_PROJECT" "$(inspect '{{ .Image }}')"
