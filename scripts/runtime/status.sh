#!/usr/bin/env bash

set -Eeuo pipefail

# shellcheck source=scripts/runtime/lib.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/lib.sh"

runtime_require_docker
runtime_require_complete_volume_set

controller_id="$(runtime_service_id controller)"
parser_id="$(runtime_service_id parser)"
[[ -n "$controller_id" && -n "$parser_id" ]] || {
  printf 'The controller and parser services must both be running.\n' >&2
  exit 69
}

inspect() {
  docker inspect --format "$1" "$2"
}

assert_equal() {
  local actual="$1"
  local expected="$2"
  local description="$3"
  [[ "$actual" == "$expected" ]] || {
    printf 'Runtime contract failed for %s: expected %s, got %s.\n' \
      "$description" "$expected" "$actual" >&2
    exit 78
  }
}

controller_state="$(inspect '{{ .State.Status }}' "$controller_id")"
parser_state="$(inspect '{{ .State.Status }}' "$parser_id")"
controller_health="$(inspect '{{ .State.Health.Status }}' "$controller_id")"
parser_health="$(inspect '{{ .State.Health.Status }}' "$parser_id")"
assert_equal "$controller_state" running 'controller state'
assert_equal "$parser_state" running 'parser state'
assert_equal "$controller_health" healthy 'controller health'
assert_equal "$parser_health" healthy 'parser health'

for service_id in "$controller_id" "$parser_id"; do
  assert_equal "$(inspect '{{ .HostConfig.ReadonlyRootfs }}' "$service_id")" \
    true 'read-only root filesystem'
  assert_equal "$(inspect '{{ json .HostConfig.CapDrop }}' "$service_id")" \
    '["ALL"]' 'dropped capabilities'
  assert_equal "$(inspect '{{ json .HostConfig.SecurityOpt }}' "$service_id")" \
    '["no-new-privileges:true"]' 'no-new-privileges'
  assert_equal "$(inspect '{{ .HostConfig.LogConfig.Type }}' "$service_id")" \
    none 'disabled logging driver'
  assert_equal "$(inspect '{{ .Config.User }}' "$service_id")" \
    '10001:10001' 'non-root identity'
  tmpfs_contract="$(inspect '{{ json .HostConfig.Tmpfs }}' "$service_id")"
  [[ "$tmpfs_contract" == *'"/tmp"'* && "$tmpfs_contract" == *'size=64m'* ]] || {
    printf 'Runtime contract failed for bounded /tmp tmpfs.\n' >&2
    exit 78
  }
done

controller_network="$(inspect '{{ .HostConfig.NetworkMode }}' "$controller_id")"
parser_network="$(inspect '{{ .HostConfig.NetworkMode }}' "$parser_id")"
[[ "$controller_network" != none && -n "$controller_network" ]] || {
  printf 'The controller has no outbound network for SSH.\n' >&2
  exit 78
}
assert_equal "$parser_network" none 'parser network isolation'

assert_equal "$(inspect '{{ .HostConfig.Memory }}' "$controller_id")" \
  536870912 'controller memory limit'
assert_equal "$(inspect '{{ .HostConfig.NanoCpus }}' "$controller_id")" \
  1000000000 'controller CPU limit'
assert_equal "$(inspect '{{ .HostConfig.PidsLimit }}' "$controller_id")" \
  128 'controller PID limit'
assert_equal "$(inspect '{{ .HostConfig.Memory }}' "$parser_id")" \
  268435456 'parser memory limit'
assert_equal "$(inspect '{{ .HostConfig.NanoCpus }}' "$parser_id")" \
  500000000 'parser CPU limit'
assert_equal "$(inspect '{{ .HostConfig.PidsLimit }}' "$parser_id")" \
  64 'parser PID limit'

controller_mounts="$(inspect '{{ range .Mounts }}{{ printf "%s|%s|%t\n" .Name .Destination .RW }}{{ end }}' "$controller_id")"
parser_mounts="$(inspect '{{ range .Mounts }}{{ printf "%s|%s|%t\n" .Name .Destination .RW }}{{ end }}' "$parser_id")"
expected_controller_mounts=(
  "$HH_RUNTIME_DATA_VOLUME|/var/lib/hosthunter-data|true"
  "$HH_RUNTIME_SECRET_VOLUME|/var/lib/hosthunter-secrets|true"
  "$HH_RUNTIME_ANCHOR_VOLUME|/var/lib/hosthunter-anchors|true"
  "$HH_RUNTIME_SSH_VOLUME|/var/lib/hosthunter-data/keys|true"
  "$HH_RUNTIME_EVIDENCE_VOLUME|/var/lib/hosthunter-evidence|true"
  "$HH_RUNTIME_PARSER_SOCKET_VOLUME|/run/hosthunter-parser|true"
)
for mount_contract in "${expected_controller_mounts[@]}"; do
  grep --fixed-strings --line-regexp --quiet -- "$mount_contract" \
    <<<"$controller_mounts" || {
    printf 'The controller is missing exact mount %s.\n' "$mount_contract" >&2
    exit 78
  }
done
assert_equal "$(grep -c . <<<"$controller_mounts")" \
  "${#expected_controller_mounts[@]}" 'controller mount count'

grep --fixed-strings --line-regexp --quiet -- \
  "$HH_RUNTIME_EVIDENCE_VOLUME|/evidence|false" <<<"$parser_mounts" || {
  printf 'The parser evidence volume is not mounted read-only.\n' >&2
  exit 78
}
grep --fixed-strings --line-regexp --quiet -- \
  "$HH_RUNTIME_PARSER_SOCKET_VOLUME|/run/hosthunter-parser|true" \
  <<<"$parser_mounts" || {
  printf 'The parser private socket volume is missing.\n' >&2
  exit 78
}
assert_equal "$(grep -c . <<<"$parser_mounts")" 2 'parser mount count'
if grep --extended-regexp --quiet \
  '/var/lib/hosthunter-(data|secrets|anchors|ssh)|docker\.sock' \
  <<<"$parser_mounts"; then
  printf 'The parser has a forbidden secret, database, SSH, or Docker socket mount.\n' >&2
  exit 78
fi
if grep --fixed-strings --quiet '/var/run/docker.sock' \
  <<<"$controller_mounts$parser_mounts"; then
  printf 'A runtime service has a forbidden Docker socket mount.\n' >&2
  exit 78
fi
parser_environment="$(inspect '{{ range .Config.Env }}{{ println . }}{{ end }}' "$parser_id")"
if grep --extended-regexp --quiet \
  '^HH_(DATA_ROOT|SECRET_PROVIDER|SECRET_ROOT|ANCHOR_ROOT|SSH_ROOT)=' \
  <<<"$parser_environment"; then
  printf 'The parser received a forbidden controller provider variable.\n' >&2
  exit 78
fi

controller_image_id="$(inspect '{{ .Image }}' "$controller_id")"
parser_image_id="$(inspect '{{ .Image }}' "$parser_id")"
receipt_root="$runtime_repo_root/.artifacts/runtime"
receipt_path="$receipt_root/runtime-container.json"
mkdir -p -- "$receipt_root"
receipt_tmp="$receipt_path.tmp.$$"
printf '%s\n' \
  '{' \
  '  "schemaVersion": 1,' \
  "  \"observedAtUtc\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\"," \
  "  \"project\": \"$HH_RUNTIME_PROJECT\"," \
  '  "status": "passed",' \
  '  "controller": {' \
  "    \"imageId\": \"$controller_image_id\"," \
  '    "uidGid": "10001:10001",' \
  '    "readOnlyRootFilesystem": true,' \
  '    "capDropAll": true,' \
  '    "noNewPrivileges": true,' \
  '    "loggingDriver": "none",' \
  '    "dockerSocketMounted": false,' \
  '    "outboundSshNetwork": true,' \
  '    "memoryBytes": 536870912,' \
  '    "nanoCpus": 1000000000,' \
  '    "pidsLimit": 128,' \
  '    "externalVolumeCount": 6' \
  '  },' \
  '  "parser": {' \
  "    \"imageId\": \"$parser_image_id\"," \
  '    "uidGid": "10001:10001",' \
  '    "readOnlyRootFilesystem": true,' \
  '    "capDropAll": true,' \
  '    "noNewPrivileges": true,' \
  '    "loggingDriver": "none",' \
  '    "networkMode": "none",' \
  '    "secretDatabaseOrSshMountCount": 0,' \
  '    "dockerSocketMounted": false,' \
  '    "evidenceReadOnly": true,' \
  '    "privateSocketOnly": true,' \
  '    "memoryBytes": 268435456,' \
  '    "nanoCpus": 500000000,' \
  '    "pidsLimit": 64' \
  '  },' \
  '  "volumes": {' \
  "    \"data\": \"$HH_RUNTIME_DATA_VOLUME\"," \
  "    \"secrets\": \"$HH_RUNTIME_SECRET_VOLUME\"," \
  "    \"anchors\": \"$HH_RUNTIME_ANCHOR_VOLUME\"," \
  "    \"ssh\": \"$HH_RUNTIME_SSH_VOLUME\"," \
  "    \"evidence\": \"$HH_RUNTIME_EVIDENCE_VOLUME\"," \
  "    \"parserSocket\": \"$HH_RUNTIME_PARSER_SOCKET_VOLUME\"" \
  '  }' \
  '}' >"$receipt_tmp"
mv -- "$receipt_tmp" "$receipt_path"
printf '%s\n' "$receipt_path"
