#!/usr/bin/env bash

set -Eeuo pipefail

runtime_script_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
runtime_repo_root="$(cd -- "$runtime_script_root/../.." && pwd -P)"
readonly runtime_script_root runtime_repo_root
readonly runtime_compose_file="$runtime_repo_root/compose.runtime.yml"
# shellcheck disable=SC2034
readonly runtime_project_label='com.hosthunter.runtime.project'
# shellcheck disable=SC2034
readonly runtime_role_label='com.hosthunter.runtime.role'

HH_RUNTIME_PROJECT="${HH_RUNTIME_PROJECT:-hosthunter-next-generation-runtime}"
if [[ ! "$HH_RUNTIME_PROJECT" =~ ^[a-z0-9][a-z0-9_-]{2,47}$ ]]; then
  printf 'HH_RUNTIME_PROJECT must match ^[a-z0-9][a-z0-9_-]{2,47}$.\n' >&2
  exit 64
fi
readonly HH_RUNTIME_PROJECT

HH_RUNTIME_DATA_VOLUME="${HH_RUNTIME_PROJECT}-data"
HH_RUNTIME_SECRET_VOLUME="${HH_RUNTIME_PROJECT}-secrets"
HH_RUNTIME_ANCHOR_VOLUME="${HH_RUNTIME_PROJECT}-anchors"
HH_RUNTIME_SSH_VOLUME="${HH_RUNTIME_PROJECT}-ssh"
HH_RUNTIME_EVIDENCE_VOLUME="${HH_RUNTIME_PROJECT}-evidence"
HH_RUNTIME_PARSER_SOCKET_VOLUME="${HH_RUNTIME_PROJECT}-parser-socket"
HH_RUNTIME_CONTROLLER_IMAGE="${HH_RUNTIME_PROJECT}-controller:local"
HH_RUNTIME_PARSER_IMAGE="${HH_RUNTIME_PROJECT}-parser:local"
HH_RUNTIME_JOURNEY_IMAGE="${HH_RUNTIME_PROJECT}-journey:local"
HH_RUNTIME_SSH_FIXTURE_IMAGE="${HH_RUNTIME_PROJECT}-ssh-fixture:local"
export HH_RUNTIME_PROJECT \
  HH_RUNTIME_DATA_VOLUME \
  HH_RUNTIME_SECRET_VOLUME \
  HH_RUNTIME_ANCHOR_VOLUME \
  HH_RUNTIME_SSH_VOLUME \
  HH_RUNTIME_EVIDENCE_VOLUME \
  HH_RUNTIME_PARSER_SOCKET_VOLUME \
  HH_RUNTIME_CONTROLLER_IMAGE \
  HH_RUNTIME_PARSER_IMAGE \
  HH_RUNTIME_JOURNEY_IMAGE \
  HH_RUNTIME_SSH_FIXTURE_IMAGE

runtime_volume_names=(
  "$HH_RUNTIME_DATA_VOLUME"
  "$HH_RUNTIME_SECRET_VOLUME"
  "$HH_RUNTIME_ANCHOR_VOLUME"
  "$HH_RUNTIME_SSH_VOLUME"
  "$HH_RUNTIME_EVIDENCE_VOLUME"
  "$HH_RUNTIME_PARSER_SOCKET_VOLUME"
)
runtime_volume_roles=(data secrets anchors ssh evidence parser-socket)
readonly runtime_volume_names runtime_volume_roles

runtime_compose() {
  docker compose \
    --project-name "$HH_RUNTIME_PROJECT" \
    --file "$runtime_compose_file" \
    "$@"
}

runtime_require_docker() {
  command -v docker >/dev/null 2>&1 || {
    printf 'Docker is required.\n' >&2
    return 69
  }
  docker info >/dev/null 2>&1 || {
    printf 'The Docker daemon is unavailable.\n' >&2
    return 69
  }
  docker compose version >/dev/null 2>&1 || {
    printf 'Docker Compose v2 is unavailable.\n' >&2
    return 69
  }
}

runtime_volume_exists() {
  docker volume inspect "$1" >/dev/null 2>&1
}

runtime_existing_volume_count() {
  local count=0
  local volume_name
  for volume_name in "${runtime_volume_names[@]}"; do
    if runtime_volume_exists "$volume_name"; then
      count=$((count + 1))
    fi
  done
  printf '%s\n' "$count"
}

runtime_validate_volume() {
  local volume_name="$1"
  local expected_role="$2"
  local actual_project actual_role actual_driver

  runtime_volume_exists "$volume_name" || {
    printf 'Required runtime volume is missing: %s\n' "$volume_name" >&2
    return 1
  }
  actual_project="$(docker volume inspect \
    --format '{{ index .Labels "com.hosthunter.runtime.project" }}' \
    "$volume_name")"
  actual_role="$(docker volume inspect \
    --format '{{ index .Labels "com.hosthunter.runtime.role" }}' \
    "$volume_name")"
  actual_driver="$(docker volume inspect --format '{{ .Driver }}' "$volume_name")"
  if [[ "$actual_project" != "$HH_RUNTIME_PROJECT" || \
    "$actual_role" != "$expected_role" || "$actual_driver" != local ]]; then
    printf 'Runtime volume ownership validation failed: %s\n' "$volume_name" >&2
    return 1
  fi
}

runtime_validate_all_volumes() {
  local index
  for index in "${!runtime_volume_names[@]}"; do
    runtime_validate_volume \
      "${runtime_volume_names[$index]}" \
      "${runtime_volume_roles[$index]}"
  done
}

runtime_require_complete_volume_set() {
  local existing_count
  existing_count="$(runtime_existing_volume_count)"
  if [[ "$existing_count" -ne "${#runtime_volume_names[@]}" ]]; then
    printf 'Expected all %s project-owned runtime volumes; found %s. Partial lifecycle state is refused.\n' \
      "${#runtime_volume_names[@]}" "$existing_count" >&2
    return 1
  fi
  runtime_validate_all_volumes
}

runtime_service_id() {
  runtime_compose ps --quiet "$1"
}
