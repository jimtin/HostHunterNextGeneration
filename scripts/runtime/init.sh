#!/usr/bin/env bash

set -Eeuo pipefail

# shellcheck source=scripts/runtime/lib.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/lib.sh"

runtime_require_docker
existing_count="$(runtime_existing_volume_count)"
if [[ "$existing_count" -ne 0 && \
  "$existing_count" -ne "${#runtime_volume_names[@]}" ]]; then
  printf 'Initialization refused: %s of %s runtime volumes already exist.\n' \
    "$existing_count" "${#runtime_volume_names[@]}" >&2
  exit 65
fi
if [[ "$existing_count" -eq "${#runtime_volume_names[@]}" ]]; then
  runtime_validate_all_volumes
  printf 'Runtime volumes are already initialized for project %s.\n' \
    "$HH_RUNTIME_PROJECT"
  exit 0
fi

created_volumes=()
rollback_created_volumes() {
  if [[ "${#created_volumes[@]}" -gt 0 ]]; then
    docker volume rm "${created_volumes[@]}" >/dev/null 2>&1 || true
  fi
}
trap rollback_created_volumes ERR INT TERM HUP

for index in "${!runtime_volume_names[@]}"; do
  volume_name="${runtime_volume_names[$index]}"
  role="${runtime_volume_roles[$index]}"
  docker volume create \
    --driver local \
    --label "$runtime_project_label=$HH_RUNTIME_PROJECT" \
    --label "$runtime_role_label=$role" \
    "$volume_name" >/dev/null
  created_volumes+=("$volume_name")
done
runtime_validate_all_volumes
trap - ERR INT TERM HUP

printf 'Initialized %s separated trust-domain volumes for project %s. No native state was migrated.\n' \
  "${#runtime_volume_names[@]}" "$HH_RUNTIME_PROJECT"
