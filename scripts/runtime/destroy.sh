#!/usr/bin/env bash

set -Eeuo pipefail

# shellcheck source=scripts/runtime/lib.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/lib.sh"

usage() {
  printf 'usage: %s --confirm-project %s --destroy-volumes\n' \
    "$0" "$HH_RUNTIME_PROJECT" >&2
  exit 64
}

[[ "$#" -eq 3 ]] || usage
[[ "$1" == '--confirm-project' ]] || usage
[[ "$2" == "$HH_RUNTIME_PROJECT" ]] || {
  printf 'Destruction confirmation did not exactly match project %s.\n' \
    "$HH_RUNTIME_PROJECT" >&2
  exit 64
}
[[ "$3" == '--destroy-volumes' ]] || usage

runtime_require_docker
runtime_require_complete_volume_set
runtime_compose --profile acceptance down --remove-orphans

# Validate ownership and attachment for every target before deletion begins.
runtime_validate_all_volumes
for volume_name in "${runtime_volume_names[@]}"; do
  attached_containers="$(docker ps --all --quiet --filter "volume=$volume_name")"
  if [[ -n "$attached_containers" ]]; then
    printf 'Destruction refused because volume %s remains attached.\n' \
      "$volume_name" >&2
    exit 74
  fi
done

# Docker does not provide an atomic multi-volume delete. Attempt only the exact
# preflighted set, then report any partial lifecycle explicitly.
delete_status=0
docker volume rm "${runtime_volume_names[@]}" >/dev/null || delete_status=$?

remaining=0
survivors=()
for volume_name in "${runtime_volume_names[@]}"; do
  if runtime_volume_exists "$volume_name"; then
    remaining=$((remaining + 1))
    survivors+=("$volume_name")
  fi
done
if [[ "$delete_status" -ne 0 || "$remaining" -ne 0 ]]; then
  printf 'Partial runtime-volume lifecycle detected. Exact survivors: %s. Fix attachment/error state, then rerun the same confirmed destroy command.\n' \
    "${survivors[*]:-none reported}" >&2
  printf 'No file-level provider cleanup was attempted.\n' >&2
  exit 74
fi

printf 'Destroyed all %s exact project-owned volumes for %s and verified absence. This cannot be undone.\n' \
  "${#runtime_volume_names[@]}" "$HH_RUNTIME_PROJECT"
