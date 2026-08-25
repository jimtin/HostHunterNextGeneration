#!/usr/bin/env bash

set -Eeuo pipefail

# shellcheck source=scripts/runtime/lib.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/lib.sh"

runtime_require_docker
[[ -f "$runtime_compose_file" ]] || {
  printf 'The runtime Compose file is missing.\n' >&2
  exit 66
}
runtime_compose config --quiet
runtime_require_complete_volume_set

printf '{"status":"ready","project":"%s","volumeCount":%s,"nativeMigration":false}\n' \
  "$HH_RUNTIME_PROJECT" "${#runtime_volume_names[@]}"
