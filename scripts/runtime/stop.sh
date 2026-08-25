#!/usr/bin/env bash

set -Eeuo pipefail

# shellcheck source=scripts/runtime/lib.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/lib.sh"

runtime_require_docker
runtime_compose --profile acceptance down --remove-orphans
printf 'Stopped runtime project %s without deleting external volumes.\n' \
  "$HH_RUNTIME_PROJECT"
