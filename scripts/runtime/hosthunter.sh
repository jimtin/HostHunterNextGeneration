#!/usr/bin/env bash

set -Eeuo pipefail

hosthunter_script_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly hosthunter_script_root
# shellcheck source=scripts/runtime/lib.sh
source "$hosthunter_script_root/lib.sh"

usage() {
  printf '%s\n' \
    'usage: hosthunter.sh init|doctor|build|start|status|invoke|stop|destroy [arguments]' >&2
  exit 64
}

action="${1:-}"
[[ -n "$action" ]] || usage
shift

case "$action" in
  init | doctor | status | stop)
    [[ "$#" -eq 0 ]] || usage
    exec "$runtime_script_root/$action.sh"
    ;;
  build)
    [[ "$#" -eq 0 ]] || usage
    runtime_require_docker
    runtime_compose build controller
    ;;
  start)
    [[ "$#" -eq 0 ]] || usage
    "$runtime_script_root/init.sh"
    if [[ "$HH_VISUALIZER_ENABLED" == true ]]; then
      [[ -n "$HH_VISUALIZER_TOKEN_SOURCE" && -s "$HH_VISUALIZER_TOKEN_SOURCE" ]] || {
        printf 'Configured visualizer producer token is missing or empty. Re-run Install-HHClient.ps1.\n' >&2
        exit 78
      }
      docker network inspect "$HH_VISUALIZER_PRODUCER_NETWORK" >/dev/null 2>&1 || \
        docker network create --internal "$HH_VISUALIZER_PRODUCER_NETWORK" >/dev/null
    fi
    runtime_compose up --build --detach controller
    ;;
  invoke)
    [[ "$#" -ge 1 && "$#" -le 2 ]] || usage
    runtime_compose exec --no-TTY controller /usr/local/bin/hosthunter-controller invoke "$@"
    ;;
  destroy)
    exec "$runtime_script_root/destroy.sh" "$@"
    ;;
  *)
    usage
    ;;
esac
