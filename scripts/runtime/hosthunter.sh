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
    runtime_compose up --build --detach controller
    ;;
  invoke)
    [[ "$#" -ge 1 && "$#" -le 2 ]] || usage
    exec docker compose \
      --project-name "$HH_RUNTIME_PROJECT" \
      --file "$runtime_compose_file" \
      exec --no-TTY controller /usr/local/bin/hosthunter-controller \
        invoke "$@"
    ;;
  destroy)
    exec "$runtime_script_root/destroy.sh" "$@"
    ;;
  *)
    usage
    ;;
esac
