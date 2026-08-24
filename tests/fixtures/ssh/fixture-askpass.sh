#!/usr/bin/env bash

set -Eeuo pipefail

readonly runtime_dir="${HH_SSH_RUNTIME_DIR:-/run/hosthunter-ssh}"
readonly password_file="${HH_SSH_PASSWORD_FILE:-${runtime_dir}/password}"
readonly prompt="${1:-}"

case "${prompt}" in
    *[Pp]assword*) ;;
    *)
        printf 'HostHunter fixture askpass refused an unexpected prompt\n' >&2
        exit 65
        ;;
esac

[[ -f "${password_file}" && ! -L "${password_file}" && -s "${password_file}" ]]
[[ "$(stat --format '%a:%u:%g' "${password_file}")" == '640:0:10002' ]] || {
    printf 'HostHunter fixture password ownership or permissions are invalid\n' >&2
    exit 77
}

exec /bin/cat -- "${password_file}"
