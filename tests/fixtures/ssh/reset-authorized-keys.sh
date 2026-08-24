#!/usr/bin/env bash

set -Eeuo pipefail

readonly fixture_user="hhfixture"
readonly fixture_group="hhfixture"
readonly ssh_dir="/home/${fixture_user}/.ssh"
readonly authorized_keys="${ssh_dir}/authorized_keys"

[[ "$(id --user)" == '0' ]] || {
    printf 'HostHunter SSH fixture reset must run as root\n' >&2
    exit 77
}
[[ ! -L "${ssh_dir}" && ! -L "${authorized_keys}" ]] || {
    printf 'HostHunter SSH fixture reset refused a symbolic link\n' >&2
    exit 65
}

install --directory --mode 0700 --owner "${fixture_user}" --group "${fixture_group}" \
    "${ssh_dir}"
temporary="$(mktemp "${ssh_dir}/.authorized_keys.XXXXXX")"
trap 'rm --force -- "${temporary:-}"' EXIT
chmod 0600 "${temporary}"
chown "${fixture_user}:${fixture_group}" "${temporary}"

if [[ -n "${HH_SSH_AUTHORIZED_KEYS_BASELINE:-}" ]]; then
    [[ -f "${HH_SSH_AUTHORIZED_KEYS_BASELINE}" && \
        ! -L "${HH_SSH_AUTHORIZED_KEYS_BASELINE}" ]] || {
        printf 'HostHunter SSH fixture baseline is invalid\n' >&2
        exit 66
    }
    /bin/cat -- "${HH_SSH_AUTHORIZED_KEYS_BASELINE}" >"${temporary}"
fi

mv --force -- "${temporary}" "${authorized_keys}"
trap - EXIT
chmod 0600 "${authorized_keys}"
chown "${fixture_user}:${fixture_group}" "${authorized_keys}"
