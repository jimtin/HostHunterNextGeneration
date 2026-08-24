#!/usr/bin/env bash

set -Eeuo pipefail

readonly runtime_dir="${HH_SSH_RUNTIME_DIR:-/run/hosthunter-ssh}"
readonly hostkey_dir="${runtime_dir}/hostkeys"
readonly hostkey_file="${hostkey_dir}/ssh_host_ed25519_key"

[[ "$(id --user)" == '0' ]] || {
    printf 'HostHunter SSH fixture host-key rotation must run as root\n' >&2
    exit 77
}
[[ ! -L "${hostkey_dir}" && ! -L "${hostkey_file}" ]] || {
    printf 'HostHunter SSH fixture rotation refused a symbolic link\n' >&2
    exit 65
}

install --directory --mode 0700 --owner root --group root "${hostkey_dir}"
stage_dir="$(mktemp --directory "${hostkey_dir}/.rotate.XXXXXX")"
trap 'rm --recursive --force -- "${stage_dir:-}"' EXIT
ssh-keygen \
    -q \
    -t ed25519 \
    -N '' \
    -C 'hosthunter-disposable-fixture-rotated' \
    -f "${stage_dir}/ssh_host_ed25519_key"
chmod 0600 "${stage_dir}/ssh_host_ed25519_key"
chown root:root "${stage_dir}/ssh_host_ed25519_key"
chmod 0644 "${stage_dir}/ssh_host_ed25519_key.pub"
chown root:root "${stage_dir}/ssh_host_ed25519_key.pub"
mv --force -- "${stage_dir}/ssh_host_ed25519_key" "${hostkey_file}"
mv --force -- "${stage_dir}/ssh_host_ed25519_key.pub" "${hostkey_file}.pub"

fingerprint="$(ssh-keygen -l -E sha256 -f "${hostkey_file}.pub" | awk '{print $2}')"
temporary="$(mktemp "${runtime_dir}/.fingerprint.XXXXXX")"
printf '%s\n' "${fingerprint}" >"${temporary}"
chmod 0644 "${temporary}"
chown root:root "${temporary}"
mv --force -- "${temporary}" "${runtime_dir}/hostkey.sha256"

[[ -s /run/sshd.pid ]]
kill -HUP "$(</run/sshd.pid)"
