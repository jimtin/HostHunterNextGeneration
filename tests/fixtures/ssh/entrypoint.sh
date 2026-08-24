#!/usr/bin/env bash

set -Eeuo pipefail

readonly fixture_user="hhfixture"
readonly fixture_group="hhfixture"
readonly secret_group="hhfixture-secret"
readonly runtime_dir="${HH_SSH_RUNTIME_DIR:-/run/hosthunter-ssh}"
readonly password_file="${runtime_dir}/password"
readonly hostkey_dir="${runtime_dir}/hostkeys"
readonly hostkey_file="${hostkey_dir}/ssh_host_ed25519_key"
readonly ready_file="${runtime_dir}/ready"

fail() {
    printf 'HostHunter SSH fixture: %s\n' "$*" >&2
    exit 1
}

write_atomic() {
    local destination="$1"
    local mode="$2"
    local owner="$3"
    local group="$4"
    local value="$5"
    local temporary

    temporary="$(mktemp "${runtime_dir}/.write.XXXXXX")"
    chmod "${mode}" "${temporary}"
    chown "${owner}:${group}" "${temporary}"
    printf '%s\n' "${value}" >"${temporary}"
    mv --force -- "${temporary}" "${destination}"
}

[[ "${runtime_dir}" == /* ]] || fail 'HH_SSH_RUNTIME_DIR must be absolute'
[[ "$(id --user)" == '0' ]] || fail 'the fixture entrypoint must run as root'
[[ "$(getent group "${secret_group}" | cut -d: -f3)" == '10002' ]] || \
    fail 'the fixture secret group must retain GID 10002'

install --directory --mode 0755 /run/sshd
install --directory --mode 0750 --owner root --group "${secret_group}" "${runtime_dir}"
install --directory --mode 0700 --owner root --group root "${hostkey_dir}"
rm --force -- "${ready_file}"

if [[ -L "${password_file}" ]]; then
    fail 'refusing a symbolic-link password path'
fi

if [[ ! -e "${password_file}" ]]; then
    password="$(od -An -N32 -tx1 /dev/urandom | tr -d '[:space:]')"
    [[ "${password}" =~ ^[0-9a-f]{64}$ ]] || fail 'password generation failed'
    write_atomic "${password_file}" 0640 root "${secret_group}" "${password}"
    unset password
fi

[[ -f "${password_file}" && -s "${password_file}" ]] || fail 'password file is invalid'
chmod 0640 "${password_file}"
chown "root:${secret_group}" "${password_file}"
password="$(<"${password_file}")"
[[ "${password}" =~ ^[0-9a-f]{64}$ ]] || fail 'password file has an invalid format'
printf '%s:%s\n' "${fixture_user}" "${password}" | chpasswd
unset password

if [[ -L "${hostkey_file}" ]]; then
    fail 'refusing a symbolic-link host-key path'
fi

if [[ ! -s "${hostkey_file}" ]]; then
    stage_dir="$(mktemp --directory "${hostkey_dir}/.stage.XXXXXX")"
    ssh-keygen \
        -q \
        -t ed25519 \
        -N '' \
        -C 'hosthunter-disposable-fixture' \
        -f "${stage_dir}/ssh_host_ed25519_key"
    install --mode 0600 --owner root --group root \
        "${stage_dir}/ssh_host_ed25519_key" "${hostkey_file}"
    install --mode 0644 --owner root --group root \
        "${stage_dir}/ssh_host_ed25519_key.pub" "${hostkey_file}.pub"
    rm --recursive --force -- "${stage_dir}"
fi

chmod 0600 "${hostkey_file}"
chown root:root "${hostkey_file}"
ssh-keygen -y -f "${hostkey_file}" >/dev/null
ssh-keygen -y -f "${hostkey_file}" >"${hostkey_file}.pub"
chmod 0644 "${hostkey_file}.pub"
chown root:root "${hostkey_file}.pub"

install --directory --mode 0700 --owner "${fixture_user}" --group "${fixture_group}" \
    "/home/${fixture_user}/.ssh"
if [[ -L "/home/${fixture_user}/.ssh/authorized_keys" ]]; then
    fail 'refusing a symbolic-link authorized_keys path'
fi
if [[ ! -e "/home/${fixture_user}/.ssh/authorized_keys" ]]; then
    install --mode 0600 --owner "${fixture_user}" --group "${fixture_group}" \
        /dev/null "/home/${fixture_user}/.ssh/authorized_keys"
fi
chmod 0600 "/home/${fixture_user}/.ssh/authorized_keys"
chown "${fixture_user}:${fixture_group}" "/home/${fixture_user}/.ssh/authorized_keys"

rm --force -- /run/sshd.pid
/usr/sbin/sshd -t -f /etc/ssh/sshd_config

hostkey_fingerprint="$(ssh-keygen -l -E sha256 -f "${hostkey_file}.pub" | awk '{print $2}')"
write_atomic "${runtime_dir}/hostkey.sha256" 0644 root root "${hostkey_fingerprint}"
write_atomic "${runtime_dir}/username" 0644 root root "${fixture_user}"
write_atomic "${ready_file}" 0644 root root 'ready'

exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
