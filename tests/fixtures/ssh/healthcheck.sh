#!/usr/bin/env bash

set -Eeuo pipefail

readonly fixture_user="hhfixture"
readonly fixture_group="hhfixture"
readonly secret_group="hhfixture-secret"
readonly runtime_dir="${HH_SSH_RUNTIME_DIR:-/run/hosthunter-ssh}"
readonly password_file="${runtime_dir}/password"
readonly hostkey_file="${runtime_dir}/hostkeys/ssh_host_ed25519_key"
readonly authorized_keys="/home/${fixture_user}/.ssh/authorized_keys"

actual_version="$(pwsh -NoLogo -NoProfile -Command "\$PSVersionTable.PSVersion.ToString()")"
[[ "${actual_version}" == '7.6.5' ]]
[[ -f "${runtime_dir}/ready" ]]
[[ ! -L "${password_file}" && -s "${password_file}" ]]
[[ "$(stat --format '%a:%U:%G' "${password_file}")" == "640:root:${secret_group}" ]]
[[ ! -L "${hostkey_file}" && -s "${hostkey_file}" ]]
[[ "$(stat --format '%a:%U:%G' "${hostkey_file}")" == '600:root:root' ]]
[[ "$(stat --format '%a:%U:%G' "/home/${fixture_user}/.ssh")" == \
    "700:${fixture_user}:${fixture_group}" ]]
[[ ! -L "${authorized_keys}" ]]
[[ "$(stat --format '%a:%U:%G' "${authorized_keys}")" == \
    "600:${fixture_user}:${fixture_group}" ]]

/usr/sbin/sshd -t -f /etc/ssh/sshd_config
[[ -s /run/sshd.pid ]]
kill -0 "$(</run/sshd.pid)"
timeout 2 bash -c '</dev/tcp/127.0.0.1/22'
