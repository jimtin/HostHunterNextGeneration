#!/usr/bin/env bash

set -Eeuo pipefail

if [[ "$#" -lt 5 ]]; then
    printf 'usage: %s NAME TIMEOUT_SECONDS STALL_SECONDS LOG_PATH COMMAND...\n' "$0" >&2
    exit 64
fi

readonly lane_name="$1"
readonly timeout_seconds="$2"
readonly stall_seconds="$3"
readonly log_path="$4"
shift 4

[[ "${timeout_seconds}" =~ ^[1-9][0-9]*$ ]] || {
    printf 'timeout must be a positive integer\n' >&2
    exit 64
}
[[ "${stall_seconds}" =~ ^[1-9][0-9]*$ ]] || {
    printf 'stall threshold must be a positive integer\n' >&2
    exit 64
}

mkdir -p -- "$(dirname -- "${log_path}")"
: >"${log_path}"

started_at="$(date +%s)"
last_output_at="${started_at}"
last_size=0
next_heartbeat_at=$((started_at + 30))
timed_out=false
stalled=false

( "$@" >"${log_path}" 2>&1 ) &
command_pid=$!

terminate_command() {
    kill -TERM "${command_pid}" 2>/dev/null || true
    sleep 1
    kill -KILL "${command_pid}" 2>/dev/null || true
}

trap 'terminate_command' INT TERM HUP

while kill -0 "${command_pid}" 2>/dev/null; do
    sleep 1
    now="$(date +%s)"
    current_size="$(wc -c <"${log_path}" | tr -d '[:space:]')"
    if [[ "${current_size}" != "${last_size}" ]]; then
        last_size="${current_size}"
        last_output_at="${now}"
    fi

    if (( now >= next_heartbeat_at )); then
        printf '[heartbeat] lane=%s elapsed=%ss output_bytes=%s\n' \
            "${lane_name}" "$((now - started_at))" "${current_size}"
        next_heartbeat_at=$((now + 30))
    fi

    if (( now - last_output_at >= stall_seconds )); then
        stalled=true
        terminate_command
        break
    fi
    if (( now - started_at >= timeout_seconds )); then
        timed_out=true
        terminate_command
        break
    fi
done

set +e
wait "${command_pid}"
command_status=$?
set -e
trap - INT TERM HUP

cat -- "${log_path}"

if [[ "${timed_out}" == true ]]; then
    printf 'lane %s exceeded hard timeout of %ss; log: %s\n' \
        "${lane_name}" "${timeout_seconds}" "${log_path}" >&2
    exit 124
fi
if [[ "${stalled}" == true ]]; then
    printf 'lane %s produced no output for %ss; log: %s\n' \
        "${lane_name}" "${stall_seconds}" "${log_path}" >&2
    exit 125
fi
exit "${command_status}"
