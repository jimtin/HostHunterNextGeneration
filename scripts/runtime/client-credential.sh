#!/usr/bin/env bash

set -Eeuo pipefail

: "${HH_CLIENT_BROKER_PORT:?HostHunter credential broker port is required}"
: "${HH_CLIENT_BROKER_TOKEN:?HostHunter credential broker token is required}"

mode="${1:?credential helper mode is required}"
prompt_base64="${2:-}"
exec 3<>"/dev/tcp/127.0.0.1/${HH_CLIENT_BROKER_PORT}"

case "$mode" in
    acquire)
        [[ -n "$prompt_base64" ]] || exit 2
        printf '%s\n%s\n%s\n' "$HH_CLIENT_BROKER_TOKEN" credential_acquire "$prompt_base64" >&3
        IFS= read -r response_base64 <&3
        [[ -n "$response_base64" ]] || exit 1
        printf '%s' "$response_base64"
        ;;
    seed)
        IFS= read -r password_base64
        [[ -n "$password_base64" ]] || exit 2
        printf '%s\n%s\n%s\n' "$HH_CLIENT_BROKER_TOKEN" credential_seed "$password_base64" >&3
        IFS= read -r response <&3
        [[ "$response" == ok ]] || exit 1
        printf '%s' "$response"
        ;;
    *) exit 2 ;;
esac
