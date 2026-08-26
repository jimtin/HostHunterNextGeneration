#!/usr/bin/env bash

set -Eeuo pipefail

: "${HH_CLIENT_BROKER_PORT:?HostHunter credential broker port is required}"
: "${HH_CLIENT_BROKER_TOKEN:?HostHunter credential broker token is required}"

prompt="${1:-Password required}"
prompt_base64="$(printf '%s' "$prompt" | base64 --wrap=0)"
exec 3<>"/dev/tcp/127.0.0.1/${HH_CLIENT_BROKER_PORT}"
printf '%s\n%s\n' "$HH_CLIENT_BROKER_TOKEN" "$prompt_base64" >&3
IFS= read -r response_base64 <&3
[[ -n "$response_base64" ]] || exit 1
printf '%s' "$response_base64" | base64 --decode
