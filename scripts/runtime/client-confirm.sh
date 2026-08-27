#!/usr/bin/env bash

set -Eeuo pipefail

: "${HH_CLIENT_BROKER_PORT:?HostHunter interaction broker port is required}"
: "${HH_CLIENT_BROKER_TOKEN:?HostHunter interaction broker token is required}"

prompt_base64="${1:?A base64-encoded confirmation prompt is required}"
exec 3<>"/dev/tcp/127.0.0.1/${HH_CLIENT_BROKER_PORT}"
printf '%s\n%s\n%s\n' "$HH_CLIENT_BROKER_TOKEN" confirmation "$prompt_base64" >&3
IFS= read -r response <&3
case "$response" in
  yes|no) printf '%s' "$response" ;;
  *) exit 1 ;;
esac
