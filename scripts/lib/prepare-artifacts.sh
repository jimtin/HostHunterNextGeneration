#!/usr/bin/env bash

set -Eeuo pipefail

if [[ "$#" -ne 1 ]]; then
    printf 'usage: %s REPOSITORY_ROOT\n' "$0" >&2
    exit 64
fi

readonly repo_root="$1"
readonly artifact_root="${repo_root}/.artifacts"

[[ -d "${repo_root}/.git" && "${repo_root}" != '/' ]] || {
    printf 'refusing invalid repository root: %s\n' "${repo_root}" >&2
    exit 2
}

mkdir -p -- "${artifact_root}"
chmod -R g+rwX "${artifact_root}"
find "${artifact_root}" -type d -exec chmod g+s {} +
chmod 2770 "${artifact_root}"
