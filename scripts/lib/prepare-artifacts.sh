#!/usr/bin/env bash

set -Eeuo pipefail

if [[ "$#" -ne 1 ]]; then
    printf 'usage: %s REPOSITORY_ROOT\n' "$0" >&2
    exit 64
fi

repo_root="$(cd -- "$1" 2>/dev/null && pwd -P)" || {
    printf 'refusing invalid repository root: %s\n' "$1" >&2
    exit 2
}
readonly repo_root
readonly artifact_root="${repo_root}/.artifacts"

resolved_root="$(git -C "${repo_root}" rev-parse --show-toplevel 2>/dev/null)" || {
    printf 'refusing invalid repository root: %s\n' "${repo_root}" >&2
    exit 2
}
resolved_root="$(cd -- "${resolved_root}" && pwd -P)"
[[ "${repo_root}" != '/' && "${resolved_root}" == "${repo_root}" ]] || {
    printf 'refusing invalid repository root: %s\n' "${repo_root}" >&2
    exit 2
}

mkdir -p -- "${artifact_root}"
chmod -R g+rwX "${artifact_root}"
find "${artifact_root}" -type d -exec chmod g+s {} +
chmod 2770 "${artifact_root}"
