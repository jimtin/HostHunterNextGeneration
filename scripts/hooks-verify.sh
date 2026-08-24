#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(git rev-parse --show-toplevel)"
configured_path="$(git config --local --get core.hooksPath || true)"
readonly repo_root configured_path

[[ "${configured_path}" == '.githooks' ]] || {
    printf 'core.hooksPath must be .githooks, found: %s\n' "${configured_path:-unset}" >&2
    exit 1
}

for hook in pre-commit pre-push; do
    hook_path="${repo_root}/.githooks/${hook}"
    [[ -f "${hook_path}" && -x "${hook_path}" ]] || {
        printf 'required hook is missing or not executable: %s\n' "${hook_path}" >&2
        exit 1
    }
done

printf 'Repository hooks are installed and active\n'
