#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly repo_root
cd -- "${repo_root}"
scripts/lib/prepare-artifacts.sh "${repo_root}"
mkdir -p .artifacts/logs
HH_HOST_GID="$(id -g)"
export HH_HOST_GID
test_image="${HH_TEST_IMAGE:-hosthunter-next-generation-test:local}"
docker image inspect "$test_image" >/dev/null 2>&1 || {
    printf 'Cached test image is missing; run: docker compose -f compose.test.yml build test\n' >&2
    exit 2
}

cleanup() {
    docker compose --file compose.test.yml down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM HUP

declare -a changed_files=()
declare -a hook_lines=()
while IFS= read -r hook_line; do
    [[ -z "$hook_line" ]] || hook_lines+=("$hook_line")
done
if [[ -n "${HH_HOOK_CHANGED_FILES:-}" ]]; then
    while IFS= read -r changed; do
        [[ -z "$changed" ]] || changed_files+=("$changed")
    done <<<"$HH_HOOK_CHANGED_FILES"
elif [[ "${#hook_lines[@]}" -gt 0 ]]; then
    for hook_line in "${hook_lines[@]}"; do
        read -r _local_ref local_sha _remote_ref remote_sha <<<"$hook_line"
        [[ "$local_sha" =~ ^[a-f0-9]{40}$ ]] || continue
        if [[ "$remote_sha" =~ ^0{40}$ ]]; then
            range_command=(git diff-tree --no-commit-id --name-only -r "$local_sha")
        else
            range_command=(git diff --name-only "$remote_sha..$local_sha")
        fi
        while IFS= read -r changed; do
            [[ -z "$changed" ]] || changed_files+=("$changed")
        done < <("${range_command[@]}")
    done
else
    while IFS= read -r changed; do
        [[ -z "$changed" ]] || changed_files+=("$changed")
    done < <(git diff-tree --no-commit-id --name-only -r HEAD)
fi

native_client_changed=false
for changed in "${changed_files[@]:-}"; do
    case "$changed" in
        client/HostHunter.Client/*|scripts/client/*|scripts/runtime/*)
            native_client_changed=true
            break
            ;;
        *) ;;
    esac
done

HH_GITLEAKS_HARD_TIMEOUT_SECONDS=30 \
HH_GITLEAKS_STALL_TIMEOUT_SECONDS=20 \
    "${repo_root}/scripts/security/scan-secrets.sh"
"${repo_root}/scripts/security/scan-dependencies.sh"
docker compose --file compose.test.yml run --rm test \
    bash scripts/lanes/static.sh
"${repo_root}/scripts/lib/run-bounded.sh" unit-smoke 45 30 \
    .artifacts/logs/prepush-unit-smoke.log \
    docker compose --file compose.test.yml run --rm test \
        bash scripts/lanes/unit-smoke.sh
"${repo_root}/scripts/verify-cmdlets.sh"

if [[ "$native_client_changed" == true ]]; then
    pwsh -NoLogo -NoProfile -NonInteractive \
        -File scripts/client/Test-HHInstalledNativeClientSsh.ps1 \
        -RepoRoot "$repo_root" -TimeoutSeconds 90
else
    printf 'Native macOS journey skipped: no owned client/runtime files changed.\n'
fi
