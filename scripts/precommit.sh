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

declare -a changed_files=()
declare -a focused_tests=()
while IFS= read -r changed; do
    [[ -z "$changed" ]] || changed_files+=("$changed")
done < <(git diff --cached --name-only --diff-filter=ACMR)

add_test() {
    local candidate="$1"
    [[ -f "$candidate" ]] || return 0
    local existing=''
    for existing in "${focused_tests[@]:-}"; do
        [[ "$existing" != "$candidate" ]] || return 0
    done
    focused_tests+=("$candidate")
}

for changed in "${changed_files[@]:-}"; do
    case "$changed" in
        tests/unit/*.Tests.ps1) add_test "$changed" ;;
        src/HostHunterNextGeneration/Private/*.ps1)
            base="$(basename -- "$changed" .ps1)"
            before_count="${#focused_tests[@]}"
            add_test "tests/unit/${base}.Tests.ps1"
            if [[ "${#focused_tests[@]}" -eq "$before_count" ]]; then
                add_test tests/unit/ModuleContract.Tests.ps1
            fi
            ;;
        src/HostHunterNextGeneration/Public/*.ps1)
            add_test tests/unit/PublicCmdlets.Tests.ps1
            case "$changed" in
                *WindowsProcessAuditPolicy*) add_test tests/unit/WindowsProcessAuditPublic.Tests.ps1 ;;
                *Audit*) add_test tests/unit/PublicAuditQuery.Tests.ps1 ;;
                *) ;;
            esac
            ;;
        src/HostHunterNextGeneration/HostHunterNextGeneration.ps[dm]1)
            add_test tests/unit/ModuleContract.Tests.ps1
            add_test tests/unit/PublicCmdlets.Tests.ps1
            ;;
        client/HostHunter.Client/*|scripts/client/*)
            add_test tests/unit/NativeClientContract.Tests.ps1
            add_test tests/unit/NativeClientProtocol.Tests.ps1
            ;;
        scripts/runtime/*)
            add_test tests/unit/RuntimeContainerContract.Tests.ps1
            add_test tests/unit/NativeClientProtocol.Tests.ps1
            ;;
        tests/e2e/*|compose.cmdlets.yml|Dockerfile.cmdlets|scripts/verify-cmdlets.sh)
            add_test tests/unit/FastHookContract.Tests.ps1
            add_test tests/unit/PublicCmdlets.Tests.ps1
            ;;
        Dockerfile*|compose*.yml|scripts/lanes/*|scripts/precommit.sh|scripts/prepush.sh|.githooks/*)
            add_test tests/unit/FastHookContract.Tests.ps1
            ;;
        eng/sqlite/*|scripts/dependencies/*)
            add_test tests/unit/ProviderPackaging.Tests.ps1
            ;;
        *) ;;
    esac
done

HH_GITLEAKS_HARD_TIMEOUT_SECONDS=20 \
HH_GITLEAKS_STALL_TIMEOUT_SECONDS=15 \
    "${repo_root}/scripts/security/scan-secrets.sh"
docker compose --file compose.test.yml run --rm test \
    bash scripts/lanes/static.sh

if [[ "${#focused_tests[@]}" -gt 0 ]]; then
    printf -v HH_FOCUSED_TESTS '%s\n' "${focused_tests[@]}"
    export HH_FOCUSED_TESTS
    printf 'Focused pre-commit tests (%s):\n%s' \
        "${#focused_tests[@]}" "$HH_FOCUSED_TESTS"
    "${repo_root}/scripts/lib/run-bounded.sh" focused-unit 30 20 \
        .artifacts/logs/focused-unit.log \
        docker compose --file compose.test.yml run --rm \
            --env HH_FOCUSED_TESTS test bash scripts/lanes/focused-unit.sh
else
    printf 'No staged runtime or test files require a focused unit test.\n'
fi
