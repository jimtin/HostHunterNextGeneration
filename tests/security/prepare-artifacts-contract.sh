#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
fixture_parent="${HH_ARTIFACT_ROOT:-${repo_root}/.artifacts}"
mkdir -p -- "${fixture_parent}"
fixture_root="$(mktemp -d "${fixture_parent}/prepare-artifacts.XXXXXX")"
fixture_repo="${fixture_root}/source"
fixture_worktree="${fixture_root}/linked"

cleanup() {
  git -C "${fixture_repo}" worktree remove --force "${fixture_worktree}" \
    >/dev/null 2>&1 || true
  rm -rf -- "${fixture_root}"
}
trap cleanup EXIT INT TERM HUP

git init --quiet "${fixture_repo}"
git -C "${fixture_repo}" config user.name 'HostHunter Test'
git -C "${fixture_repo}" config user.email 'hosthunter-test@example.invalid'
printf 'fixture\n' >"${fixture_repo}/README.md"
git -C "${fixture_repo}" add README.md
git -C "${fixture_repo}" commit --quiet -m fixture
git -C "${fixture_repo}" worktree add --quiet --detach "${fixture_worktree}" HEAD

"${repo_root}/scripts/lib/prepare-artifacts.sh" "${fixture_worktree}"
[[ -d "${fixture_worktree}/.artifacts" ]] || {
  printf 'linked-worktree artifact root was not created\n' >&2
  exit 1
}

if "${repo_root}/scripts/lib/prepare-artifacts.sh" "${fixture_root}" \
  >/dev/null 2>&1; then
  printf 'non-repository root was accepted\n' >&2
  exit 1
fi
if "${repo_root}/scripts/lib/prepare-artifacts.sh" / >/dev/null 2>&1; then
  printf 'filesystem root was accepted\n' >&2
  exit 1
fi

printf 'Artifact-root linked-worktree contract passed\n'
