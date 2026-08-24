#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(git rev-parse --show-toplevel)"
readonly repo_root
cd -- "${repo_root}"
git config --local core.hooksPath .githooks
chmod 0755 .githooks/pre-commit .githooks/pre-push scripts/*.sh scripts/lib/*.sh scripts/lanes/*.sh
exec scripts/hooks-verify.sh
