#!/usr/bin/env bash

set -Eeuo pipefail

pwsh -NoLogo -NoProfile -NonInteractive -File scripts/toolchain/Test-Toolchain.ps1
test "$(editorconfig-checker -version)" = 'v3.11.1'
shellcheck --version | grep --fixed-strings 'version: 0.11.0'
hadolint --version
markdownlint-cli2 --version
test "$(yamllint --version)" = 'yamllint 1.38.0'
printf 'Container toolchain pins verified\n'
