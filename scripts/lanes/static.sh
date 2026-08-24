#!/usr/bin/env bash

set -euo pipefail

repo_root="${HH_REPO_ROOT:-/workspace}"
repo_root="$(cd -- "$repo_root" && pwd -P)"

if [[ "$repo_root" == "/" || ! -f "$repo_root/Dockerfile.test" ]]; then
  echo "Static lane refused an invalid repository root: $repo_root" >&2
  exit 2
fi

artifact_root="${HH_ARTIFACT_ROOT:-/artifacts}"
artifact_dir="$artifact_root/static"
mkdir -p -- "$artifact_dir"

(
echo "Running static validation for $repo_root"

# The embedded program is PowerShell and must not be expanded by Bash.
# shellcheck disable=SC2016
HH_PSSA_REPO_ROOT="$repo_root" \
HH_PSSA_REPORT_PATH="$artifact_dir/psscriptanalyzer.json" \
pwsh -NoLogo -NoProfile -NonInteractive -Command '
$ErrorActionPreference = "Stop"
$RepoRoot = $env:HH_PSSA_REPO_ROOT
$ReportPath = $env:HH_PSSA_REPORT_PATH
Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force

$scanPaths = @("src", "tests", "scripts", "build") |
    ForEach-Object { Join-Path -Path $RepoRoot -ChildPath $_ } |
    Where-Object { Test-Path -LiteralPath $_ }

$rootFiles = Get-ChildItem -LiteralPath $RepoRoot -File |
    Where-Object { $_.Extension -in ".ps1", ".psd1", ".psm1" } |
    Select-Object -ExpandProperty FullName

$findings = @(
    foreach ($path in @($scanPaths) + @($rootFiles)) {
        Invoke-ScriptAnalyzer -Path $path -Recurse -Settings (Join-Path $RepoRoot "PSScriptAnalyzerSettings.psd1")
    }
)

if ($findings.Count -eq 0) {
    "[]" | Set-Content -LiteralPath $ReportPath -Encoding utf8NoBOM
    exit 0
}

$findings |
    Select-Object RuleName, Severity, ScriptName, Line, Column, Message |
    ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath $ReportPath -Encoding utf8NoBOM
$findings | Format-Table -AutoSize | Out-Host
exit 1
'

file_paths=()
while IFS= read -r -d '' file_path; do
  file_paths+=("$file_path")
done < <(
  find "$repo_root" -type f \
    -not -path "$repo_root/.git/*" \
    -not -path "$repo_root/.artifacts/*" \
    -print0
)

if [[ ${#file_paths[@]} -gt 0 ]]; then
  (
    cd -- "$repo_root"
    editorconfig-checker "${file_paths[@]}"
  )
fi

markdown_paths=()
while IFS= read -r -d '' markdown_path; do
  markdown_paths+=("$markdown_path")
done < <(
  find "$repo_root" -type f -name '*.md' \
    -not -path "$repo_root/.git/*" \
    -not -path "$repo_root/.artifacts/*" \
    -print0
)

if [[ ${#markdown_paths[@]} -gt 0 ]]; then
  markdownlint-cli2 --config "$repo_root/.markdownlint-cli2.jsonc" "${markdown_paths[@]}"
fi

yamllint --config-file "$repo_root/.yamllint.yml" "$repo_root"

dockerfile_paths=()
while IFS= read -r -d '' dockerfile_path; do
  dockerfile_paths+=("$dockerfile_path")
done < <(
  find "$repo_root" -type f -name 'Dockerfile*' \
    -not -path "$repo_root/.artifacts/*" \
    -print0
)

if [[ ${#dockerfile_paths[@]} -gt 0 ]]; then
  hadolint --config "$repo_root/.hadolint.yaml" "${dockerfile_paths[@]}"
fi

shell_paths=()
while IFS= read -r -d '' shell_path; do
  shell_paths+=("$shell_path")
done < <(
  find "$repo_root" -type f -name '*.sh' \
    -not -path "$repo_root/.git/*" \
    -not -path "$repo_root/.artifacts/*" \
    -print0
)

if [[ ${#shell_paths[@]} -gt 0 ]]; then
  shellcheck --rcfile "$repo_root/.shellcheckrc" "${shell_paths[@]}"
fi

tests/security/prepare-artifacts-contract.sh
echo "Static validation passed"
) 2>&1 | tee "$artifact_dir/static.log"
