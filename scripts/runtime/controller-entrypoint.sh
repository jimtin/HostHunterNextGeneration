#!/usr/bin/env bash
# shellcheck disable=SC2016

set -Eeuo pipefail

readonly expected_provider='DockerVolume'
readonly expected_exports=11

: "${HH_DATA_ROOT:?HH_DATA_ROOT is required}"
: "${HH_SECRET_ROOT:?HH_SECRET_ROOT is required}"
: "${HH_ANCHOR_ROOT:?HH_ANCHOR_ROOT is required}"
: "${HH_SSH_ROOT:?HH_SSH_ROOT is required}"
: "${HH_EVIDENCE_ROOT:?HH_EVIDENCE_ROOT is required}"

fail() {
  printf 'HostHunter controller startup refused: %s\n' "$1" >&2
  exit 70
}

require_absolute_directory() {
  local variable_name="$1"
  local path_value="${!variable_name:-}"

  [[ "$path_value" == /* ]] || fail "$variable_name must be an absolute path."
  [[ -d "$path_value" ]] || fail "$variable_name does not resolve to a mounted directory."
  [[ ! -L "$path_value" ]] || fail "$variable_name cannot be a symbolic link."
}

[[ "${HH_SECRET_PROVIDER:-}" == "$expected_provider" ]] ||
  fail 'HH_SECRET_PROVIDER must be exactly DockerVolume.'

for root_variable in \
  HH_DATA_ROOT \
  HH_SECRET_ROOT \
  HH_ANCHOR_ROOT \
  HH_SSH_ROOT \
  HH_EVIDENCE_ROOT; do
  require_absolute_directory "$root_variable"
done

roots=(
  "$HH_DATA_ROOT"
  "$HH_SECRET_ROOT"
  "$HH_ANCHOR_ROOT"
  "$HH_SSH_ROOT"
  "$HH_EVIDENCE_ROOT"
)
for ((left = 0; left < ${#roots[@]}; left++)); do
  for ((right = left + 1; right < ${#roots[@]}; right++)); do
    [[ "${roots[$left]}" != "${roots[$right]}" ]] ||
      fail 'Runtime data, secret, anchor, SSH, and evidence roots must be distinct.'
  done
done

[[ "${HH_PARSER_SOCKET:-}" == /* ]] || fail 'HH_PARSER_SOCKET must be absolute.'
[[ -d "$(dirname -- "$HH_PARSER_SOCKET")" ]] ||
  fail 'The parser socket directory is not mounted.'
[[ -f "${HH_RUNTIME_MODULE_PATH:-}" ]] || fail 'The built module manifest is missing.'

for writable_root in \
  "$HH_DATA_ROOT" \
  "$HH_SECRET_ROOT" \
  "$HH_ANCHOR_ROOT" \
  "$HH_SSH_ROOT" \
  "$HH_EVIDENCE_ROOT" \
  "$(dirname -- "$HH_PARSER_SOCKET")"; do
  [[ -w "$writable_root" ]] || fail "The runtime identity cannot write $writable_root."
done

module_contract="$({
  pwsh -NoLogo -NoProfile -NonInteractive -Command '
    $ErrorActionPreference = "Stop"
    Import-Module $env:HH_RUNTIME_MODULE_PATH -Force
    $commands = @(Get-Command -Module HostHunterNextGeneration -CommandType Function)
    [pscustomobject]@{
      Count = $commands.Count
      Names = @($commands.Name | Sort-Object)
    } | ConvertTo-Json -Compress
  '
} 2>&1)" || fail "The built module could not be imported: $module_contract"

module_count="$(
  MODULE_CONTRACT="$module_contract" pwsh -NoLogo -NoProfile -NonInteractive -Command '
    [int](ConvertFrom-Json $env:MODULE_CONTRACT).Count
  '
)"
[[ "$module_count" == "$expected_exports" ]] ||
  fail "The built module exported $module_count commands; expected $expected_exports."

case "${1:-serve}" in
  serve)
    shift || true
    [[ "$#" -eq 0 ]] || fail 'The serve action does not accept arguments.'
    exec pwsh -NoLogo -NoProfile -NonInteractive -Command '
      $ErrorActionPreference = "Stop"
      Import-Module $env:HH_RUNTIME_MODULE_PATH -Force
      while ($true) { Start-Sleep -Seconds 3600 }
    '
    ;;
  doctor)
    shift
    [[ "$#" -eq 0 ]] || fail 'The doctor action does not accept arguments.'
    printf '{"status":"ready","uid":%s,"provider":"%s","exportCount":%s}\n' \
      "$(id -u)" "$HH_SECRET_PROVIDER" "$module_count"
    ;;
  *)
    exec "$@"
    ;;
esac
