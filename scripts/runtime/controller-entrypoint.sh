#!/usr/bin/env bash
# shellcheck disable=SC2016

set -Eeuo pipefail

readonly expected_provider='DockerVolume'
readonly expected_exports=11
readonly dispatcher='/opt/hosthunter/runtime/Invoke-HHCmdlet.ps1'

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
  [[ "$path_value" == /* ]] || fail "$variable_name must be absolute."
  [[ -d "$path_value" && ! -L "$path_value" ]] ||
    fail "$variable_name must be a mounted non-symlink directory."
}

[[ "${HH_SECRET_PROVIDER:-}" == "$expected_provider" ]] ||
  fail 'HH_SECRET_PROVIDER must be DockerVolume.'
for root_variable in HH_DATA_ROOT HH_SECRET_ROOT HH_ANCHOR_ROOT HH_SSH_ROOT HH_EVIDENCE_ROOT; do
  require_absolute_directory "$root_variable"
done
roots=("$HH_DATA_ROOT" "$HH_SECRET_ROOT" "$HH_ANCHOR_ROOT" "$HH_SSH_ROOT" "$HH_EVIDENCE_ROOT")
for ((left = 0; left < ${#roots[@]}; left++)); do
  for ((right = left + 1; right < ${#roots[@]}; right++)); do
    [[ "${roots[$left]}" != "${roots[$right]}" ]] ||
      fail 'Data, secret, anchor, SSH, and evidence roots must be distinct.'
  done
done
for writable_root in "${roots[@]}"; do
  [[ -w "$writable_root" ]] || fail "The runtime identity cannot write $writable_root."
done
[[ -f "${HH_RUNTIME_MODULE_PATH:-}" && -f "$dispatcher" ]] ||
  fail 'The packaged module or constrained dispatcher is missing.'

module_count="$(pwsh -NoLogo -NoProfile -NonInteractive -Command '
  $ErrorActionPreference = "Stop"
  Import-Module $env:HH_RUNTIME_MODULE_PATH -Force
  @(Get-Command -Module HostHunterNextGeneration -CommandType Function).Count
')" || fail 'The packaged module could not be imported.'
[[ "$module_count" == "$expected_exports" ]] ||
  fail "The module exported $module_count commands; expected $expected_exports."

case "${1:-serve}" in
  serve)
    shift || true
    [[ "$#" -eq 0 ]] || fail 'serve accepts no arguments.'
    exec pwsh -NoLogo -NoProfile -NonInteractive -Command '
      Import-Module $env:HH_RUNTIME_MODULE_PATH -Force
      while ($true) { Start-Sleep -Seconds 3600 }
    '
    ;;
  doctor)
    shift
    [[ "$#" -eq 0 ]] || fail 'doctor accepts no arguments.'
    printf '{"status":"ready","uid":%s,"provider":"%s","exportCount":%s}\n' \
      "$(id -u)" "$HH_SECRET_PROVIDER" "$module_count"
    ;;
  invoke)
    shift
    [[ "$#" -ge 1 && "$#" -le 2 ]] ||
      fail 'invoke requires CMDLET and optional PARAMETERS_JSON.'
    exec pwsh -NoLogo -NoProfile -NonInteractive -File "$dispatcher" \
      -CommandName "$1" -ParametersJson "${2:-{}}"
    ;;
  *)
    fail 'Only serve, doctor, and invoke are permitted.'
    ;;
esac
