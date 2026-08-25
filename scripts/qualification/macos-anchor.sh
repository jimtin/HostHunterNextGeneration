#!/usr/bin/env bash

set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
  printf 'usage: %s CANDIDATE_SHA PACKAGE_ARCHIVE\n' "$0" >&2
  exit 64
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(git -C "$script_dir/../.." rev-parse --show-toplevel)"
candidate_sha="$(git -C "$repo_root" rev-parse --verify "$1^{commit}" 2>/dev/null)" || {
  printf 'Unknown candidate commit: %s\n' "$1" >&2
  exit 2
}
package_archive="$(cd -- "$(dirname -- "$2")" && pwd -P)/$(basename -- "$2")"
candidate_receipt="$repo_root/.artifacts/release/$candidate_sha/receipt.json"
qualification_root="$repo_root/.artifacts/qualification/macos/$candidate_sha"

[[ "$(uname -s)" == Darwin ]] || {
  printf 'macOS native qualification requires a macOS controller.\n' >&2
  exit 2
}
[[ -f "$package_archive" && -f "$candidate_receipt" ]] || {
  printf 'The exact candidate archive or receipt is missing.\n' >&2
  exit 2
}
[[ -z "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)" ]] || {
  printf 'Native qualification requires a clean candidate repository.\n' >&2
  exit 2
}
[[ "$(git -C "$repo_root" rev-parse HEAD)" == "$candidate_sha" ]] || {
  printf 'Repository HEAD is not the requested candidate.\n' >&2
  exit 2
}

package_sha256="$(shasum -a 256 "$package_archive" | awk '{print $1}')"
jq -e --arg sha "$candidate_sha" --arg packageSha "$package_sha256" '
  .status == "passed" and .candidateSha == $sha and
  .packageArchiveSha256 == $packageSha
' "$candidate_receipt" >/dev/null || {
  printf 'Package archive is not the exact verified candidate package.\n' >&2
  exit 2
}

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/hosthunter-macos-qualification.XXXXXX")"
cleanup() { rm -rf -- "$temporary_root"; }
trap cleanup EXIT INT TERM HUP
tar -xzf "$package_archive" -C "$temporary_root"
manifest_path="$(find "$temporary_root" -type f -name HostHunterNextGeneration.psd1 -print -quit)"
[[ -n "$manifest_path" ]] || {
  printf 'Candidate archive does not contain the module manifest.\n' >&2
  exit 2
}

mkdir -p -- "$qualification_root"
"$repo_root/scripts/lib/run-bounded.sh" \
  macos-anchor-qualification 1200 180 \
  "$qualification_root/qualification.log" \
  pwsh -NoLogo -NoProfile -NonInteractive \
  -File "$repo_root/scripts/qualification/Test-HHMacOSAnchor.ps1" \
  -CandidateSha "$candidate_sha" \
  -ModuleManifestPath "$manifest_path" \
  -PackageArchiveSha256 "$package_sha256" \
  -ReceiptPath "$qualification_root/receipt.json"

jq -e --arg sha "$candidate_sha" --arg packageSha "$package_sha256" '
  .status == "passed" and .candidateSha == $sha and
  .packageArchiveSha256 == $packageSha and .cleanupComplete == true and
  .spaceContainingDataRootVerified == true and .redacted == true
' "$qualification_root/receipt.json" >/dev/null

printf 'Native macOS qualification passed: %s\n' "$qualification_root/receipt.json"
