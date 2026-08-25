#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
  printf 'usage: %s SOURCE_ARTIFACT_ROOT DESTINATION\n' "$0" >&2
  exit 64
fi
source_root="$(cd -- "$1" && pwd -P)"
destination="$2"
mkdir -p -- "$destination"
destination="$(cd -- "$destination" && pwd -P)"
if find "$destination" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  printf 'Retained proof destination must be empty: %s\n' "$destination" >&2
  exit 2
fi

readonly budget_bytes=20971520
readonly -a allowlist=(
  'summary/verify-local.json'
  'build/module-package.json'
  'unit/coverage-summary.json'
  'unit/coverage-thresholds.xml'
  'unit/unit-tests.xml'
  'integration/integration-tests.xml'
  'integration/ssh-fixture-contract.json'
  'e2e/e2e-tests.xml'
  'static/psscriptanalyzer.json'
  'security/receipt.json'
  'security/gitleaks-receipt.json'
  'security/image-inventory.tsv'
  'security/release-package/receipt.json'
  'security/release-package/package-sha256.txt'
  'runtime/runtime-verification.json'
  'runtime/runtime-container.json'
  'runtime/parser-sidecar-receipts.json'
)

manifest_tmp="$(mktemp "${TMPDIR:-/tmp}/hh-proof-manifest.XXXXXX")"
cleanup() { rm -f -- "$manifest_tmp"; }
trap cleanup EXIT INT TERM HUP

copied=0
for relative_path in "${allowlist[@]}"; do
  source_path="$source_root/$relative_path"
  [[ -f "$source_path" ]] || continue
  [[ ! -L "$source_path" ]] || {
    printf 'Refusing symlinked proof receipt: %s\n' "$relative_path" >&2
    exit 2
  }
  mkdir -p -- "$destination/$(dirname -- "$relative_path")"
  cp -p -- "$source_path" "$destination/$relative_path"
  bytes="$(wc -c < "$destination/$relative_path" | tr -d ' ')"
  sha256="$(shasum -a 256 "$destination/$relative_path" | awk '{print $1}')"
  printf '%s\t%s\t%s\n' "$sha256" "$bytes" "$relative_path" >> "$manifest_tmp"
  copied=$((copied + 1))
done
(( copied > 0 )) || { printf 'No allowlisted proof receipts were found.\n' >&2; exit 2; }
LC_ALL=C sort -k3,3 "$manifest_tmp" > "$destination/receipt-sha256.tsv"

bundle_bytes="$(find "$destination" -type f -exec wc -c {} + | awk '{total += $1} END {print total + 0}')"
printf '{"schemaVersion":1,"cachePolicy":"external-not-retained","fileCount":%s,"retainedBytes":%s,"budgetBytes":%s}\n' \
  "$copied" "$bundle_bytes" "$budget_bytes" > "$destination/bundle-index.json"
bundle_bytes="$(find "$destination" -type f -exec wc -c {} + | awk '{total += $1} END {print total + 0}')"
if (( bundle_bytes > budget_bytes )); then
  printf 'ArtifactBudgetExceeded: retained proof bundle is %s bytes; limit is %s bytes.\n' \
    "$bundle_bytes" "$budget_bytes" >&2
  exit 2
fi
