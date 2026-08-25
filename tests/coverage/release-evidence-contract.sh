#!/usr/bin/env bash
set -Eeuo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/hh-release-evidence.XXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT INT TERM HUP

HH_SECURITY_CACHE_ROOT="$fixture/external-security-cache"
export HH_SECURITY_CACHE_ROOT
# shellcheck source=scripts/security/common.sh
source "$repo_root/scripts/security/common.sh"
hh_security_init
[[ "$HH_SECURITY_CACHE_DIR" == "$fixture/external-security-cache" ]]
case "$HH_SECURITY_CACHE_DIR/" in
  "$repo_root"/*)
    printf 'security cache unexpectedly resolved inside the repository\n' >&2
    exit 1
    ;;
  *) ;;
esac

mkdir -p "$fixture/source/summary" "$fixture/source/security/cache" \
  "$fixture/source/security/release-package" "$fixture/source/unit" \
  "$fixture/source/runtime"
printf '{"status":"passed"}\n' > "$fixture/source/summary/verify-local.json"
printf '{"status":"passed"}\n' > "$fixture/source/security/release-package/receipt.json"
printf 'must-not-copy\n' > "$fixture/source/security/cache/database.bin"
printf 'raw\n' > "$fixture/source/unit/branch-events.jsonl"
printf '{"status":"passed"}\n' > "$fixture/source/runtime/runtime-verification.json"
printf 'must-not-copy\n' > "$fixture/source/runtime/runtime-verification.log"
"$repo_root/scripts/release/copy-proof-receipts.sh" "$fixture/source" "$fixture/destination"
[[ -f "$fixture/destination/summary/verify-local.json" ]]
[[ -f "$fixture/destination/security/release-package/receipt.json" ]]
[[ ! -e "$fixture/destination/security/cache/database.bin" ]]
[[ ! -e "$fixture/destination/unit/branch-events.jsonl" ]]
[[ -f "$fixture/destination/runtime/runtime-verification.json" ]]
[[ ! -e "$fixture/destination/runtime/runtime-verification.log" ]]
python3 - "$fixture/destination/bundle-index.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["cachePolicy"] == "external-not-retained"
assert value["retainedBytes"] <= value["budgetBytes"]
PY
dd if=/dev/zero of="$fixture/source/summary/verify-local.json" bs=1048576 count=21 status=none
if "$repo_root/scripts/release/copy-proof-receipts.sh" "$fixture/source" "$fixture/overflow" \
  >"$fixture/overflow.stdout" 2>"$fixture/overflow.stderr"; then
  printf 'oversized retained proof bundle unexpectedly passed\n' >&2
  exit 1
fi
grep -F 'ArtifactBudgetExceeded:' "$fixture/overflow.stderr" >/dev/null
mkdir -p "$fixture/stale"
printf 'stale-cache\n' > "$fixture/stale/cache.bin"
if "$repo_root/scripts/release/copy-proof-receipts.sh" "$fixture/source" "$fixture/stale" \
  >"$fixture/stale.stdout" 2>"$fixture/stale.stderr"; then
  printf 'non-empty retained proof destination unexpectedly passed\n' >&2
  exit 1
fi
grep -F 'Retained proof destination must be empty:' "$fixture/stale.stderr" >/dev/null
