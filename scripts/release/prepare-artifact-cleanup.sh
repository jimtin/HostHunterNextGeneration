#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(git -C "$script_dir/../.." rev-parse --show-toplevel)"
artifact_input="${1:-$repo_root/.artifacts}"
mkdir -p -- "$artifact_input/retention"
artifact_root="$(cd -- "$artifact_input" && pwd -P)"
plan_path="${2:-$artifact_root/retention/cleanup-plan.json}"
mkdir -p -- "$(dirname -- "$plan_path")"
plan_path="$(cd -- "$(dirname -- "$plan_path")" && pwd -P)/$(basename -- "$plan_path")"
receipt_tsv="$(mktemp "${TMPDIR:-/tmp}/hh-receipts.XXXXXX")"
target_tsv="$(mktemp "${TMPDIR:-/tmp}/hh-cleanup-targets.XXXXXX")"
history_root="$artifact_root/retention/receipt-history"
history_stage="$(mktemp -d "$artifact_root/retention/receipt-history.XXXXXX")"
cleanup() { rm -f -- "$receipt_tsv" "$target_tsv"; rm -rf -- "$history_stage"; }
trap cleanup EXIT INT TERM HUP

while IFS= read -r -d '' receipt; do
  relative="${receipt#"$artifact_root/"}"
  [[ "$relative" != *$'\n'* && "$relative" != *$'\t'* ]] || exit 2
  bytes="$(wc -c < "$receipt" | tr -d ' ')"
  sha256="$(shasum -a 256 "$receipt" | awk '{print $1}')"
  retained_relative="retention/receipt-history/$relative"
  mkdir -p -- "$history_stage/$(dirname -- "$relative")"
  cp -p -- "$receipt" "$history_stage/$relative"
  printf '%s\t%s\t%s\t%s\n' "$sha256" "$bytes" "$relative" "$retained_relative" >> "$receipt_tsv"
done < <(find "$artifact_root" -type f \( -name receipt.json -o \
  -name verify-local.json -o -name build.json -o -name coverage-summary.json -o \
  -name bundle-index.json \) -not -path '*/cache/*' -not -path '*/retention/*' -print0)
history_bytes="$(find "$history_stage" -type f -exec wc -c {} + | awk '{n += $1} END {print n + 0}')"
if (( history_bytes > 20971520 )); then
  printf 'ArtifactBudgetExceeded: retained receipt history is %s bytes; limit is 20971520 bytes.\n' "$history_bytes" >&2
  exit 2
fi
history_previous="$artifact_root/retention/receipt-history.previous"
rm -rf -- "$history_previous"
if [[ -d "$history_root" ]]; then mv -- "$history_root" "$history_previous"; fi
mv -- "$history_stage" "$history_root"
mkdir -p -- "$history_stage"
rm -rf -- "$history_previous"

add_target() {
  local target="$1" classification="$2" reason="$3" relative bytes files
  [[ -e "$target" || -L "$target" ]] || return 0
  relative="${target#"$artifact_root/"}"
  [[ "$relative" != "$target" && "$relative" != *'..'* && \
    "$relative" != *$'\n'* && "$relative" != *$'\t'* ]] || {
    printf 'Unsafe cleanup target: %s\n' "$target" >&2; exit 2;
  }
  if [[ -d "$target" && ! -L "$target" ]]; then
    bytes="$(find "$target" -type f -exec wc -c {} + | awk '{n += $1} END {print n + 0}')"
    files="$(find "$target" -type f | wc -l | tr -d ' ')"
  else
    bytes="$(wc -c < "$target" | tr -d ' ')"; files=1
  fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$classification" "$bytes" "$files" "$relative" "$reason" >> "$target_tsv"
}

while IFS= read -r -d '' child; do
  name="$(basename -- "$child")"
  case "$name" in
    release|qualification|publication|retention|summary|security) ;;
    *) add_target "$child" reproducible 'repo-ignored test or build working data' ;;
  esac
done < <(find "$artifact_root" -mindepth 1 -maxdepth 1 -print0)
add_target "$artifact_root/security/cache" cache 'external scanner cache is never retained as proof'
head_sha="$(git -C "$repo_root" rev-parse HEAD)"
active_candidate_sha="${HH_ACTIVE_CANDIDATE_SHA:-$head_sha}"
[[ "$active_candidate_sha" =~ ^[a-f0-9]{40}$ ]] || { printf 'Active candidate SHA must be 40 lowercase hex characters.\n' >&2; exit 2; }
if [[ -d "$artifact_root/release" ]]; then
  while IFS= read -r -d '' candidate; do
    candidate_sha="$(basename -- "$candidate")"
    if [[ "$candidate_sha" != "$active_candidate_sha" ]]; then
      # The candidate directory and its claim/receipts are permanent tombstones:
      # deleting them would make an already-consumed exact SHA runnable again.
      while IFS= read -r -d '' payload; do
        case "$(basename -- "$payload")" in
          claim.json|receipt.json|build-receipt.json|cmdlet-receipt.json|\
          windows-receipt.json|coverage-receipt.json|persistence-receipt.json|\
          security-receipt.json|orchestration-receipt.json) ;;
          *) add_target "$payload" superseded \
            'non-receipt payload belongs to a terminal non-active release candidate' ;;
        esac
      done < <(find "$candidate" -mindepth 1 -maxdepth 1 -print0)
      continue
    fi
    evidence="$candidate/evidence"
    if [[ -d "$evidence" ]] && { [[ ! -f "$evidence/bundle-index.json" ]] ||
      ! python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["retainedBytes"] <= 20971520 and v["cachePolicy"] == "external-not-retained"' \
        "$evidence/bundle-index.json" >/dev/null 2>&1; }; then
      add_target "$evidence" superseded 'legacy candidate evidence tree lacks a valid compact bundle index'
    fi
  done < <(find "$artifact_root/release" -mindepth 1 -maxdepth 1 -type d -name '[a-f0-9]*' -print0)
fi

LC_ALL=C sort -k3,3 "$receipt_tsv" -o "$receipt_tsv"
LC_ALL=C sort -k4,4 "$target_tsv" -o "$target_tsv"
created="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
plan_tmp="$plan_path.tmp"
python3 - "$receipt_tsv" "$target_tsv" "$repo_root" "$artifact_root" "$head_sha" "$active_candidate_sha" "$created" "$plan_tmp" <<'PY'
import csv, json, sys
receipts_path, targets_path, repo, artifacts, head, active, created, output = sys.argv[1:]
with open(receipts_path, newline="", encoding="utf-8") as stream:
    receipts = [
        {
            "sha256": row[0],
            "bytes": int(row[1]),
            "sourceRelativePath": row[2],
            "retainedRelativePath": row[3],
        }
        for row in csv.reader(stream, delimiter="\t")
    ]
with open(targets_path, newline="", encoding="utf-8") as stream:
    targets = [
        {
            "classification": row[0],
            "bytes": int(row[1]),
            "fileCount": int(row[2]),
            "relativePath": row[3],
            "reason": row[4],
        }
        for row in csv.reader(stream, delimiter="\t")
    ]
value = {
    "schemaVersion": 1,
    "repositoryRoot": repo,
    "artifactRoot": artifacts,
    "headSha": head,
    "activeCandidateSha": active,
    "createdAtUtc": created,
    "retainedReceiptBytes": sum(row["bytes"] for row in receipts),
    "budgetBytes": 20971520,
    "receipts": receipts,
    "targets": targets,
}
with open(output, "w", encoding="utf-8") as stream:
    json.dump(value, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
mv -f -- "$plan_tmp" "$plan_path"
shasum -a 256 "$plan_path" > "$plan_path.sha256"
printf 'Cleanup plan created (no files deleted): %s\n' "$plan_path"
