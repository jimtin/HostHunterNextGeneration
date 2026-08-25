#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 3 || "$1" != '--plan' || "$3" != 'DELETE-CLASSIFIED-ARTIFACTS' ]]; then
  printf 'usage: %s --plan PLAN_PATH DELETE-CLASSIFIED-ARTIFACTS\n' "$0" >&2
  exit 64
fi
plan_path="$2"
[[ -f "$plan_path" && -f "$plan_path.sha256" && ! -L "$plan_path" ]] || exit 2
(cd -- "$(dirname -- "$plan_path")" && shasum -a 256 -c "$(basename -- "$plan_path.sha256")") >/dev/null
python3 -c '
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["schemaVersion"] == 1
assert isinstance(value["targets"], list)
assert isinstance(value["receipts"], list)
' "$plan_path"
repo_root="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["repositoryRoot"])' "$plan_path")"
artifact_root="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["artifactRoot"])' "$plan_path")"
[[ -d "$repo_root/.git" || -f "$repo_root/.git" ]]
if [[ "${HH_CLEANUP_TEST_MODE:-0}" != 1 ]]; then
  [[ "$artifact_root" == "$repo_root/.artifacts" ]] || { printf 'Artifact root mismatch.\n' >&2; exit 2; }
fi

verify_receipts() {
  while IFS=$'\t' read -r expected relative; do
    [[ -n "$relative" && "$relative" != /* && "$relative" != *'..'* ]]
    receipt="$artifact_root/$relative"
    [[ -f "$receipt" && ! -L "$receipt" ]] || { printf 'Indexed receipt missing: %s\n' "$relative" >&2; exit 2; }
    actual="$(shasum -a 256 "$receipt" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || { printf 'Indexed receipt changed: %s\n' "$relative" >&2; exit 2; }
  done < <(python3 -c 'import json,sys; [print(r["sha256"]+"\t"+r["retainedRelativePath"]) for r in json.load(open(sys.argv[1]))["receipts"]]' "$plan_path")
}
verify_receipts
while IFS= read -r relative; do
  [[ -n "$relative" && "$relative" != /* && "$relative" != *'..'* && "$relative" != '.' ]]
  target="$artifact_root/$relative"
  [[ "$target" == "$artifact_root/"* && "$target" != "$artifact_root" ]]
  [[ ! -L "$target" ]] || { printf 'Refusing symlink cleanup target: %s\n' "$relative" >&2; exit 2; }
  if [[ "${HH_CLEANUP_TEST_MODE:-0}" != 1 ]]; then
    git -C "$repo_root" check-ignore -q -- "$target" || { printf 'Cleanup target is not git-ignored: %s\n' "$relative" >&2; exit 2; }
  fi
done < <(python3 -c 'import json,sys; [print(r["relativePath"]) for r in json.load(open(sys.argv[1]))["targets"]]' "$plan_path")
while IFS= read -r relative; do
  target="$artifact_root/$relative"
  [[ -e "$target" ]] && rm -rf -- "$target"
done < <(python3 -c 'import json,sys; [print(r["relativePath"]) for r in json.load(open(sys.argv[1]))["targets"]]' "$plan_path")
verify_receipts
printf 'Removed only classified artifact targets from verified plan: %s\n' "$plan_path"
