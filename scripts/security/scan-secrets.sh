#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/security/common.sh
source "$script_dir/common.sh"

hh_security_init
hh_require_docker

gitleaks_image='ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f'
host_uid="$(id -u)"
host_gid="$(id -g)"
bounded="$HH_SECURITY_REPO_ROOT/scripts/lib/run-bounded.sh"
hard_timeout_seconds="${HH_GITLEAKS_HARD_TIMEOUT_SECONDS:-660}"
stall_timeout_seconds="${HH_GITLEAKS_STALL_TIMEOUT_SECONDS:-180}"
[[ "$hard_timeout_seconds" =~ ^[1-9][0-9]*$ ]] || {
  printf 'HH_GITLEAKS_HARD_TIMEOUT_SECONDS must be a positive integer.\n' >&2
  exit 64
}
[[ "$stall_timeout_seconds" =~ ^[1-9][0-9]*$ ]] || {
  printf 'HH_GITLEAKS_STALL_TIMEOUT_SECONDS must be a positive integer.\n' >&2
  exit 64
}
snapshot_root="$(mktemp -d "${TMPDIR:-/tmp}/hosthunter-gitleaks.XXXXXX")"
snapshot_tree="$snapshot_root/tree"
file_list="$snapshot_root/source-files.zlist"
manifest_before="$snapshot_root/manifest-before.bin"
manifest_after="$snapshot_root/manifest-after.bin"
history_repo="$snapshot_root/history.git"

cleanup() {
  rm -rf -- "$snapshot_root"
}
trap cleanup EXIT INT TERM HUP

mkdir -p -- "$snapshot_tree"

write_source_manifest() {
  local destination="$1"
  local path=''
  local digest=''
  local link_target=''

  : > "$destination"
  git -C "$HH_SECURITY_REPO_ROOT" \
    ls-files --cached --others --exclude-standard -z > "$file_list"

  while IFS= read -r -d '' path; do
    [[ "$path" != /* && "$path" != ../* && "$path" != */../* ]] || {
      printf 'Gitleaks snapshot rejected an unsafe repository path.\n' >&2
      return 2
    }

    if [[ -L "$HH_SECURITY_REPO_ROOT/$path" ]]; then
      link_target="$(readlink "$HH_SECURITY_REPO_ROOT/$path")"
      digest="$(printf '%s' "$link_target" | shasum -a 256 | awk '{print $1}')"
      printf '%s\0%s\0%s\0' "$path" symlink "$digest" >> "$destination"
    elif [[ -f "$HH_SECURITY_REPO_ROOT/$path" ]]; then
      digest="$(shasum -a 256 "$HH_SECURITY_REPO_ROOT/$path" | awk '{print $1}')"
      printf '%s\0%s\0%s\0' "$path" file "$digest" >> "$destination"
    else
      printf 'Gitleaks snapshot rejected a missing or special source path.\n' >&2
      return 2
    fi
  done < "$file_list"
}

copy_source_snapshot() {
  local path=''
  local parent=''
  local link_target=''

  while IFS= read -r -d '' path; do
    parent="$(dirname -- "$snapshot_tree/$path")"
    mkdir -p -- "$parent"
    if [[ -L "$HH_SECURITY_REPO_ROOT/$path" ]]; then
      link_target="$(readlink "$HH_SECURITY_REPO_ROOT/$path")"
      ln -s -- "$link_target" "$snapshot_tree/$path"
    else
      cp -p -- "$HH_SECURITY_REPO_ROOT/$path" "$snapshot_tree/$path"
    fi
  done < "$file_list"
}

write_source_manifest "$manifest_before"
copy_source_snapshot
write_source_manifest "$manifest_after"

if ! cmp -s -- "$manifest_before" "$manifest_after"; then
  printf 'Repository source changed while the Gitleaks snapshot was created.\n' >&2
  exit 2
fi

snapshot_manifest_sha256="$(shasum -a 256 "$manifest_before" | awk '{print $1}')"
source_file_count="$(tr -cd '\000' < "$file_list" | wc -c | tr -d '[:space:]')"
head_sha=''
history_commit_count=0
if git -C "$HH_SECURITY_REPO_ROOT" rev-parse --verify HEAD >/dev/null 2>&1; then
  head_sha="$(git -C "$HH_SECURITY_REPO_ROOT" rev-parse HEAD)"
  git clone --quiet --mirror --no-local "$HH_SECURITY_REPO_ROOT" "$history_repo"
  git --git-dir "$history_repo" cat-file -e "${head_sha}^{commit}"
  history_commit_count="$(git --git-dir "$history_repo" rev-list --count "$head_sha")"
  [[ "$history_commit_count" =~ ^[1-9][0-9]*$ ]] || {
    printf 'Gitleaks history snapshot contains no candidate commits.\n' >&2
    exit 2
  }
fi

docker_base=(
  docker run --rm --network none --read-only --cap-drop ALL
  --security-opt no-new-privileges --pids-limit 128 --memory 512m --cpus 2
  --user "$host_uid:$host_gid"
  --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=64m"
  --mount "type=bind,src=$HH_SECURITY_ARTIFACT_DIR,dst=/out"
  --mount "type=bind,src=$HH_SECURITY_REPO_ROOT/.gitleaks.toml,dst=/gitleaks.toml,readonly"
)

"$bounded" gitleaks-working-tree "$hard_timeout_seconds" \
  "$stall_timeout_seconds" \
  "$HH_SECURITY_ARTIFACT_DIR/gitleaks-working-tree.log" \
  "${docker_base[@]}" \
  --mount "type=bind,src=$snapshot_tree,dst=/snapshot,readonly" \
  --workdir /snapshot \
  "$gitleaks_image" dir /snapshot \
  --config /gitleaks.toml --ignore-gitleaks-allow --no-banner --no-color \
  --redact=100 --report-format json \
  --report-path /out/gitleaks-working-tree.json --timeout 600

if [[ -n "$head_sha" ]]; then
  "$bounded" gitleaks-history "$hard_timeout_seconds" \
    "$stall_timeout_seconds" \
    "$HH_SECURITY_ARTIFACT_DIR/gitleaks-history.log" \
    "${docker_base[@]}" \
    --mount "type=bind,src=$history_repo,dst=/history,readonly" \
    --workdir /history \
    "$gitleaks_image" git /history \
    --config /gitleaks.toml --ignore-gitleaks-allow --no-banner --no-color \
    --redact=100 --report-format json \
    --report-path /out/gitleaks-history.json --timeout 600
  if grep -Eq 'not a git repository|(^|[^[:digit:]])0 commits scanned' \
    "$HH_SECURITY_ARTIFACT_DIR/gitleaks-history.log"; then
    printf 'Gitleaks did not scan the self-contained history snapshot.\n' >&2
    exit 2
  fi
else
  printf '[]\n' > "$HH_SECURITY_ARTIFACT_DIR/gitleaks-history.json"
fi

jq -e 'type == "array"' \
  "$HH_SECURITY_ARTIFACT_DIR/gitleaks-working-tree.json" > /dev/null
jq -e 'type == "array"' \
  "$HH_SECURITY_ARTIFACT_DIR/gitleaks-history.json" > /dev/null

receipt_tmp="$HH_SECURITY_ARTIFACT_DIR/gitleaks-receipt.json.tmp"
jq -n \
  --arg status passed \
  --arg image "$gitleaks_image" \
  --arg head "$head_sha" \
  --arg manifestSha256 "$snapshot_manifest_sha256" \
  --argjson sourceFileCount "$source_file_count" \
  --argjson historyCommitCount "$history_commit_count" \
  '{
    status: $status,
    image: $image,
    head: (if $head == "" then null else $head end),
    sourceFileCount: $sourceFileCount,
    historyCommitCount: $historyCommitCount,
    snapshotManifestSha256: $manifestSha256,
    workingTreeReport: "gitleaks-working-tree.json",
    historyReport: "gitleaks-history.json"
  }' > "$receipt_tmp"
mv -f -- "$receipt_tmp" "$HH_SECURITY_ARTIFACT_DIR/gitleaks-receipt.json"

printf 'Gitleaks passed for deterministic source snapshot: %s\n' \
  "$HH_SECURITY_REPO_ROOT"
