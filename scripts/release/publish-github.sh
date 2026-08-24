#!/usr/bin/env bash

set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s CANDIDATE_SHA\n' "$0" >&2
  exit 64
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(git -C "$script_dir/../.." rev-parse --show-toplevel)"
repo_root="$(cd -- "$repo_root" && pwd -P)"
candidate_sha="$(git -C "$repo_root" rev-parse --verify "$1^{commit}" 2>/dev/null)" || {
  printf 'Unknown candidate commit: %s\n' "$1" >&2
  exit 2
}
owner='jimtin'
repository='HostHunterNextGeneration'
repository_slug="$owner/$repository"
candidate_receipt="$repo_root/.artifacts/release/$candidate_sha/receipt.json"
macos_receipt="$repo_root/.artifacts/qualification/macos/$candidate_sha/receipt.json"
windows_receipt="$repo_root/.artifacts/qualification/windows/$candidate_sha/receipt.json"
publication_root="$repo_root/.artifacts/publication/$candidate_sha"

for receipt in "$candidate_receipt" "$macos_receipt" "$windows_receipt"; do
  [[ -f "$receipt" ]] || {
    printf 'Required release receipt is missing: %s\n' "$receipt" >&2
    exit 2
  }
  jq -e --arg sha "$candidate_sha" \
    '.status == "passed" and .candidateSha == $sha' "$receipt" >/dev/null || {
    printf 'Required release receipt is invalid: %s\n' "$receipt" >&2
    exit 2
  }
done

package_sha="$(jq -r '.packageArchiveSha256' "$candidate_receipt")"
for receipt in "$macos_receipt" "$windows_receipt"; do
  jq -e --arg packageSha "$package_sha" \
    '.packageArchiveSha256 == $packageSha' "$receipt" >/dev/null || {
    printf 'Native qualification did not use the exact candidate package.\n' >&2
    exit 2
  }
done

[[ -z "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)" ]] || {
  printf 'Publication requires a clean source repository.\n' >&2
  exit 2
}
[[ "$(git -C "$repo_root" rev-parse HEAD)" == "$candidate_sha" ]] || {
  printf 'Publication requires HEAD to equal the qualified candidate.\n' >&2
  exit 2
}
if git -C "$repo_root" ls-tree -r --name-only "$candidate_sha" -- .github/workflows |
  grep -q .; then
  printf 'Candidate contains prohibited GitHub Actions workflows.\n' >&2
  exit 2
fi

command -v gh >/dev/null 2>&1 || {
  printf 'GitHub CLI is required for publication.\n' >&2
  exit 2
}
gh auth status >/dev/null
mkdir -p -- "$publication_root/raw"

if gh api "repos/$repository_slug" >/dev/null 2>&1; then
  printf 'Refusing to reuse an existing GitHub repository: %s\n' \
    "$repository_slug" >&2
  exit 2
fi

gh repo create "$repository_slug" --private --disable-wiki
gh api --method PUT "repos/$repository_slug/actions/permissions" \
  --input - <<< '{"enabled":false}' >/dev/null
gh api "repos/$repository_slug/actions/permissions" \
  > "$publication_root/raw/actions-before-push.json"
jq -e '.enabled == false' \
  "$publication_root/raw/actions-before-push.json" >/dev/null

remote_url="https://github.com/$repository_slug.git"
git -C "$repo_root" push "$remote_url" "$candidate_sha:refs/heads/main"
gh api --method PATCH "repos/$repository_slug" \
  -f default_branch=main >/dev/null

gh api --method PATCH "repos/$repository_slug" \
  -f visibility=public >/dev/null
gh api --method PUT "repos/$repository_slug/branches/main/protection" \
  --input - <<'PROTECTION' >/dev/null
{
  "required_status_checks": null,
  "enforce_admins": true,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": false,
  "lock_branch": false,
  "allow_fork_syncing": false
}
PROTECTION

gh api "repos/$repository_slug" > "$publication_root/raw/repository.json"
gh api "repos/$repository_slug/actions/permissions" \
  > "$publication_root/raw/actions.json"
gh api "repos/$repository_slug/collaborators?affiliation=direct&per_page=100" \
  > "$publication_root/raw/collaborators.json"
gh api "repos/$repository_slug/keys?per_page=100" \
  > "$publication_root/raw/deploy-keys.json"
gh api "repos/$repository_slug/hooks?per_page=100" \
  > "$publication_root/raw/hooks.json"
gh api "repos/$repository_slug/actions/workflows?per_page=100" \
  > "$publication_root/raw/workflows.json"
gh api "repos/$repository_slug/branches/main/protection" \
  > "$publication_root/raw/branch-protection.json"
gh api "repos/$repository_slug/git/ref/heads/main" \
  > "$publication_root/raw/main-ref.json"

printf '[]\n' > "$publication_root/raw/repository-installations.json"
while IFS= read -r installation_id; do
  installation_repositories="$publication_root/raw/installation-$installation_id-repositories.json"
  gh api --paginate --slurp \
    "user/installations/$installation_id/repositories?per_page=100" \
    > "$installation_repositories"
  if jq -e --arg fullName "$repository_slug" \
    '.[]?.repositories[]? | select(.full_name == $fullName)' \
    "$installation_repositories" >/dev/null; then
    jq --argjson id "$installation_id" '. + [$id]' \
      "$publication_root/raw/repository-installations.json" \
      > "$publication_root/raw/repository-installations.json.tmp"
    mv -f "$publication_root/raw/repository-installations.json.tmp" \
      "$publication_root/raw/repository-installations.json"
  fi
done < <(gh api --paginate 'user/installations?per_page=100' \
  --jq '.installations[].id')

jq -e --arg owner "$owner" '
  .visibility == "public" and .owner.login == $owner and
  .default_branch == "main"
' "$publication_root/raw/repository.json" >/dev/null
jq -e '.enabled == false' "$publication_root/raw/actions.json" >/dev/null
jq -e --arg owner "$owner" '
  length == 1 and .[0].login == $owner and .[0].permissions.admin == true
' "$publication_root/raw/collaborators.json" >/dev/null
jq -e 'length == 0' "$publication_root/raw/deploy-keys.json" >/dev/null
jq -e 'length == 0' "$publication_root/raw/hooks.json" >/dev/null
jq -e '.total_count == 0' "$publication_root/raw/workflows.json" >/dev/null
jq -e 'length == 0' \
  "$publication_root/raw/repository-installations.json" >/dev/null
jq -e '
  .allow_force_pushes.enabled == false and
  .allow_deletions.enabled == false and
  .enforce_admins.enabled == true
' "$publication_root/raw/branch-protection.json" >/dev/null
jq -e --arg sha "$candidate_sha" '.object.sha == $sha' \
  "$publication_root/raw/main-ref.json" >/dev/null

receipt_tmp="$publication_root/receipt.json.tmp"
jq -n \
  --arg status passed \
  --arg candidateSha "$candidate_sha" \
  --arg packageArchiveSha256 "$package_sha" \
  --arg repository "$repository_slug" \
  '{
    status: $status,
    candidateSha: $candidateSha,
    packageArchiveSha256: $packageArchiveSha256,
    repository: $repository,
    visibility: "public",
    actionsEnabled: false,
    directCollaborators: ["jimtin"],
    deployKeyCount: 0,
    hookCount: 0,
    workflowCount: 0,
    repositoryInstallationCount: 0,
    forcePushAllowed: false,
    branchDeletionAllowed: false
  }' > "$receipt_tmp"
mv -f -- "$receipt_tmp" "$publication_root/receipt.json"

printf 'GitHub publication verified: %s at %s\n' \
  "$repository_slug" "$candidate_sha"
