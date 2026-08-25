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
windows_receipt="$repo_root/.artifacts/qualification/windows/$candidate_sha/receipt.json"
runtime_verification_receipt="$repo_root/.artifacts/release/$candidate_sha/evidence/runtime/runtime-verification.json"
runtime_contract_receipt="$repo_root/.artifacts/release/$candidate_sha/evidence/runtime/runtime-container.json"
publication_root="$repo_root/.artifacts/publication/$candidate_sha"

for receipt in "$candidate_receipt" "$runtime_verification_receipt" \
  "$runtime_contract_receipt" "$windows_receipt"; do
  [[ -f "$receipt" ]] || {
    printf 'Required release receipt is missing: %s\n' "$receipt" >&2
    exit 2
  }
done
jq -e --arg sha "$candidate_sha" \
  '.status == "passed" and .candidateSha == $sha' \
  "$candidate_receipt" >/dev/null
jq -e --arg sha "$candidate_sha" \
  '.status == "passed" and .candidateSha == $sha' \
  "$windows_receipt" >/dev/null

package_sha="$(jq -r '.packageArchiveSha256' "$candidate_receipt")"
runtime_receipt_sha256="$(shasum -a 256 "$runtime_verification_receipt" | awk '{print $1}')"
jq -e --arg runtimeSha "$runtime_receipt_sha256" \
  '.runtimeReceiptSha256 == $runtimeSha' "$candidate_receipt" >/dev/null || {
  printf 'The production runtime receipt is not bound to the candidate.\n' >&2
  exit 2
}
controller_image_id="$(jq -r '.controller.imageId' "$runtime_contract_receipt")"
jq -e --arg imageId "$controller_image_id" '
  .status == "passed" and .controller.imageId == $imageId and
  .controller.dockerSocketMounted == false and
  .parser.networkMode == "none" and
  .parser.secretDatabaseOrSshMountCount == 0
' "$runtime_contract_receipt" >/dev/null || {
  printf 'The production runtime receipt is incomplete.\n' >&2
  exit 2
}
jq -e '
  .status == "passed" and
  .freshExternalVolumes == 6 and
  .nativeMigrationAttempted == false and
  .exactVolumeDestructionVerified == true and
  .cliJourney.journeys == 23 and
  .cliJourney.spaceContainingDataRootVerified == true
' "$runtime_verification_receipt" >/dev/null || {
  printf 'The production runtime journey receipt is incomplete.\n' >&2
  exit 2
}
jq -e --arg packageSha "$package_sha" --arg imageId "$controller_image_id" '
  .packageArchiveSha256 == $packageSha and
  .controllerMode == "LinuxDockerVolume" and
  .controllerImageId == $imageId and
  .controllerVolumeCount == 6 and
  .controllerVolumeCleanupComplete == true and
  .controllerVolumesDestroyed == 6 and
  .stablePackagedModuleVerified == true and
  .targetPlatform == "Windows" and
  .directRuntime == "PowerShell7" and .directEdition == "Core" and
  .directExecutionMode == "Direct" and
  .compatibilityRuntime == "WindowsPowerShell51" and
  .compatibilityEdition == "Desktop" and
  .compatibilityExecutionMode == "WindowsPowerShellCompatibility" and
  .mixedTargetCount == 2 and .keyTransitionSucceeded == true and
  .restartPersistenceVerified == true and
  .escalationPreferenceVerified == true and
  .processAuditPowerShell7Verified == true and
  .processAuditWindowsPowerShell51Verified == true and
  .commandLineEnabledEventVerified == true and
  .commandLineDisabledEventVerified == true and
  .processAuditPolicyRestored == true and
  .runScopedSshAgentVerified == true and
  .runScopedSshAgentIdentityRemoved == true and
  .runScopedSshAgentStopped == true and
  .passwordAuthenticationPreserved == true and
  .remoteQualificationKeyRemoved == true and
  .cleanupComplete == true and .redacted == true
' "$windows_receipt" >/dev/null || {
  printf 'The Windows qualification receipt is incomplete.\n' >&2
  exit 2
}

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

gh api "repos/$repository_slug" > "$publication_root/raw/repository-before-push.json"
gh api "repos/$repository_slug/actions/permissions" \
  > "$publication_root/raw/actions-before-push.json"
jq -e --arg owner "$owner" '
  .visibility == "public" and .owner.login == $owner and
  .default_branch == "main"
' "$publication_root/raw/repository-before-push.json" >/dev/null
jq -e '.enabled == false' \
  "$publication_root/raw/actions-before-push.json" >/dev/null

remote_url="$(git -C "$repo_root" remote get-url origin)"
[[ "$remote_url" == "https://github.com/$repository_slug.git" || \
  "$remote_url" == "git@github.com:$repository_slug.git" ]] || {
  printf 'Origin is not the approved repository: %s\n' "$remote_url" >&2
  exit 2
}
git -C "$repo_root" push origin "$candidate_sha:refs/heads/main"

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
    canonicalRuntime: "DockerVolume",
    liveWindowsControllerMode: "LinuxDockerVolume",
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
