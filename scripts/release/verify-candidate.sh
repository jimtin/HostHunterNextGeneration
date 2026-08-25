#!/usr/bin/env bash

set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s CANDIDATE_SHA\n' "$0" >&2
  exit 64
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(git -C "$script_dir/../.." rev-parse --show-toplevel)"
repo_root="$(cd -- "$repo_root" && pwd -P)"
candidate_input="$1"

if [[ -n "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)" ]]; then
  printf 'Exact-candidate verification requires a clean source repository.\n' >&2
  exit 2
fi

candidate_sha="$(git -C "$repo_root" rev-parse --verify \
  "${candidate_input}^{commit}" 2>/dev/null)" || {
  printf 'Unknown candidate commit: %s\n' "$candidate_input" >&2
  exit 2
}
candidate_tree="$(git -C "$repo_root" show -s --format=%T "$candidate_sha")"
short_sha="${candidate_sha:0:12}"
artifact_root="$repo_root/.artifacts/release/$candidate_sha"
worktree_root="$(mktemp -d "${TMPDIR:-/tmp}/hosthunter-candidate.XXXXXX")"
checkout_root="$worktree_root/checkout"
started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
project_name="hosthunter-candidate-${short_sha}-$$"
worktree_added=false

cleanup() {
  docker compose --project-name "$project_name" \
    --file "$checkout_root/compose.test.yml" \
    down --volumes --remove-orphans >/dev/null 2>&1 || true
  if [[ "$worktree_added" == true ]]; then
    git -C "$repo_root" worktree remove --force "$checkout_root" \
      >/dev/null 2>&1 || true
  fi
  rm -rf -- "$worktree_root"
}
trap cleanup EXIT INT TERM HUP

mkdir -p -- "$artifact_root"
git -C "$repo_root" worktree add --detach "$checkout_root" "$candidate_sha"
worktree_added=true

if [[ "$(git -C "$checkout_root" rev-parse HEAD)" != "$candidate_sha" ]] ||
  [[ -n "$(git -C "$checkout_root" status --porcelain=v1 --untracked-files=all)" ]]; then
  printf 'Detached candidate checkout is not the requested clean commit.\n' >&2
  exit 2
fi

export COMPOSE_PROJECT_NAME="$project_name"
export HH_CANDIDATE_SHA="$candidate_sha"

(cd -- "$checkout_root" && ./scripts/verify-local.sh)

package_path_container="$(jq -r '.packagePath' \
  "$checkout_root/.artifacts/build/module-package.json")"
case "$package_path_container" in
  /artifacts/*)
    package_root="$checkout_root/.artifacts/${package_path_container#/artifacts/}"
    ;;
  *)
    printf 'Build receipt returned an unsafe package path: %s\n' \
      "$package_path_container" >&2
    exit 2
    ;;
esac
[[ -d "$package_root" ]] || {
  printf 'Built candidate package is missing: %s\n' "$package_root" >&2
  exit 2
}

(cd -- "$checkout_root" && \
  ./scripts/security/scan-release-package.sh "$package_root")

package_inventory="$artifact_root/package-sha256.txt"
(cd -- "$package_root" && \
  find . -type f -exec shasum -a 256 {} \; | LC_ALL=C sort -k2) \
  > "$package_inventory"
package_inventory_sha256="$(shasum -a 256 "$package_inventory" | awk '{print $1}')"

archive_path="$artifact_root/HostHunterNextGeneration-${candidate_sha}.tar.gz"
COPYFILE_DISABLE=1 tar -C "$(dirname -- "$package_root")" \
  -czf "$archive_path" "$(basename -- "$package_root")"
package_archive_sha256="$(shasum -a 256 "$archive_path" | awk '{print $1}')"

mkdir -p -- "$artifact_root/evidence"
"$checkout_root/scripts/release/copy-proof-receipts.sh" \
  "$checkout_root/.artifacts" "$artifact_root/evidence"

runtime_receipt="$artifact_root/evidence/runtime/runtime-verification.json"
runtime_contract="$artifact_root/evidence/runtime/runtime-container.json"
security_receipt="$artifact_root/evidence/security/receipt.json"
for required_receipt in "$runtime_receipt" "$runtime_contract" "$security_receipt"; do
  [[ -f "$required_receipt" ]] || {
    printf 'Required compact candidate evidence is missing: %s\n' \
      "$required_receipt" >&2
    exit 2
  }
done
jq -e '
  .status == "passed" and
  .freshExternalVolumes == 6 and
  .nativeMigrationAttempted == false and
  .exactVolumeDestructionVerified == true and
  .cliJourney.journeys == 23 and
  .cliJourney.spaceContainingDataRootVerified == true and
  (.parserEcsJourneys | length) == 2 and
  ([.parserEcsJourneys[] |
    select(.status == "passed" and .ecsVersion == "9.5.0" and
      .plaintextJsonlArtifactCreated == false)] | length) == 2
' \
  "$runtime_receipt" >/dev/null
jq -e '.status == "passed" and .controller.imageId and .parser.imageId' \
  "$runtime_contract" >/dev/null
jq -e '.status == "passed" and .scope == "full-product-and-production-runtime"' \
  "$security_receipt" >/dev/null
runtime_receipt_sha256="$(shasum -a 256 "$runtime_receipt" | awk '{print $1}')"
controller_image_id="$(jq -r '.controller.imageId' "$runtime_contract")"
parser_image_id="$(jq -r '.parser.imageId' "$runtime_contract")"

if [[ -n "$(git -C "$checkout_root" status --porcelain=v1 --untracked-files=all)" ]]; then
  printf 'Candidate proof dirtied tracked or unignored checkout state.\n' >&2
  exit 2
fi
if [[ "$(git -C "$checkout_root" rev-parse HEAD)" != "$candidate_sha" ]]; then
  printf 'Candidate checkout HEAD changed during proof.\n' >&2
  exit 2
fi

finished_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
receipt_tmp="$artifact_root/receipt.json.tmp"
jq -n \
  --arg status passed \
  --arg candidateSha "$candidate_sha" \
  --arg candidateTree "$candidate_tree" \
  --arg packageArchive "$(basename -- "$archive_path")" \
  --arg packageArchiveSha256 "$package_archive_sha256" \
  --arg packageInventorySha256 "$package_inventory_sha256" \
  --arg runtimeReceiptSha256 "$runtime_receipt_sha256" \
  --arg controllerImageId "$controller_image_id" \
  --arg parserImageId "$parser_image_id" \
  --arg composeProject "$project_name" \
  --arg startedAtUtc "$started_at" \
  --arg finishedAtUtc "$finished_at" \
  '{
    status: $status,
    candidateSha: $candidateSha,
    candidateTree: $candidateTree,
    packageArchive: $packageArchive,
    packageArchiveSha256: $packageArchiveSha256,
    packageInventorySha256: $packageInventorySha256,
    runtimeReceiptSha256: $runtimeReceiptSha256,
    productionRuntimeImageIds: {
      controller: $controllerImageId,
      parser: $parserImageId
    },
    composeProject: $composeProject,
    startedAtUtc: $startedAtUtc,
    finishedAtUtc: $finishedAtUtc,
    fullProofReceipt: "evidence/summary/verify-local.json",
    releasePackageReceipt: "evidence/security/release-package/receipt.json"
  }' > "$receipt_tmp"
mv -f -- "$receipt_tmp" "$artifact_root/receipt.json"

printf 'Exact candidate proof passed: %s\nReceipt: %s\n' \
  "$candidate_sha" "$artifact_root/receipt.json"
