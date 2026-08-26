#!/usr/bin/env bash
set -Eeuo pipefail
export PYTHONDONTWRITEBYTECODE=1

if [[ $# -ne 1 ]]; then
  printf 'usage: %s CANDIDATE_SHA\n' "$0" >&2
  exit 64
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(git -C "$script_dir/../.." rev-parse --show-toplevel)"
repo_root="$(cd -- "$repo_root" && pwd -P)"
state="$script_dir/release-receipt-state.py"
candidate_sha="$(git -C "$repo_root" rev-parse --verify "$1^{commit}" 2>/dev/null)" || {
  printf 'Unknown candidate commit: %s\n' "$1" >&2
  exit 2
}
candidate_tree="$(git -C "$repo_root" show -s --format=%T "$candidate_sha")"
artifact_root="$repo_root/.artifacts/release/$candidate_sha"
started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
windows_command="${HH_WINDOWS_QUALIFICATION_COMMAND:-}"

terminal_status=failed
terminal_phase=initialization
terminal_reason='Release process exited before completing every runnable phase'
terminal_exit_code=1
sealed=false
claim_acquired=false
worktree_root=''
checkout_root=''
worktree_added=false
project_name="hosthunter-candidate-${candidate_sha:0:12}-$$"

seal_terminal() {
  local process_exit="${1:-$?}"
  if [[ "$claim_acquired" == true && "$sealed" == false ]]; then
    if [[ "$terminal_exit_code" -eq 0 && "$terminal_status" != passed ]]; then
      terminal_exit_code="$process_exit"
    fi
    python3 "$state" seal --root "$artifact_root" --sha "$candidate_sha" \
      --status "$terminal_status" --phase "$terminal_phase" \
      --exit-code "$terminal_exit_code" --reason "$terminal_reason" \
      --finished "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >/dev/null || true
    sealed=true
  fi
}

# shellcheck disable=SC2329 # invoked by the EXIT and signal traps below
cleanup() {
  local process_exit="$?"
  trap - EXIT INT TERM HUP
  if [[ -n "$checkout_root" && -f "$checkout_root/compose.test.yml" ]]; then
    docker compose --project-name "$project_name" --file "$checkout_root/compose.test.yml" \
      down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ "$worktree_added" == true ]]; then
    git -C "$repo_root" worktree remove --force "$checkout_root" >/dev/null 2>&1 || true
  fi
  [[ -z "$worktree_root" ]] || rm -rf -- "$worktree_root"
  seal_terminal "$process_exit"
  exit "$process_exit"
}

# shellcheck disable=SC2329 # invoked by the signal traps below
abort_signal() {
  terminal_status=aborted
  terminal_phase=interrupted
  terminal_reason="Release process received signal $1; the exact SHA remains consumed"
  terminal_exit_code=130
  exit 130
}

preflight_block() {
  printf '%s\n' "$1" >&2
  exit 2
}

record_synthetic() {
  python3 "$state" record --root "$artifact_root" --sha "$candidate_sha" \
    --kind "$1" --status "$2" --reason "$3" >/dev/null
}

record_result() {
  local kind="$1" source="$2" exit_code="$3" missing_reason="$4"
  if [[ -f "$source" ]]; then
    local source_status
    source_status="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status", ""))' "$source")"
    if [[ "$exit_code" -ne 0 && "$source_status" == passed ]]; then
      record_synthetic "$kind" failed \
        "$kind exited $exit_code but emitted a contradictory passing receipt"
      return
    fi
    python3 "$state" record --root "$artifact_root" --sha "$candidate_sha" \
      --kind "$kind" --source "$source" >/dev/null
  else
    local status=failed
    [[ "$exit_code" -eq 0 ]] && status=blocked
    record_synthetic "$kind" "$status" "$missing_reason"
  fi
}

component_status() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$1"
}

trap cleanup EXIT
trap 'abort_signal INT' INT
trap 'abort_signal TERM' TERM
trap 'abort_signal HUP' HUP

# Read-only readiness checks do not consume an exact-SHA attempt.
if [[ -e "$artifact_root" ]]; then
  python3 "$state" recover --root "$artifact_root" --sha "$candidate_sha" \
    --stale-after "${HH_RELEASE_CLAIM_STALE_AFTER_SECONDS:-86400}" >/dev/null 2>&1 || true
  printf 'Exact SHA has already been claimed and can never rerun: %s\n' "$candidate_sha" >&2
  exit 73
fi
[[ -z "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)" ]] || \
  preflight_block 'Exact-candidate verification requires a clean source repository.'
docker info >/dev/null 2>&1 || preflight_block 'Docker is unavailable before the exact-SHA claim.'
[[ -n "$windows_command" ]] || \
  preflight_block 'Live Windows qualification command is required before the exact-SHA claim.'
[[ -t 0 && -t 1 ]] || \
  preflight_block 'Live Windows qualification requires an interactive terminal before claim.'

python3 "$state" claim --root "$artifact_root" --sha "$candidate_sha" \
  --tree "$candidate_tree" --started "$started_at" --pid "$$" >/dev/null
claim_acquired=true

worktree_root="$(mktemp -d "${TMPDIR:-/tmp}/hosthunter-candidate.XXXXXX")"
checkout_root="$worktree_root/checkout"
git -C "$repo_root" worktree add --detach "$checkout_root" "$candidate_sha"
worktree_added=true
[[ "$(git -C "$checkout_root" rev-parse HEAD)" == "$candidate_sha" ]]

export COMPOSE_PROJECT_NAME="$project_name"
export HH_CANDIDATE_SHA="$candidate_sha"

terminal_phase=build
build_command="${HH_RELEASE_BUILD_COMMAND:-./scripts/release/build-candidate.sh}"
set +e
(cd -- "$checkout_root" && bash -c "$build_command")
build_exit=$?
set -e
build_source="${HH_RELEASE_BUILD_RECEIPT_PATH:-$checkout_root/.artifacts/summary/build.json}"
record_result build "$build_source" "$build_exit" \
  "Build exit $build_exit did not produce its terminal receipt"
build_status="$(component_status "$artifact_root/build-receipt.json")"

if [[ "$build_status" == passed ]]; then
  export HH_RELEASE_IMAGES_PREBUILT=1
  export HH_RELEASE_CONTROLLER_IMAGE
  export HH_RELEASE_CONTROLLER_IMAGE_ID
  export HH_TEST_IMAGE
  export HH_RELEASE_TEST_IMAGE_ID
  export HH_RELEASE_SSH_IMAGE
  export HH_SSH_FIXTURE_IMAGE
  export HH_RELEASE_SSH_IMAGE_ID
  export HH_RELEASE_VERIFIER_IMAGE
  export HH_RELEASE_VERIFIER_IMAGE_ID
  HH_RELEASE_CONTROLLER_IMAGE="$(jq -r '.images.controller.tag' "$build_source")"
  HH_RELEASE_CONTROLLER_IMAGE_ID="$(jq -r '.images.controller.id' "$build_source")"
  HH_TEST_IMAGE="$(jq -r '.images.test.tag' "$build_source")"
  HH_RELEASE_TEST_IMAGE_ID="$(jq -r '.images.test.id' "$build_source")"
  HH_RELEASE_SSH_IMAGE="$(jq -r '.images.sshFixture.tag' "$build_source")"
  HH_SSH_FIXTURE_IMAGE="$HH_RELEASE_SSH_IMAGE"
  HH_RELEASE_SSH_IMAGE_ID="$(jq -r '.images.sshFixture.id' "$build_source")"
  HH_RELEASE_VERIFIER_IMAGE="$(jq -r '.images.verifier.tag' "$build_source")"
  HH_RELEASE_VERIFIER_IMAGE_ID="$(jq -r '.images.verifier.id' "$build_source")"
  export HH_RUNTIME_CONTROLLER_IMAGE="$HH_RELEASE_CONTROLLER_IMAGE"
  export HH_RELEASE_BUILD_RECEIPT="$build_source"
fi

terminal_phase=cmdlet-verdict
if [[ "$build_status" == passed ]]; then
  cmdlet_command="${HH_CMDLET_VERIFY_COMMAND:-./scripts/verify-cmdlets.sh}"
  set +e
  (cd -- "$checkout_root" && bash -c "$cmdlet_command")
  cmdlet_exit=$?
  set -e
  cmdlet_source="${HH_CMDLET_RECEIPT_PATH:-$checkout_root/.artifacts/cmdlets/$candidate_sha/cmdlets/receipt.json}"
  record_result cmdlet "$cmdlet_source" "$cmdlet_exit" \
    "Cmdlet verifier exit $cmdlet_exit did not produce its independent receipt"
else
  cmdlet_exit=0
  record_synthetic cmdlet not-run not_run_due_to_build
fi
cmdlet_status="$(component_status "$artifact_root/cmdlet-receipt.json")"

terminal_phase=windows-qualification
if [[ "$build_status" == passed && "$cmdlet_status" == passed ]]; then
  set +e
  (cd -- "$checkout_root" && bash -c "$windows_command")
  windows_exit=$?
  set -e
  windows_source="${HH_WINDOWS_QUALIFICATION_RECEIPT_PATH:-$checkout_root/.artifacts/qualification/windows/$candidate_sha/receipt.json}"
  record_result windows "$windows_source" "$windows_exit" \
    "Windows qualification exit $windows_exit produced no receipt"
else
  windows_exit=0
  record_synthetic windows not-run not_run_due_to_build_or_cmdlet
fi
windows_status="$(component_status "$artifact_root/windows-receipt.json")"

terminal_phase=release-proof
if [[ "$build_status" == passed ]]; then
  heavy_command="${HH_RELEASE_PROOF_COMMAND:-./scripts/verify-local.sh}"
  set +e
  (cd -- "$checkout_root" && bash -c "$heavy_command")
  heavy_exit=$?
  set -e
  heavy_source="${HH_RELEASE_PROOF_RECEIPT_PATH:-$checkout_root/.artifacts/summary/verify-local.json}"
  record_result heavy "$heavy_source" "$heavy_exit" \
    "Release proof exit $heavy_exit did not produce its terminal receipt"
else
  heavy_exit=0
  record_synthetic heavy not-run not_run_due_to_build
fi
heavy_status="$(component_status "$artifact_root/heavy-receipt.json")"

terminal_phase=aggregation
statuses=("$build_status" "$cmdlet_status" "$windows_status" "$heavy_status")
terminal_status=passed
terminal_exit_code=0
terminal_reason='Build, cmdlets, Windows qualification, coverage, integration, and security passed'
for status in "${statuses[@]}"; do
  if [[ "$status" == failed || "$status" == aborted ]]; then
    terminal_status=failed
    terminal_exit_code=1
  elif [[ "$status" != passed && "$terminal_status" == passed ]]; then
    terminal_status=blocked
    terminal_exit_code=2
  fi
done
if [[ "$terminal_status" != passed ]]; then
  terminal_reason="Release terminal; build=$build_status cmdlets=$cmdlet_status windows=$windows_status proof=$heavy_status"
fi

seal_terminal "$terminal_exit_code"
printf 'Exact candidate release is terminal: %s\nReceipt: %s\n' \
  "$terminal_status" "$artifact_root/receipt.json"
exit "$terminal_exit_code"
