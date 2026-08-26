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

terminal_status=failed
terminal_phase=initialization
terminal_reason='Release process exited before completing all phases'
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

# Invoked by the EXIT and signal traps below.
# shellcheck disable=SC2329
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
# Invoked by the signal traps below.
# shellcheck disable=SC2329
abort_signal() {
  terminal_status=aborted
  terminal_phase=interrupted
  terminal_reason="Release process received signal $1; the exact SHA remains consumed"
  terminal_exit_code=130
  exit 130
}
block() {
  terminal_status=blocked
  terminal_phase="$1"
  terminal_reason="$2"
  terminal_exit_code=2
  printf '%s\n' "$2" >&2
  exit 2
}
trap cleanup EXIT
trap 'abort_signal INT' INT
trap 'abort_signal TERM' TERM
trap 'abort_signal HUP' HUP

# An existing directory is a permanently consumed SHA. If its owner is gone,
# seal it aborted; in every case refuse to execute candidate work again.
if [[ -e "$artifact_root" ]]; then
  python3 "$state" recover --root "$artifact_root" --sha "$candidate_sha" \
    --stale-after "${HH_RELEASE_CLAIM_STALE_AFTER_SECONDS:-86400}" >/dev/null 2>&1 || true
  printf 'Exact SHA has already been claimed and can never rerun: %s\n' "$candidate_sha" >&2
  exit 73
fi

# mkdir(2) on the exact-SHA directory is the atomic, durable once-only claim.
python3 "$state" claim --root "$artifact_root" --sha "$candidate_sha" \
  --tree "$candidate_tree" --started "$started_at" --pid "$$"
claim_acquired=true

terminal_phase=source-preconditions
[[ -z "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)" ]] || \
  block "$terminal_phase" 'Exact-candidate verification requires a clean source repository.'

worktree_root="$(mktemp -d "${TMPDIR:-/tmp}/hosthunter-candidate.XXXXXX")"
checkout_root="$worktree_root/checkout"
git -C "$repo_root" worktree add --detach "$checkout_root" "$candidate_sha"
worktree_added=true
[[ "$(git -C "$checkout_root" rev-parse HEAD)" == "$candidate_sha" ]] || \
  block detached-checkout 'Detached checkout does not match the claimed SHA.'

export COMPOSE_PROJECT_NAME="$project_name"
export HH_CANDIDATE_SHA="$candidate_sha"

terminal_phase=cmdlet-verdict
cmdlet_command="${HH_CMDLET_VERIFY_COMMAND:-./scripts/verify-cmdlets.sh}"
set +e
(cd -- "$checkout_root" && bash -c "$cmdlet_command")
cmdlet_exit=$?
set -e
cmdlet_source="${HH_CMDLET_RECEIPT_PATH:-$checkout_root/.artifacts/cmdlets/$candidate_sha/cmdlets/receipt.json}"
if [[ -f "$cmdlet_source" ]]; then
  python3 "$state" record --root "$artifact_root" --sha "$candidate_sha" \
    --kind cmdlet --source "$cmdlet_source"
else
  cmdlet_status=failed
  [[ "$cmdlet_exit" -eq 0 ]] && cmdlet_status=blocked
  python3 "$state" record --root "$artifact_root" --sha "$candidate_sha" \
    --kind cmdlet --status "$cmdlet_status" \
    --reason "Cmdlet verifier exit $cmdlet_exit did not produce its independent receipt"
fi

terminal_phase=heavy-proof
heavy_command="${HH_RELEASE_PROOF_COMMAND:-./scripts/verify-local.sh}"
set +e
(cd -- "$checkout_root" && bash -c "$heavy_command")
heavy_exit=$?
set -e
heavy_source="${HH_RELEASE_PROOF_RECEIPT_PATH:-$checkout_root/.artifacts/summary/verify-local.json}"
if [[ -f "$heavy_source" ]]; then
  python3 "$state" record --root "$artifact_root" --sha "$candidate_sha" \
    --kind heavy --source "$heavy_source"
else
  heavy_status=failed
  [[ "$heavy_exit" -eq 0 ]] && heavy_status=blocked
  python3 "$state" record --root "$artifact_root" --sha "$candidate_sha" \
    --kind heavy --status "$heavy_status" \
    --reason "Heavy proof exit $heavy_exit did not produce its independent receipt"
fi

terminal_phase=windows-qualification
windows_command="${HH_WINDOWS_QUALIFICATION_COMMAND:-}"
windows_source="${HH_WINDOWS_QUALIFICATION_RECEIPT_PATH:-$checkout_root/.artifacts/qualification/windows/$candidate_sha/receipt.json}"
if [[ -z "$windows_command" ]]; then
  windows_exit=2
  python3 "$state" record --root "$artifact_root" --sha "$candidate_sha" \
    --kind windows --status blocked \
    --reason 'Live Windows qualification command was not supplied for this exact SHA'
else
  set +e
  (cd -- "$checkout_root" && bash -c "$windows_command")
  windows_exit=$?
  set -e
  if [[ -f "$windows_source" ]]; then
    python3 "$state" record --root "$artifact_root" --sha "$candidate_sha" \
      --kind windows --source "$windows_source"
  else
    windows_status=failed
    [[ "$windows_exit" -eq 0 ]] && windows_status=blocked
    python3 "$state" record --root "$artifact_root" --sha "$candidate_sha" \
      --kind windows --status "$windows_status" \
      --reason "Windows qualification exit $windows_exit produced no receipt"
  fi
fi

cmdlet_status="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$artifact_root/cmdlet-receipt.json")"
heavy_status="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$artifact_root/heavy-receipt.json")"
windows_status="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$artifact_root/windows-receipt.json")"
terminal_phase=aggregation
if [[ "$cmdlet_exit" -eq 0 && "$heavy_exit" -eq 0 && \
      "$windows_exit" -eq 0 && "$cmdlet_status" == passed && \
      "$heavy_status" == passed && "$windows_status" == passed ]]; then
  terminal_status=passed
  terminal_reason='Cmdlet verdict, one-shot heavy release proof, and live Windows qualification passed'
  terminal_exit_code=0
else
  terminal_status=failed
  terminal_reason="Release failed; cmdlets=$cmdlet_status heavy=$heavy_status windows=$windows_status"
  terminal_exit_code=1
fi
seal_terminal "$terminal_exit_code"
printf 'Exact candidate release is terminal: %s\nReceipt: %s\n' \
  "$terminal_status" "$artifact_root/receipt.json"
exit "$terminal_exit_code"
