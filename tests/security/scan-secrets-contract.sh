#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/hh-gitleaks-contract.XXXXXX")"
fixture_repo="$fixture_root/repo"
fake_bin="$fixture_root/bin"

cleanup() {
  rm -rf -- "$fixture_root"
}
trap cleanup EXIT INT TERM HUP

mkdir -p -- "$fixture_repo/scripts/security" "$fixture_repo/scripts/lib" \
  "$fake_bin"
cp -- "$repo_root/scripts/security/scan-secrets.sh" \
  "$repo_root/scripts/security/common.sh" "$fixture_repo/scripts/security/"
cp -- "$repo_root/scripts/lib/run-bounded.sh" "$fixture_repo/scripts/lib/"
cp -- "$repo_root/.gitleaks.toml" "$fixture_repo/.gitleaks.toml"

cat > "$fake_bin/docker" <<'FAKE_DOCKER'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == info ]]; then exit 0; fi
if [[ "${HH_FAKE_DOCKER_HANG:-0}" == 1 ]]; then sleep 10; fi
out_root=''
snapshot_root=''
history_root=''
report_path=''
history_mode=false
previous=''
for argument in "$@"; do
  case "$argument" in
    type=bind,src=*,dst=/out)
      out_root="${argument#type=bind,src=}"
      out_root="${out_root%,dst=/out}"
      ;;
    type=bind,src=*,dst=/snapshot,readonly)
      snapshot_root="${argument#type=bind,src=}"
      snapshot_root="${snapshot_root%,dst=/snapshot,readonly}"
      ;;
    type=bind,src=*,dst=/history,readonly)
      history_root="${argument#type=bind,src=}"
      history_root="${history_root%,dst=/history,readonly}"
      ;;
    git)
      history_mode=true
      ;;
  esac
  if [[ "$previous" == --report-path ]]; then report_path="$argument"; fi
  previous="$argument"
done
[[ -n "$out_root" && -n "$report_path" ]] || exit 70
if [[ "$history_mode" == true ]]; then
  [[ -n "$history_root" && -f "$history_root/HEAD" && \
    -d "$history_root/objects" ]] || exit 71
fi
host_report="$out_root/${report_path#/out/}"
if [[ -n "$snapshot_root" ]] &&
  grep -R -l --binary-files=without-match 'HH_FAKE_SECRET_[A-Z0-9]*' \
    "$snapshot_root" >/dev/null 2>&1; then
  printf '[{"RuleID":"fixture-secret","Secret":"REDACTED"}]\n' > "$host_report"
  exit 1
fi
printf '[]\n' > "$host_report"
FAKE_DOCKER
chmod +x "$fake_bin/docker" "$fixture_repo/scripts/security/scan-secrets.sh" \
  "$fixture_repo/scripts/lib/run-bounded.sh"

git -C "$fixture_repo" init -q -b main
git -C "$fixture_repo" config user.name 'HostHunter test'
git -C "$fixture_repo" config user.email 'hosthunter-test@example.invalid'
printf '*.hhout\n.artifacts/\n' > "$fixture_repo/.gitignore"
printf 'clean source\n' > "$fixture_repo/README.md"
git -C "$fixture_repo" add .
git -C "$fixture_repo" commit -qm baseline

run_scan() {
  PATH="$fake_bin:$PATH" "$fixture_repo/scripts/security/scan-secrets.sh"
}

run_scan >/dev/null

printf 'HH_FAKE_SECRET_UNTRACKED\n' > "$fixture_repo/untracked.txt"
if run_scan >/dev/null 2>&1; then
  printf 'untracked non-ignored secret was not rejected\n' >&2
  exit 1
fi
rm -- "$fixture_repo/untracked.txt"

printf 'HH_FAKE_SECRET_IGNORED\n' > "$fixture_repo/ignored.hhout"
run_scan >/dev/null
git -C "$fixture_repo" add -f ignored.hhout
if run_scan >/dev/null 2>&1; then
  printf 'force-tracked ignored secret was not rejected\n' >&2
  exit 1
fi
git -C "$fixture_repo" rm --cached -q ignored.hhout
rm -- "$fixture_repo/ignored.hhout"

printf 'clean tracked ignored file\n' > "$fixture_repo/tracked.hhout"
git -C "$fixture_repo" add -f tracked.hhout
git -C "$fixture_repo" commit -qm 'track ignored fixture'
printf 'HH_FAKE_SECRET_MODIFIED\n' > "$fixture_repo/tracked.hhout"
if run_scan >/dev/null 2>&1; then
  printf 'modified tracked ignored secret was not rejected\n' >&2
  exit 1
fi
git -C "$fixture_repo" checkout -q -- tracked.hhout

linked_worktree="$fixture_root/linked-worktree"
git -C "$fixture_repo" worktree add --quiet --detach "$linked_worktree" HEAD
PATH="$fake_bin:$PATH" "$linked_worktree/scripts/security/scan-secrets.sh" >/dev/null
git -C "$fixture_repo" worktree remove --force "$linked_worktree"

outside_secret="$fixture_root/outside-secret"
printf 'HH_FAKE_SECRET_OUTSIDE\n' > "$outside_secret"
ln -s -- "$outside_secret" "$fixture_repo/outside-link"
printf 'safe\n' > "$fixture_repo/space and
newline.txt"
run_scan >/dev/null
rm -- "$fixture_repo/outside-link" "$fixture_repo/space and
newline.txt"

set +e
PATH="$fake_bin:$PATH" HH_FAKE_DOCKER_HANG=1 \
  HH_GITLEAKS_HARD_TIMEOUT_SECONDS=2 HH_GITLEAKS_STALL_TIMEOUT_SECONDS=1 \
  "$fixture_repo/scripts/security/scan-secrets.sh" >/dev/null 2>&1
bounded_status=$?
set -e
if [[ "$bounded_status" -ne 124 && "$bounded_status" -ne 125 ]]; then
  printf 'hung scanner was not terminated by the bounded runner: %s\n' \
    "$bounded_status" >&2
  exit 1
fi

printf 'Deterministic Gitleaks snapshot contract passed\n'
