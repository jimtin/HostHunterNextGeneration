#!/usr/bin/env bash
# shellcheck disable=SC2016

set -Eeuo pipefail

runtime_script_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
runtime_repo_root="$(cd -- "$runtime_script_root/../.." && pwd -P)"
readonly runtime_script_root runtime_repo_root
artifact_root="$runtime_repo_root/.artifacts/runtime"
readonly artifact_root

if [[ "${1:-}" != '--inside-bounded-run' ]]; then
  mkdir -p -- "$artifact_root"
  HH_RUNTIME_PROJECT="hosthunter-runtime-test-$(date -u '+%Y%m%d%H%M%S')-$$"
  export HH_RUNTIME_PROJECT
  exec "$runtime_repo_root/scripts/lib/run-bounded.sh" \
    runtime-production 3600 300 "$artifact_root/runtime-verification.log" \
    "$runtime_script_root/verify.sh" --inside-bounded-run
fi

shift
# shellcheck source=scripts/runtime/lib.sh
source "$runtime_script_root/lib.sh"

receipt_path="$artifact_root/runtime-verification.json"
parser_receipt_path="$artifact_root/parser-sidecar-receipts.json"
journey_log_path="$artifact_root/production-cli-journeys.log"
readonly receipt_path parser_receipt_path journey_log_path

cleanup_required=true
cleanup() {
  local cleanup_status=0
  if [[ "$cleanup_required" == true ]]; then
    runtime_compose --profile acceptance down --volumes --remove-orphans \
      >/dev/null 2>&1 || cleanup_status=1
    if [[ "$(runtime_existing_volume_count)" -eq "${#runtime_volume_names[@]}" ]]; then
      "$runtime_script_root/destroy.sh" \
        --confirm-project "$HH_RUNTIME_PROJECT" \
        --destroy-volumes >/dev/null 2>&1 || cleanup_status=1
    fi
  fi
  return "$cleanup_status"
}
trap cleanup EXIT INT TERM HUP

wait_for_health() {
  local deadline=$((SECONDS + 180))
  local service_name service_id health
  while ((SECONDS < deadline)); do
    ready=0
    for service_name in parser controller; do
      service_id="$(runtime_service_id "$service_name")"
      health='missing'
      if [[ -n "$service_id" ]]; then
        health="$(docker inspect --format '{{ .State.Health.Status }}' "$service_id")"
      fi
      if [[ "$health" == healthy ]]; then
        ready=$((ready + 1))
      elif [[ "$health" == unhealthy ]]; then
        printf '%s became unhealthy.\n' "$service_name" >&2
        return 1
      fi
    done
    if [[ "$ready" -eq 2 ]]; then
      return 0
    fi
    printf '[runtime] waiting for controller and parser health (%s/2 ready)\n' "$ready"
    sleep 5
  done
  printf 'Runtime services did not become healthy within 180 seconds.\n' >&2
  return 1
}

copy_fixture_to_evidence() {
  local source_path="$1"
  local destination_name="$2"
  local common_arguments=(
    run --rm
    --read-only
    --cap-drop ALL
    --security-opt no-new-privileges:true
    --network none
    --user 10001:10001
    --memory 64m
    --cpus 0.25
    --pids-limit 32
    --volume "$HH_RUNTIME_EVIDENCE_VOLUME:/evidence"
  )
  docker "${common_arguments[@]}" --entrypoint /bin/mkdir \
    "$HH_RUNTIME_CONTROLLER_IMAGE" -p /evidence/runtime-verify >/dev/null
  docker "${common_arguments[@]}" \
    --volume "$source_path:/source.evtx:ro" \
    --entrypoint /bin/cp \
    "$HH_RUNTIME_CONTROLLER_IMAGE" \
    /source.evtx "/evidence/runtime-verify/$destination_name" >/dev/null
  docker "${common_arguments[@]}" --entrypoint /bin/chmod \
    "$HH_RUNTIME_CONTROLLER_IMAGE" \
    0400 "/evidence/runtime-verify/$destination_name" >/dev/null
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

runtime_require_docker
printf '[runtime] initializing fresh external volumes for %s\n' "$HH_RUNTIME_PROJECT"
"$runtime_script_root/init.sh"
printf '[runtime] building production controller, isolated parser, and derived journey images\n'
runtime_compose --profile acceptance build controller parser journey ssh-target
printf '[runtime] starting hardened production services\n'
runtime_compose up --detach parser controller
wait_for_health
runtime_container_receipt_path="$("${runtime_script_root}/status.sh")"

sysmon_source="$runtime_repo_root/tests/fixtures/forensics/evtx/sysmon-1.evtx"
security_source="$runtime_repo_root/tests/fixtures/forensics/evtx/security-4688.evtx"
copy_fixture_to_evidence "$sysmon_source" sysmon-1.evtx
copy_fixture_to_evidence "$security_source" security-4688.evtx
sysmon_sha256="$(sha256_file "$sysmon_source")"
security_sha256="$(sha256_file "$security_source")"

printf '[runtime] running package-backed Sysmon 1 and Security 4688 ECS journeys through the private socket\n'
sysmon_receipt="$(runtime_compose exec --no-TTY controller \
  pwsh -NoLogo -NoProfile -NonInteractive \
  -File /opt/hosthunter/runtime/Invoke-HHRuntimeEcsJourney.ps1 \
  -FixtureName sysmon-1.evtx \
  -ExpectedSha256 "$sysmon_sha256" \
  -ExpectedRecordCount 3 \
  -ExpectedEventCount 2)"
security_receipt="$(runtime_compose exec --no-TTY controller \
  pwsh -NoLogo -NoProfile -NonInteractive \
  -File /opt/hosthunter/runtime/Invoke-HHRuntimeEcsJourney.ps1 \
  -FixtureName security-4688.evtx \
  -ExpectedSha256 "$security_sha256" \
  -ExpectedRecordCount 8 \
  -ExpectedEventCount 2)"
printf '[%s,%s]\n' "$sysmon_receipt" "$security_receipt" \
  >"$parser_receipt_path"

printf '[runtime] invoking the existing 23 package-backed CLI journeys from the production-derived image\n'
runtime_compose --profile acceptance run --rm journey | tee "$journey_log_path"
journey_receipt="$(tail -n 1 "$journey_log_path")"
[[ "$journey_receipt" == *'"journeys":23'* ]] || {
  printf 'The production-derived CLI journey receipt is missing or incomplete.\n' >&2
  exit 1
}

printf '[runtime] restarting production services and re-reading authenticated persisted audit state\n'
runtime_compose restart parser controller
wait_for_health
restart_audit_count="$(runtime_compose exec --no-TTY controller \
  pwsh -NoLogo -NoProfile -NonInteractive -Command '
    $ErrorActionPreference = "Stop"
    $env:HH_DATA_ROOT = Join-Path $env:HH_DATA_ROOT "Library/Application Support/HostHunterNextGeneration"
    Import-Module $env:HH_RUNTIME_MODULE_PATH -Force
    @(Get-HHAuditRecord -First 100).Count
  ')"
[[ "$restart_audit_count" =~ ^[1-9][0-9]*$ ]] || {
  printf 'Authenticated persistence did not survive the production service restart.\n' >&2
  exit 1
}
runtime_container_receipt_path="$("${runtime_script_root}/status.sh")"
runtime_container_receipt="$(<"$runtime_container_receipt_path")"

printf '[runtime] stopping services and removing only the exact test-project volumes\n'
runtime_compose --profile acceptance down --volumes --remove-orphans
"$runtime_script_root/destroy.sh" \
  --confirm-project "$HH_RUNTIME_PROJECT" \
  --destroy-volumes
asserted_remaining="$(runtime_existing_volume_count)"
[[ "$asserted_remaining" -eq 0 ]] || {
  printf 'Test-project volumes remained after exact destruction.\n' >&2
  exit 1
}
cleanup_required=false
trap - EXIT INT TERM HUP

receipt_tmp="$receipt_path.tmp.$$"
printf '%s\n' \
  '{' \
  '  "schemaVersion": 1,' \
  "  \"observedAtUtc\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\"," \
  '  "status": "passed",' \
  "  \"project\": \"$HH_RUNTIME_PROJECT\"," \
  '  "freshExternalVolumes": 6,' \
  '  "nativeMigrationAttempted": false,' \
  '  "exactVolumeDestructionVerified": true,' \
  "  \"restartAuditRecordCount\": $restart_audit_count," \
  "  \"runtimeContract\": $runtime_container_receipt," \
  "  \"parserEcsJourneys\": [$sysmon_receipt,$security_receipt]," \
  "  \"cliJourney\": $journey_receipt" \
  '}' >"$receipt_tmp"
mv -- "$receipt_tmp" "$receipt_path"
printf 'Runtime verification passed. Receipt: %s\n' "$receipt_path"
