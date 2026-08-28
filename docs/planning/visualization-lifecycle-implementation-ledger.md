# HostHunter visualization lifecycle implementation ledger

Status: **IMPLEMENTED; focused verification and installed-profile native macOS
journey green** (2026-08-29)

Confirmed on 2026-08-28. This ledger governs the integration of the existing
HostHunter CIM/mission work with the separate HostHunterVisualizer repository.
It supersedes the earlier public `Start-Mission` and automatic
controller-start mission-reset behavior. It does not discard the existing CIM
collector, encrypted observation persistence, endpoint identity, or bounded
producer adapter.

## Acceptance ledger

| ID | Requirement | Intended implementation | Focused proof | Status |
| --- | --- | --- | --- | --- |
| VL-01 | Existing HostHunter startup and animation remain unchanged | Run visualization prompt only after command synchronization and animation | Native-client unit ordering plus fresh-profile journey | verified focused and native profile |
| VL-02 | Start visualization from canonical PowerShell | Client-local `Start-HHVisualization` advanced function; no managed-host dispatch | Pester command, `WhatIf`, and container lifecycle tests | verified focused and real-service |
| VL-03 | Stop visualization from canonical PowerShell | Client-local `Stop-HHVisualization`; persist pause before volume-preserving Compose stop | Pester state/failure tests and restart integration | verified focused and real-service |
| VL-04 | Running visualizer offers a new mission with default No | Authenticated producer status probe followed by bounded interactive confirmation | Pester prompt/default tests | verified focused |
| VL-05 | Declining a new mission continues the current mission | Match local/remote run IDs, enable publishing, make no activation request | Mission-state integration and producer contract | verified focused and against real services; visual node rendering is Visualizer-owned |
| VL-06 | Accepting a new mission safely resets derived data | Recoverable pending activation plus idempotent collection-run PUT | Crash/replay and old-run pruning integration | verified focused, including lost-response reconciliation |
| VL-07 | Successful start offers to open the browser with default Yes | Interactive local browser open only after ready/compatible status | Pester interactive/noninteractive tests | verified focused |
| VL-08 | Repository locations are easy to configure | Versioned client config and installer `-VisualizerRepoRoot`; no sibling assumption | Installer round-trip, migration, moved/invalid path tests | verified focused |
| VL-09 | Connection proof authenticates the producer without mutation | Visualizer `GET /api/v1/producer/status`, bearer auth, contract versions, active run | API unit/integration tests and controller probe test | verified focused and real-service |
| VL-10 | Explicit stop pauses publishing but preserves HostHunter evidence and mission data | Authenticated current-mission selection is cleared on pause and restored from matching remote state | Persistence and managed-operation tests | verified focused and real-service |
| VL-11 | Unexpected outage preserves enabled pending deliveries | Existing local-first encrypted observation record plus bounded later reconciliation | Failure/recovery integration test | verified focused |
| VL-12 | Host details use the confirmed CIM contract | Retain `Get-TargetHostDetails`, initial onboarding collection, stable endpoint IDs and typed PUT | CIM unit/golden fixture, Linux journey and browser node proof | verified focused and native Linux target |
| VL-13 | No general-log or process-event endpoint is introduced | Retain host-only API and negative browser/API assertions | Static and E2E absence sweep | verified static/API |
| VL-14 | Existing `Start-Mission` and automatic controller-start reset are removed | Replace with client-local lifecycle commands and explicit operator action | Deleted-surface sweep and exact export contract | implemented; exact package proof passed |
| VL-15 | Visualizer startup is engaging without concealing work | Extracted client renderer shows a bounded opening animation, then retains every real lifecycle step and diagnostic line | Pure renderer tests with injected sleep/output plus one interactive-terminal contract | verified focused; lifecycle services previously verified |
| VL-16 | Visualizer failure never breaks an otherwise successful HostHunter import | Explicit command remains terminating; automatic prompt catches the failure, writes a bounded warning and returns to the loaded shell | Prompt failure Pester test and fresh-profile journey | verified focused |
| VL-17 | Lifecycle code no longer expands the client monolith | Move visualization-only functions to one installed private component and copy that component through the installer | Module packaging, import and deleted-surface tests | verified focused |

## User-action coverage matrix

| User action | Surface | Persona/state | Expected behavior | Service/E2E evidence | Unit/integration evidence | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Open an interactive `pwsh` shell | macOS profile import | operator; visualization configured | HostHunter completes first; visualization prompt appears afterward | Fresh installed-profile journey | startup-order Pester test | covered focused and native profile |
| Open a noninteractive shell | profile import | automation/redirected | no visualization prompt, wait, or browser open | Native client automation journey | prompt-suppression tests | covered focused |
| Decline visualization startup | startup prompt | visualizer stopped | HostHunter remains ready; no visualizer mutation | Native client journey | prompt branch test | covered focused |
| Run `Start-HHVisualization` | PowerShell | visualizer stopped | containers become healthy and authenticated connection succeeds | Two-Compose-project journey | lifecycle/status integration | covered real-service |
| Decline a new mission | startup/cmdlet prompt | visualizer running; matching mission | current mission continues without a replacement activation | Progressive host browser journey | no-activation mission test | covered focused; visual rendering remains Visualizer-owned |
| Accept a new mission | startup/cmdlet prompt | visualizer running | warning, new run activation, old derived run pruned after acceptance | Lifecycle API journey | pending/recovery state tests | covered focused, including failed and lost-response recovery, plus real-service pruning |
| Decline browser open | start prompt | interactive | visualization stays running; no browser process is opened | Native client journey | browser prompt branch test | covered focused |
| Accept browser open | start prompt | interactive | loopback visualizer opens only after readiness | Native macOS journey | injected opener test | covered focused |
| Run `Stop-HHVisualization` | PowerShell | active mission | publishing pauses, visualizer stops, volumes remain | stop/restart service journey | pause-before-stop failure tests | covered real-service |
| Restart after explicit stop | PowerShell | paused matching mission | same mission resumes without replacing the mission | Cross-repo restart/browser journey | persistence/status integration | covered focused; visual rendering remains Visualizer-owned |
| Start with mismatched local/remote missions | PowerShell | divergent state | fail closed; do not publish or reset silently | Negative service journey | state-machine tests | covered focused |
| Configure a non-sibling visualizer repo | installer | valid path | versioned user config is written with restrictive permissions | Installed-profile journey | installer tests | covered focused and real-service |
| Supply an invalid/moved visualizer repo | installer/start | invalid path | finite actionable error; HostHunter remains intact | Negative native-client journey | config validation tests | covered focused |
| Collect target host details | `Get-TargetHostDetails` / onboarding | enabled or paused mission | encrypted local record precedes any typed delivery; public result remains truthful | Linux cmdlet and native-client journeys | collector/persistence tests | covered focused and native Linux target |
| Collect while explicitly paused | managed-host operation | paused mission | HostHunter evidence remains; no visualizer delivery is scheduled | Native-client paused journey | managed-operation/persistence tests | covered native and focused |
| Encounter an unexpected visualizer outage | managed-host operation | enabled mission | endpoint result remains truthful; pending delivery remains recoverable | Bounded producer failure/recovery journey | producer failure/recovery tests | covered focused |
| Accept Visualizer startup | startup prompt | interactive operator; Visualizer stopped | show the animated lifecycle, retain step logs, authenticate and return one terminal receipt | Native interactive journey | renderer and lifecycle orchestration tests | covered focused; service lifecycle covered |
| Start when the Visualizer is already running | startup prompt | interactive operator; active mission | skip the generic start question, continue the mission by default, offer a new mission with default No, and retain lifecycle logs | Native interactive journey | state-aware prompt tests | covered focused; service lifecycle covered |
| Encounter startup failure after accepting | startup prompt | interactive operator; Docker, health, auth or contract failure | preserve completed step logs, mark the failing step, warn that HostHunter remains ready, restore the cursor and return to the shell | Negative native journey | renderer failure and prompt isolation tests | covered focused |
| Start visualization non-interactively | `Start-HHVisualization` | script/CI | no animation or prompts; emit the ordinary terminal receipt or terminating error | Container command journey | suppression tests | covered focused |

Every `missing` or `partial` row is an implementation task. The final action
matrix must contain only `covered`, an explicit user-approved deferral, or a
concrete blocker before either repository's canonical full gate begins.

The bounded installed-profile macOS journey now passes in an isolated runtime
and disposable SSH fixture. During qualification it exposed three concrete
defects: a generated worker-command continuation, cleanup with an empty target
name, and a remote collector collision between `$isWindows` and PowerShell's
read-only `$IsWindows` automatic variable. Each defect received a focused
regression check before the journey continued. The final receipt proves a fresh
installed-profile load, all 12 framework commands, key-first and stored-password
onboarding, invisible stored-password execution, audit readback, controller
restart persistence, key conversion, and credential purge. Every isolated
container, network, and volume was removed without touching the operator's
running HostHunter or Visualizer projects.

## Verification record

- Native client lifecycle and configuration contract: 26/26 assertions passed
  in 1.22 seconds. Pester's optional CI XML export then failed because the
  source mount is read-only; the test assertions themselves were green and the
  suite was not rerun.
- Host-details and mission schema contract: 14/14 passed in the focused
  container lane.
- SQLite provider/persistence: 31/31 passed; host-details persistence: 1/1
  passed against committed migrations.
- Visualizer API/summary/demo unit tests: 26/26 passed; PostgreSQL integration:
  3/3 passed; static/typecheck passed with existing non-fatal Biome warnings.
- Managed-host AST boundary passes with six host-facing operations. No public
  host-details code contains a transport primitive.
- Native client lifecycle contract: 33/33 passed in 1.76 seconds. Mission
  lifecycle plus managed-host boundary: 17/17 passed in 4.49 seconds.
- Host-details collector regression: 14/14 passed in 0.89 seconds. Final native
  installed-profile journey status: passed, with 12 unique framework commands.
- The authoritative Phase 1 schemas, OpenAPI, examples, and package exports are
  byte-checked by Visualizer governance. `process_event_schema_version` is
  explicitly null and no process-event ingestion route was introduced.

## Prune classification

| Candidate | Classification | Evidence | Action |
| --- | --- | --- | --- |
| `Start-Mission` public framework command | removed | User selected `Start-HHVisualization`; current source/package/test surface contains no command | Replaced with client-local lifecycle command |
| `HH_RUNTIME_ACTIVATION_ID` controller-start reset | removed | Controller startup now only imports the module and waits | No automatic reset remains |
| Hard-coded sibling visualizer token discovery | removed | Installer/config supplies an explicit path and token source | Versioned client configuration is authoritative |
| CIM collector and `Get-TargetHostDetails` | active | Confirmed contract and existing focused tests | Retain and finish proof |
| Authenticated mission/observation persistence | active, evolved without schema change | A null authenticated current mission represents paused publishing; retained mission rows support resume and reconciliation | Preserve migration 0003; no unnecessary lifecycle migration |
| Typed visualizer producer adapter | active, requires status support | Needed for authenticated connection and host delivery | Retain PUT behavior and add bounded GET status |

## Test ledger

Tests are developed before or with each behavior slice. Focused Pester/API
tests run after each slice. Full container gates wait until all acceptance and
user-action rows are reconciled and the test-readiness preflight is complete.

## Parallel work

Parallel agents are not used because the current execution policy prohibits
spawning them without an explicit user request. The main agent owns both dirty
worktree integration and final validation.
