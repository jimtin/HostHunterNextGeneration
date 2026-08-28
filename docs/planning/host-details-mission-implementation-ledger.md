# Host details and mission implementation ledger

Status: **SUPERSEDED FOR LIFECYCLE BEHAVIOR**

`docs/planning/visualization-lifecycle-implementation-ledger.md` replaces every
`Start-Mission` row below. The retained historical rows are implementation
history only. The supported controller surface is `Get-TargetHostDetails`; the
supported lifecycle surface is client-local `Start-HHVisualization` and
`Stop-HHVisualization`.

Status: **IMPLEMENTED; focused verification green** (2026-08-28)

## Readiness note

The operator needs two additional native PowerShell actions: start/reset a
visualizer mission, and collect a fresh, truthful host inventory for one or more
saved targets. HostHunter already has the correct managed-host gateway,
authenticated SQLite boundary, encrypted evidence format, Docker runtime, and
the visualizer's versioned `PUT` contracts. The implementation extends those
patterns; it does not add another transport, collector service, queue, or event
log pipeline.

The rejected naive design is to call `Invoke-HHCommand`, parse display output,
and post it directly. That would duplicate transport logic, lose the semantic
operation label, risk exposing native machine identity in audit output, and
make delivery failure look like collection failure. Instead,
`Get-TargetHostDetails` crosses `Invoke-HHManagedHostOperation` exactly once,
the engine owns a fixed inventory script, local authenticated storage commits
before one bounded producer attempt, and delivery state remains independent.

The schema rollout is expand-only migration 0003. Existing target, audit,
credential, and configuration formats remain readable. Rollback to older code
is not supported after migration 0003; this testing-stage repository requires a
fresh data volume for binary rollback. Visualizer payloads are capped by its
committed 256 KiB contract. Producer calls use the visualizer's committed
write-only bearer token, exact-body SHA-256, idempotency key, and private Docker
network.

Failure behavior is fixed: partial remote fields are valid; a failed refresh
does not erase the last good observation; visualizer downtime leaves one local
pending delivery and never fails controller startup or starts a retry loop.
`Start-Mission -WhatIf` performs no persistence or network mutation. Raw native
machine identifiers are never returned, logged, persisted, or sent.

## Acceptance and test ledger

| Requirement / action | Implementation | Focused evidence | Status |
|---|---|---|---|
| Manual `Start-Mission` | Public adapter plus private mission coordinator | Unit delegation, SQLite integration, producer contract | verified |
| `Start-Mission -WhatIf` | `SupportsShouldProcess` before mutation | Public contract unit test | verified |
| Genuine controller activation starts one mission | Activation ID persisted idempotently by controller startup | Runtime lifecycle integration | implemented; runtime qualification pending |
| Reusing a running controller does not reset visualization | Activation ID created only by an actual start/rebuild | Native macOS client journey | implemented; native qualification pending |
| Visualizer unavailable does not block HostHunter | Local-first commit, one bounded send, pending state | Producer failure integration | verified |
| `Get-TargetHostDetails` without `-Name` refreshes all active targets | One engine call, 1-8 target selection | Linux fixture E2E | implemented; final journey pending |
| `Get-TargetHostDetails -Name` refreshes selected targets | Exact saved-target selection | Unit and Linux fixture E2E | implemented; final journey pending |
| Partial metadata is truthful and accepted | Per-field status/source, no invented values | Collector unit fixtures | verified |
| Stable opaque endpoint ID never exposes native identifier | Controller-side HMAC over remote digest | Security and persistence tests | verified |
| `Set-HHTarget` records initial host details | Validate target engine path collects after authentication | Linux and bounded Windows journeys | implemented; final journey pending |
| All host traffic uses the single managed-host engine | Closed operation plus AST boundary guard | Managed-host contract test | verified |
| Local evidence is encrypted and authenticated before delivery | Migration 0003 repository and external anchor | Migration, tamper, plaintext sweep | verified |
| Established visualizer contract remains byte-compatible | Mirrored OpenAPI/schemas/examples | Cross-repo semantic comparison | verified |
| No event logs or continuous telemetry | No process/event routes, phases, jobs, or collectors | Deleted/negative surface sweep | verified |
| Canonical verifier invokes 13 unique cmdlets once | One ordered journey, no retries/shards/fanout | `verify-cmdlets.sh` receipt | implemented; latest bounded run 11/13 before final allowlist fix; no rerun loop |

## User-action coverage matrix

| User action | Surface | Persona | Data state | Expected behavior | E2E evidence | Unit/integration evidence | Status |
|---|---|---|---|---|---|---|---|
| Start a mission manually | PowerShell `Start-Mission` | trusted operator | visualizer online/offline | local mission is current; online sends reset, offline remains terminally recorded | cmdlet journey | mission repository and producer tests | focused verified |
| Preview a mission reset | PowerShell `Start-Mission -WhatIf` | trusted operator | any | no local or remote mutation | cmdlet journey | public adapter test | verified |
| Refresh all target details | PowerShell `Get-TargetHostDetails` | trusted operator | 1-8 active targets | one fresh result per target; partial is valid | Linux fixture journey | collector/engine/repository tests | focused verified; E2E pending |
| Refresh selected target details | PowerShell `Get-TargetHostDetails -Name` | trusted operator | named saved targets | only selected targets refresh | Linux fixture journey | target selection tests | focused verified; E2E pending |
| Onboard a target | PowerShell `Set-HHTarget` | trusted operator | valid SSH endpoint | target remains saved and initial details are recorded when collection succeeds | Linux and Windows journeys | engine integration | implemented; E2E pending |
| Load another native shell | macOS PowerShell profile | trusted operator | controller already running | proxies refresh; mission is not reset | native macOS journey | runtime lifecycle test | implemented; qualification pending |

## Verification record

- Production-derived package build passed and exported exactly 13 cmdlets.
- Managed-host/details focused unit contracts passed 23/23; the partial-payload
  regression passed in the subsequent 8/8 focused run.
- Docker v3 anchor and fresh migration/encrypted observation proof passed 17/17.
- The visualizer OpenAPI and Markdown contracts match byte-for-byte; JSON
  schemas and examples match semantically after canonical JSON formatting.
- The single bounded verifier created one terminal 13-row receipt. Eleven rows
  passed. Its two details rows exposed one missing audit-operation allowlist;
  that root cause is fixed and covered by a focused allowlist test. The verifier
  was deliberately not looped again; the next exact-SHA qualification owns the
  final 13-row runtime verdict.

## Parallel work

Parallel agents are not used. The current execution policy prohibits spawning
them unless the user explicitly asks, and the persistence, engine, runtime, and
contract edits are tightly coupled. The primary agent owns integration and all
validation.

## Explicit non-goals

- Windows Security events 4688/4689, process telemetry, event-log ingestion.
- Polling, subscriptions, background collection, automatic retry loops.
- A second managed-host transport or raw SSH from public cmdlets.
- Direct HostHunter access to visualizer PostgreSQL.
