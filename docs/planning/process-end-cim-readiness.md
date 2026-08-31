# Process End CIM Readiness

Status: **READY — confirmed by the 2026-08-31 request to add the separately
versioned Windows process-end definition.**

## Shared understanding

- Add `process.end/1.0.0` as the canonical ECS-aligned normalization of Windows
  Security Event 4689 version 0.
- Require the observed PID, executable path, derived executable name, end time,
  unsigned 32-bit exit status, and terminating subject principal.
- Use `event.type: [end]`, `event.action: process-ended`,
  `event.dataset: hosthunter.process_end`, and set `process.end` equal to the
  source event timestamp.
- Preserve the numeric exit status without interpreting application-specific
  success or failure. Do not manufacture `event.outcome`.
- Reuse `process.entity_id` only when the process can be correlated to a
  verified process-start instance. A 4689 PID alone is not stable identity.
- Register the schema for HostHunter validation and the Visualizer's existing
  authenticated immutable event ingest. Any derived activity/lifecycle
  projection remains rebuildable and never mutates the accepted document.

## Authoritative constraints checked 2026-08-31

- Microsoft documents Event 4689 as version 0 with Subject SID, account name,
  account domain, logon ID, process ID, process name, and exit status.
- ECS defines `event.type: end`, `process.end` as the process termination time,
  and `process.exit_code` as the termination exit code.
- Windows exit status is application-specific, so the canonical record does
  not infer `event.outcome` from it.

Sources:

- <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4689>
- <https://www.elastic.co/docs/reference/ecs/ecs-process>
- <https://www.elastic.co/guide/en/ecs/current/ecs-event.html>

## Data and rollout

This is an additive registry change. The Visualizer already stores generic
forensic records immutably in PostgreSQL, so no database migration or
destructive rewrite is needed. Existing records and process-start projections
remain compatible. Rollback removes producer/consumer registration before any
producer relies on the new capability; immutable records already accepted are
not deleted.

The existing mixed `process-lifecycle-event` schema remains removed. It is not
restored because it used superseded identity and integrity semantics.

## Non-goals

- The schema-only slice added no cmdlet; the confirmed framework slice adds
  `Get-TargetProcessEndEvents` as the seventeenth framework cmdlet.
- No polling, background collection, retry loop, or managed-host connection.
- No new standalone timeline, route, or UI control. Existing generic activity
  projection may represent the registered event and disclose its correlation.
- No Sysmon Event 5 contract in this version.
- No full coverage, release build, image scan, or live-Windows qualification.

## Acceptance and test ledger

| Requirement | Implementation | Focused evidence | Status |
|---|---|---|---|
| Canonical 4689 v0 record | Mirrored schema, fixture, and normative documentation | JSON Schema positive and negative vectors | verified |
| Stable identity and truthful correlation | Generic source UUID plus optional verified `process.entity_id` | Fixture identity and negative bare-PID assertions | verified |
| Producer validation | HostHunter packaged schema registry | Focused Pester schema/capability tests | verified |
| Consumer acceptance | Visualizer registry, OpenAPI enum, immutable ingest, and disclosed lifecycle projection | Focused Vitest registry, route, and persistence tests | verified |
| Capability compatibility | Accept shared `kind: event` and `kind: state` values | Focused producer-status compatibility test | verified |
| Mirror integrity | Both `CIM_Specification` trees match exactly | `diff -qr` | verified |

## Failure handling and security

Invalid versions, missing required fields, encoded native placeholders,
undeclared fields, and mismatched event semantics fail closed before
persistence. Full command lines are not part of Event 4689 and are never copied
from a separate start event into the termination record. Existing authenticated
ingest, exact-byte digest, idempotency, immutable storage, and record-before-
delivery rules remain unchanged.

## Parallel work

No new parallel workers are used. The schema and documentation must be mirrored
byte-for-byte, the change is small, and current delegation policy does not
authorize new subagents for this task.
