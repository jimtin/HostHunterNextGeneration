# HostHunter Visualizer Integration Specification

Status: **CONFIRMED REQUIREMENTS - IMPLEMENTATION MUST BE RECONCILED**
Implementation readiness: **CONDITIONAL**
Date: 2026-08-28
Owner: HostHunter

## 1. Purpose

This document is the source of truth for how HostHunter must start, stop, and
publish evidence to the separate HostHunter Visualizer. It replaces lifecycle
behavior inferred from implementation ledgers or partially completed code.

The integration must preserve HostHunter's existing automatic PowerShell
startup experience. Visualization is optional and is controlled separately by
the operator.

## 2. Sources Reviewed

| Source | Role | Status |
| --- | --- | --- |
| Operator decisions in the HostHunter visualizer conversation | Product requirements | Reviewed |
| `CIM_Specification` host-details contract | Host metadata semantics | Reviewed |
| Existing HostHunter runtime, client, persistence, and managed-host boundaries | Current architecture | Reviewed; implementation is not acceptance evidence |
| HostHunter Visualizer producer API and contract package | Consumer boundary | Reviewed; must be reconciled to this specification |
| Representative production process-start and process-stop payloads | Golden-fixture evidence | Not yet supplied |

## 3. Goal

From a normal macOS PowerShell session, an operator must be able to keep the
existing HostHunter startup intact and optionally start a local Dockerized
visualizer. HostHunter must prove an authenticated compatible connection,
continue or deliberately replace the current mission, and publish explicitly
collected host metadata and later process lifecycle events without losing its
own evidence when the visualizer is stopped or unavailable.

## 4. Non-Goals

- The visualizer does not replace HostHunter's evidence store or audit trail.
- The visualizer never connects directly to managed endpoints.
- HostHunter does not expose a public arbitrary-log forwarding cmdlet.
- HostHunter does not infer domain membership from process events, hostnames,
  DNS suffixes, IP addresses, or other indirect evidence.
- Stopping visualization does not delete a mission or its HostHunter evidence.
- Restarting HostHunter does not automatically start a new mission.
- The browser does not issue managed-host commands.
- Phase 1 does not require process trees or timelines; their data contract is
  frozen now for a later phase.

## 5. Actors And Boundaries

| Actor | Responsibility | Prohibited Access |
| --- | --- | --- |
| macOS operator | Starts HostHunter, chooses visualization, chooses mission lifecycle | Does not handle producer secrets manually |
| `HostHunter.Client` | Presents prompts and canonical lifecycle commands | Does not contact managed hosts directly |
| HostHunter controller | Collects, records, validates, and publishes CIM data | Cannot read visualizer operator sessions or PostgreSQL |
| Managed endpoint | Supplies explicitly observed host and process facts | Never contacted by the visualizer |
| HostHunter Visualizer producer API | Accepts bounded versioned writes and exposes compatibility status | Cannot read HostHunter credentials, SQLite, keys, or audit anchors |

## 6. Required Operator Workflow

### 6.1 PowerShell startup

1. Starting a PowerShell session continues to trigger the existing HostHunter
    startup and animation without interruption.
2. After HostHunter startup finishes, and only in an interactive session, the
    client presents a separate prompt to start visualization.
3. The start-visualization prompt defaults to **No**.
4. Declining the prompt leaves HostHunter fully usable and performs no
    visualizer, mission, or publishing mutation.

### 6.2 `Start-HHVisualization`

`Start-HHVisualization` is the canonical public lifecycle command.

When invoked it must:

1. Resolve both repository locations from explicit client configuration. It
    must not depend on sibling-folder discovery.
2. Start or reuse the visualizer's Docker Compose project.
3. Start or reuse a HostHunter controller configured for the private producer
    network.
4. call the authenticated, non-mutating producer status endpoint;
5. verify service name, API version, required schema versions, persistence
    readiness, and active mission identity;
6. if no active mission exists, create one and wait for an accepted receipt;
7. if an active mission exists, ask whether to start a new mission, defaulting
    to **No**;
8. when the answer is No, continue the same mission without pruning it;
9. when the answer is Yes or `-NewMission` is supplied, activate a new mission
    and consider it current only after the visualizer accepts it;
10. report the visualizer URL, authenticated connection state, mission ID,
    whether the mission was created or continued, and pending delivery count;
11. offer to open the browser, defaulting to **Yes**.

`-Open:$false`, `-NewMission`, non-interactive operation, `-Confirm`, and
`-WhatIf` must have deterministic testable behavior. `-WhatIf` performs no
container, mission, publishing, or browser mutation.

### 6.3 `Stop-HHVisualization`

`Stop-HHVisualization` is the canonical public stop command. It must:

1. pause HostHunter publishing first;
2. stop only the visualizer application and database containers owned by the
    configured visualizer Compose project;
3. preserve the active mission, PostgreSQL volume, HostHunter evidence, and
    pending delivery state;
4. be idempotent when visualization is already stopped;
5. return a receipt that distinguishes `paused`, `already-stopped`, and
    `failed` states.

Stopping visualization means pausing. It is not mission completion, deletion,
or reset.

### 6.4 Restart and update safety

- An ordinary visualizer, PostgreSQL, controller, or framework restart resumes
  the current mission.
- Updating either repository must not silently create a new mission.
- A failed new-mission activation leaves the previous mission current.
- An accepted activation whose response is lost is reconciled by comparing the
  remote active mission with authenticated pending local state.
- An unknown remote mission mismatch fails closed and requires operator action.

## 7. Collection And Publishing Behavior

### 7.1 Host metadata

- `Set-HHTarget` collects a first host-details observation after authenticated
  endpoint validation. Missing optional fields do not invalidate the target.
- `Get-TargetHostDetails` performs a fresh collection for one to eight named
  targets, or every active target when no name is supplied.
- HostHunter assigns and preserves an opaque endpoint ID. Hostname and IP
  address are never stable identity by themselves.
- Domain/workgroup, OS, hardware, network, boot, time-zone, provenance, and
  field-result values follow the CIM specification.
- Missing membership is `unknown`; it is never guessed.

### 7.2 Process lifecycle events

- Phase 2 accepts only the versioned process-start/process-stop structure in
  `CIM_Specification`; it is not an unrestricted general-log endpoint.
- HostHunter preserves provider, channel, record ID, endpoint ID, event time,
  collection time, PID, available process identity, available parent identity,
  and available user/exit information.
- Absent values remain absent with explicit provenance where available.
- PID alone is not a stable process identity and must not be presented as one.
- Host metadata, including domain membership, remains an independent explicit
  observation and is never derived from process events.

### 7.3 Record-before-delivery

For every mission, host observation, and process event HostHunter must:

1. validate the document against the pinned local schema;
2. record the exact immutable payload, digest, identity, and delivery state in
    authenticated local persistence;
3. make one bounded API attempt when publishing is enabled;
4. record the receipt or truthful failure state;
5. retain the original evidence when the visualizer is unavailable;
6. replay only the same event ID and exact bytes through an explicit bounded
    synchronization step.

There is no recursive retry or unbounded background loop inside a collection
command.

## 8. Source-Of-Truth Model

| Source | Classification | Authority |
| --- | --- | --- |
| Managed-host result plus HostHunter audit record | Original observation and audit evidence | Authoritative for what HostHunter observed |
| Authenticated HostHunter local store | Delivery and mission state | Authoritative producer recovery state |
| `CIM_Specification` schemas | Expected wire state | Authoritative payload shape |
| Visualizer activation/ingest receipt | Consumer acceptance evidence | Authoritative only for API acceptance |
| Visualizer PostgreSQL and projections | Derived state | Rebuildable; never replaces HostHunter evidence |

## 9. Numbered Requirements

| ID | Requirement | Source Evidence | Type | Phase | Acceptance Criteria | Proof | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| HH-R-001 | Preserve automatic HostHunter startup before any visualizer prompt | Operator decisions + CIM contract | UX | 1 | Existing startup completes unchanged; separate prompt appears afterward | Native-client E2E | confirmed |
| HH-R-002 | Default the startup visualizer prompt to No | Operator decisions + CIM contract | UX | 1 | Empty response causes no visualizer mutation | Unit + native-client E2E | confirmed |
| HH-R-003 | Provide `Start-HHVisualization` | Operator decisions + CIM contract | Functional | 1 | Command is installed, discoverable, idempotent, and returns a receipt | Contract + E2E | confirmed |
| HH-R-004 | Provide `Stop-HHVisualization` | Operator decisions + CIM contract | Functional | 1 | Command pauses publishing and stops only owned visualizer containers | Integration + E2E | confirmed |
| HH-R-005 | Configure both repository paths explicitly | Operator decisions + CIM contract | Operational | 1 | Installer persists validated absolute paths; moved paths fail clearly | Unit + install journey | confirmed |
| HH-R-006 | Prove authenticated producer compatibility | Operator decisions + CIM contract | Security | 1 | Start succeeds only after bounded authenticated status and schema checks | API integration | confirmed |
| HH-R-007 | Continue an active mission by default | Operator decisions + CIM contract | Functional | 1 | New-mission prompt defaults No and active ID is unchanged | Lifecycle integration | confirmed |
| HH-R-008 | Create a new mission only by explicit choice | Operator decisions + CIM contract | Functional | 1 | Yes/`-NewMission` activates exactly one new ID after receipt | Lifecycle integration | confirmed |
| HH-R-009 | Preserve the previous mission on failed activation | Operator decisions + CIM contract | Data | 1 | Failure leaves previous active run and local state unchanged | Fault-injection integration | confirmed |
| HH-R-010 | Treat stop as pause | Operator decisions + CIM contract | Functional | 1 | Mission, database volume, evidence, and pending items survive stop/start | Compose integration | confirmed |
| HH-R-011 | Offer browser opening with default Yes | Operator decisions + CIM contract | UX | 1 | Interactive accepted/default response opens loopback URL once | Native-client E2E | confirmed |
| HH-R-012 | Collect explicit host metadata | Operator decisions + CIM contract | Data | 1 | Documents conform to host-details schema, including explicit unknowns | Windows/Linux fixtures + schema validation | confirmed |
| HH-R-013 | Never infer membership | Operator decisions + CIM contract | Data | 1 | Missing domain/workgroup renders as unknown in payload | Unit + golden fixtures | confirmed |
| HH-R-014 | Record before delivery | Operator decisions + CIM contract | Security | 1 | Local immutable record exists before any API call | Persistence integration | confirmed |
| HH-R-015 | Preserve data during visualizer outage | Operator decisions + CIM contract | Operational | 1 | Failed send retains evidence and pending immutable payload | Fault-injection integration | confirmed |
| HH-R-016 | Replay idempotently and boundedly | Operator decisions + CIM contract | Integration | 1 | Same ID/bytes replay; conflicts fail; no unbounded retry | API + persistence integration | confirmed |
| HH-R-017 | Collect versioned process start/stop events | Operator decisions + CIM contract | Data | 2 | Events conform to the process lifecycle schema | Provider golden fixtures | confirmed |
| HH-R-018 | Keep process events independent of host membership | Operator decisions + CIM contract | Data | 2 | No process field populates or changes membership | Projection integration | confirmed |
| HH-R-019 | Keep managed-host transport unchanged | Operator decisions + CIM contract | Security | 1 | Collections use the sole managed-host operation/SSH boundary | Static contract + integration | confirmed |
| HH-R-020 | Keep producer credential narrowly scoped | Operator decisions + CIM contract | Security | 1 | Credential can read status and write CIM resources only | Authorization integration | confirmed |

## 10. Phase Plan

### Phase 0 - Contract reconciliation

- Freeze the mirrored CIM files and golden fixtures in both repositories.
- Compare current uncommitted implementation against this specification.
- Remove or revise code that is not justified by a requirement.
- Confirm the established repository test architecture remains unchanged.

### Phase 1 - Host visualization integration

- Canonical lifecycle commands and prompts.
- Authenticated status and mission lifecycle.
- Host metadata collection, local persistence, delivery, pause, and replay.
- Real macOS client, Linux target, visualizer, and PostgreSQL journey.

### Phase 2 - Process investigation data

- Process start/stop collection and narrow API delivery.
- Provider-specific fixtures and correlation evidence.
- No UI inference beyond disclosed correlation confidence.

### Phase 3 - Operational hardening

- Bounded performance qualification, recovery drills, upgrades, schema
  compatibility, support diagnostics, and release documentation.

## 11. Technical Validation Register

| Question | Why It Matters | Validation | Phase | Status |
| --- | --- | --- | --- | --- |
| Which Windows and Linux provider fields are reliably available as a standard user? | Controls truthful optional fields | Real endpoint fixtures | 0 | open |
| Which provider supplies a stable process instance ID and parent instance ID? | Controls correlation quality | Sysmon/Security/Linux fixture comparison | 2 | open |
| What bounded replay size meets realistic outages without blocking the shell? | Controls operability | Load and fault benchmark | 1 | open |
| Does every current implementation path conform to the frozen schemas? | Prevents implementation-led contract drift | Contract test inventory | 0 | open |

There are no unresolved Phase 1 client questions. The operator decisions in
this specification are confirmed.

## 12. Assumptions And Risks

Assumptions:

- Phase 1 is one local operator on macOS with Docker Desktop and PowerShell 7.
- Both repositories are local and their absolute paths can be configured.
- Managed endpoints continue to use the supported PowerShell 7/OpenSSH path.
- Phase 2 provider fixtures will be supplied before process collection is
  treated as implementation-ready.

| Risk | Impact | Mitigation | Owner |
| --- | --- | --- | --- |
| Producer and consumer schemas drift | Silent loss or rejection | Byte-compatible mirrored files and golden contract tests | Both repos |
| Failed activation erases history | Loss of operator context | One accepted transaction before pruning; fault proof | Visualizer |
| Membership is guessed | Misleading node/domain state | Schema invariants and negative projection tests | Both repos |
| Retry creates duplicate evidence | Incorrect timelines/counts | Immutable IDs, exact-byte digest, idempotent replay | Both repos |
| Feature code pressures the established test gate | Validation instability | Keep the collector unchanged; simplify and test feature modules | HostHunter |
| Producer secret leaks | Unauthorized writes | Docker secrets, scoped auth, redacted logs, gitleaks | Both repos |

## 13. Parallel Work

When implementation resumes, the main worker owns the shared behavior
contract, integration decisions, existing gate, security review, and final
proof. Independent workers may own disjoint areas: CIM fixtures/contract tests,
HostHunter lifecycle/persistence, and native-client journeys. No worker may
change the shared testing architecture or the same files concurrently. If
parallel workers are unavailable, use the same boundaries sequentially.

## 14. Testing And Proof

- Preserve the repository's existing canonical containerized test architecture.
- Add focused unit tests beside each changed function or module.
- Cover mission activation, pause, restart, response-loss reconciliation,
  mismatch failure, outage retention, replay, and digest conflict in integration.
- Cover every macOS prompt, default, switch, error, browser action, and
  non-interactive path through the native client journey.
- Validate host and process structures with golden Windows/Linux fixtures.
- Maintain at least 90% statements, branches, functions, and lines without
  changing the collector to accommodate feature code.
- Run the security threat model, dependency/image scans, and gitleaks before
  any push. Full exact-SHA proof remains owned by the standalone local gate.

## 15. Security And Privacy

- Secrets are Docker secrets or protected local configuration and are never
  printed in receipts or logs.
- Browser URL configuration is an uncredentialed loopback HTTP origin for the
  local Phase 1 deployment.
- Host-controlled strings are bounded and rendered as inert text.
- Raw native endpoint identifiers used for stable-ID derivation are protected
  and never sent as ordinary API fields.
- Producer and operator credentials are separate.

## 16. Definition Of Done

The HostHunter integration is complete only when every confirmed requirement
is implemented against the unchanged canonical test architecture, all focused
and full container gates are green, an actual macOS PowerShell journey proves
start/continue/new/pause/resume, a real host observation appears in the UI,
outage recovery is demonstrated, and both repositories contain byte-compatible
CIM contracts and golden fixtures.

## 17. Production AI Handoff

Before implementation resumes:

1. use `clarify-before-build` to confirm this shared understanding;
2. use `feature-design-preflight` to reconcile the lifecycle, persistence, and
    producer-network boundaries;
3. use `user-action-coverage-review` before changing client prompts or UI;
4. use `security-threat-model` for producer credentials and Docker networks;
5. use `test-readiness-preflight` before the established full local gate.

## 18. Decision Log

| Date | Decision | Owner | Source |
| --- | --- | --- | --- |
| 2026-08-28 | Visualization prompt is separate and defaults No | Operator | Conversation |
| 2026-08-28 | Existing mission continues by default | Operator | Conversation |
| 2026-08-28 | Stop means pause and preserves the mission | Operator | Conversation |
| 2026-08-28 | Canonical commands are `Start-HHVisualization` and `Stop-HHVisualization` | Operator | Conversation |
| 2026-08-28 | Repository paths are explicitly configurable | Operator | Conversation |
| 2026-08-28 | Startup proves connection and then offers the browser | Operator | Conversation |
