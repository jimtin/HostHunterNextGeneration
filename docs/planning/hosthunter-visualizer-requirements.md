# HostHunter - Dockerized Visualizer Requirements

Status: DRAFT - not confirmed
Implementation readiness: CONDITIONAL
Phase 1 client decisions: CIM V1 NORMATIVE; STANDALONE PUBLIC REPOSITORY REQUIRED
Date: 2026-08-28
Owner: James Hinton
Planning scope: requirements and implementation handoff only

> This document does not authorize code, schema, container, dependency,
> deployment, commit, push, or live-system changes. HostHunter and the new
> visualizer remain separate product surfaces. Implementation must wait for
> explicit confirmation of this document and the later Shared Understanding
> Contract.

## 1. Executive Summary

- Build a separate, localhost-only Dockerized visualizer for HostHunter.
- Develop it in its own public GitHub repository, independently versioned from
  HostHunter; public source and synthetic fixtures must never make runtime host
  inventory or credentials public.
- Represent individual computers as the top-level investigation nodes.
- Make Phase 1 a deliberately small host map: one node per registered computer
  containing truthful fundamental host details and collection freshness.
- Let an operator select a host once to see its full available metadata without
  leaving the map.
- Have HostHunter collect explicit computer and domain/workgroup metadata when
  it establishes an authenticated endpoint connection. Domain membership must
  never be inferred from process events.
- Receive exactly the ECS-compliant observation defined by
  `CIM_Specification`; do not create a parallel visualizer field model.
- Populate the display progressively as HostHunter registers computers and
  sends validated host-status and metadata observations.
- Use PostgreSQL as the Phase 1 durable visualizer system of record, running as
  a private service in the local Docker Compose stack.
- Use Cytoscape.js for the Phase 1 host map. Retain Apache ECharts as the
  selected Phase 2 process-duration timeline library, but do not load or bundle
  it into the host-only Phase 1 surface.
- Define the producer API contract-first with OpenAPI 3.1/JSON Schema 2020-12
  and connect HostHunter through a dedicated Docker-private producer network;
  keep PostgreSQL on its separate private database network.
- Start a fresh empty investigation for each new HostHunter collection run;
  ordinary application/database restarts resume the current investigation.
- Automatically delete prior visualizer-derived sessions after the new run is
  established, while preserving HostHunter's original evidence and audit
  records.
- Keep the data model, API, projection engine, and renderer modular so later
  releases can add Process Start/Stop events, process trees/timelines, logons,
  permissions, users, groups, services, files, network relationships, and
  deeper domain analysis.

## 2. Source Materials Reviewed

| Source | Type | Reviewed | Notes |
| --- | --- | --- | --- |
| Current user requirements and numbered answers | Conversation | Yes | Primary source for Phase 1 product decisions |
| Archived `Build forensic timeline container` task | Prior planning task | Yes | Established offline timeline and evidence-preservation direction |
| `Research Rust event log normalizer` task | Prior planning task | Yes | Established progressive HostHunter-to-viewer and node-graph direction |
| HostHunter repository `AGENTS.md` | Repository contract | Yes | Current supported product is exactly eleven cmdlets with local container proof |
| HostHunter `README.md` | Repository documentation | Yes | Current Forensics/parser/API subsystem is intentionally absent |
| HostHunter simplification plan and ledger | Repository planning evidence | Yes | Reintroducing the removed coupled subsystem is not an accepted shortcut |
| Historical commit `b7e53b8` planning documents | Git history | Yes | Useful prior design evidence; not current approved architecture |
| Follow-up PostgreSQL decision | Conversation | Yes | Confirms PostgreSQL, rather than embedded SQLite, as the Phase 1 visualizer database |
| Follow-up session lifecycle and retention decisions | Conversation | Yes | Confirms collection-run reset, restart resume, and automatic deletion of prior derived visualizer sessions |
| Follow-up visualization and private producer-network decisions | Conversation | Yes | Confirms Cytoscape.js for graphs, Apache ECharts for timelines, shared application state, and a Docker-private HostHunter API path |
| Phase 1 host-only visualization decision | Conversation | Yes | Re-scopes the first visualizer to fundamental host metadata nodes; process telemetry/tree/timeline moves to Phase 2 |
| Phase 1 target-enrichment clarification | Conversation | Yes | Includes the previously optional target-machine facts such as OS edition, hardware, addresses, boot time, time zone, and directory role; excludes expanded operational telemetry |
| `CIM_Specification/README.md` | Confirmed product contract | Yes | Declares contract `1.0.0-draft.1`, ECS `9.5.0`, public `Get-TargetHostDetails`, first-onboarding collection, immutable record-before-delivery, and no in-command retry loop |
| `CIM_Specification/host-details-ecs-v1.md` | Normative semantic contract | Yes | Defines canonical ECS/`hosthunter.*` fields, missing-data semantics, identity, collection sources, producer behavior, security, and compatibility |
| `CIM_Specification/schemas/host-details-observation.v1.schema.json` | Normative payload schema | Yes | Defines the JSON Schema 2020-12 observation shape, bounds, allowed values, and conditional invariants |
| `CIM_Specification/openapi/host-details-ingest.v1.openapi.yaml` | Normative HTTP contract | Yes | Defines the private authenticated idempotent `PUT` ingest route, 256 KiB body limit, digest header, receipts, and errors |
| `CIM_Specification/examples/windows-complete.v1.json` and `examples/linux-partial.v1.json` | Synthetic golden fixtures | Yes | Provide non-production complete/partial examples for both repositories |
| Current public-repository decision | Conversation | Yes | Visualizer must be a separate Dockerized public GitHub repository |
| [PostgreSQL concurrency control](https://www.postgresql.org/docs/current/mvcc-intro.html) and [parallel query](https://www.postgresql.org/docs/current/parallel-query.html) documentation | Authoritative technical research | Yes | Supports the PostgreSQL feasibility direction; does not replace the required Phase 1 host benchmark or deferred Phase 2 process benchmark |
| [Cytoscape.js documentation](https://js.cytoscape.org/) | Authoritative technical research | Yes | Confirms directed/compound graph, layout, event, and interaction capabilities; exact version/layout extensions still require Phase 0 qualification |
| [Apache ECharts custom-series](https://echarts.apache.org/handbook/en/how-to/custom-series/) and [Canvas guidance](https://echarts.apache.org/handbook/en/best-practices/canvas-vs-svg/) | Authoritative technical research | Yes | Supports range-bar timelines and bounded Canvas rendering; exact version/modules still require Phase 0 qualification |
| [OpenAPI 3.1 specification](https://spec.openapis.org/oas/v3.1.0) and [PowerShell REST documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod) | Authoritative technical research | Yes | Supports a JSON Schema 2020-12 contract consumable by the PowerShell 7 HostHunter runtime |
| Representative Phase 1 host registrations and observations | Fixture/sample | No | Required before freezing the host producer/API schema |

## 3. Goal

Give one local HostHunter operator a truthful, progressively populated map of
the computers HostHunter has registered in the current collection run. Each
host is one stable node, and selecting it reveals the fundamental host metadata
that HostHunter explicitly observed.

The smallest useful proof must answer:

1. Which computers has HostHunter registered in this operator run?
2. Which domain or workgroup did each computer explicitly report, if known?
3. What hostname, platform, operating-system, architecture, network, and
    collection details were explicitly observed for each host?
4. Which values are current, stale, unavailable, or unknown?
5. When and by which HostHunter/schema version was the metadata observed?
6. Can the operator select one node and review every available Phase 1 host
    field without leaving the map?

## 4. Non-Goals

Phase 1 deliberately excludes:

- Process Start/Stop ingestion, process correlation, process trees, duration
  timelines, and Apache ECharts rendering; these move to Phase 2;
- raw EVTX upload or parsing inside the visualizer;
- a Sysmon-specific or Security-log-specific user interface;
- live endpoint control from the browser;
- browser buttons that collect, retry, cancel, delete, or change HostHunter;
- continuous endpoint heartbeat, availability, resource-performance, or health
  monitoring, connection-performance telemetry, failure counters, or retry
  scheduling;
- remote/network access or multiple investigators;
- a persistent case library, prior-session browser, or operator-facing case-ID
  workflow;
- Active Directory trust, group, user, permission, or attack-path analysis;
- inferred domain membership;
- cross-provider process merging when identity is uncertain;
- automated threat, anomaly, or maliciousness classification;
- AI analysis;
- cloud services, telemetry, runtime CDNs, or required internet access;
- modification or deletion of HostHunter source evidence and audit records.

## 5. Current State

HostHunter currently:

- runs a Linux PowerShell 7 controller in Docker;
- manages Linux and Windows PowerShell 7/OpenSSH endpoints;
- exposes exactly eleven public cmdlets;
- has one private managed-host gateway for endpoint operations;
- stores authenticated SQLite state and encrypted, tamper-evident evidence;
- has intentionally removed its former Forensics, parser, API, ECS, and outbox
  product surfaces;
- stores a target name, connection endpoint, host name, and validation data,
  but does not yet implement the confirmed target-host details contract;
- exports eleven cmdlets today. `CIM_Specification` confirms a future twelfth
  cmdlet, `Get-TargetHostDetails`, but explicitly states that implementation has
  not started;
- now contains the implementation-neutral CIM contract, schema, OpenAPI
  document, and synthetic Windows/Linux examples as untracked planning work.

The visualizer repository does not currently exist. It must be a separate
public application repository with an independently versioned runtime rather
than code embedded back into HostHunter's controller. The CIM OpenAPI defines
host-observation ingestion but does not yet define the separately required
collection-run create/activate transition; that companion contract must be
resolved in Phase 0 before persistence or pruning is implemented.

## 6. Proposed End State

### 6.1 Operator experience

- The visualizer opens directly into the active operator investigation.
- The empty state says it is waiting for HostHunter computer registrations.
- Each registered computer appears immediately as a stable node, even before
  optional host metadata is ready.
- Computers with the same explicitly reported domain are visibly grouped.
- Workgroup and unknown membership remain distinct, truthful states.
- Each node shows a compact identity/status summary. Selecting it once opens a
  host-details region containing every available Phase 1 field without
  navigating away from the map.
- Additional computers and host observations appear progressively
  without globally rearranging the operator's current view.

### 6.2 System behavior

- A small companion collection-run endpoint establishes the fresh active run
  before host observations arrive. Its exact schema is a Phase 0 addition to
  the shared contract because the current CIM OpenAPI does not define it.
- HostHunter sends one immutable ECS observation through the normative
  `PUT /api/v1/collection-runs/{collection_run_id}/host-observations/{event_id}`
  route after recording that observation locally. `Set-HHTarget` produces the
  onboarding observation and `Get-TargetHostDetails` produces fresh ones.
- The visualizer enforces the 262,144-byte limit before parsing, authenticates
  the write-only producer, verifies the exact-byte SHA-256 header, validates
  JSON Schema 2020-12 and semantic invariants, and checks both path/body IDs.
- One PostgreSQL transaction stores the immutable observation, its canonical
  digest/receipt, normalized field results, and the current-host projection.
  A byte-identical replay is harmless; an event-ID conflict never overwrites.
- `complete`, `partial`, and `unavailable` observations may become the current
  host projection. A `failed` observation is retained for audit/status but
  never replaces the last usable host snapshot.
- The visualizer derives a rebuildable host-node projection and domain,
  workgroup, operating-system, and status groupings.
- A bounded same-origin read API serves the active host list and selected-host
  details. Server-Sent Events announce only run/host/revision changes; the
  browser refetches the bounded record rather than receiving payloads in the
  update stream.
- Starting a new HostHunter collection run creates a fresh active derived
  session and empty graph. Ordinary visualizer or PostgreSQL restarts resume
  the current active session.
- After the new session has been established successfully, the visualizer
  automatically deletes all prior derived sessions and their dependent
  observations/projections. It never deletes or rewrites HostHunter's source
  evidence.
- Cytoscape.js renders the Phase 1 host map. Apache ECharts and process-ancestry
  rendering remain absent until the separately qualified Phase 2 process
  investigation.
- HostHunter sends the exact standard UTF-8 JSON defined by CIM contract
  `1.0.0-draft.1` / host schema `1.0.0` / ECS `9.5.0` through the private
  producer adapter. The contract does not expose PostgreSQL, browser APIs, or
  visualization-library models.

### 6.3 Proposed deployment boundary

The initial deployment should remain operationally small:

```text
Managed computers
    ^
    | SSH through HostHunter's existing managed-host boundary
    |
HostHunter controller container
    |
    | authenticated CIM host-details observations (max 256 KiB)
    | private hh-visualizer-producer Docker network
    v
HostHunter visualizer application container <--- browser via 127.0.0.1 only
    +-- versioned ingest/read API
    +-- schema validation and idempotency
    +-- host-node projection and groupings
    +-- shared investigation state and browser update stream
    +-- Cytoscape.js host map and host-details view
    |
    | private visualizer-db Docker network
    v
PostgreSQL database container
    +-- committed schema migrations
    +-- durable host observations, projections, and session state
    +-- dedicated persistent database volume

Producer network members: HostHunter controller and visualizer application only
Published address: visualizer application on 127.0.0.1 only
Database exposure: no PostgreSQL host port and no producer-network membership
```

The existing HostHunter runtime and new two-service visualizer remain separate
Compose projects. They share only the explicitly named external producer
network. The visualizer application also joins its own private database
network; PostgreSQL joins only that database network. API, persistence,
projection, notification, shared-state, and renderer code remain separate
modules with versioned internal boundaries.

### 6.4 Visualization and API boundaries

- Cytoscape.js owns the Phase 1 host-map rendering and graph-local interaction.
- A framework-neutral application state owns selected host, domain/workgroup,
  operating-system and status filters, focus, and host-detail visibility.
- The visible node stays compact: display hostname, membership badge,
  operating-system badge, collection status, and observation
  freshness. The selected-host details region holds the complete field set.
- PostgreSQL-backed APIs return only the active run's bounded host-node and
  selected-host records.
- A synchronized semantic host list/details view is the accessible source for
  keyboard and assistive-technology navigation; Canvas output is not the only
  interface.
- Cytoscape has an isolated error boundary so a render failure does not hide
  the semantic host list/details or application status.
- Apache ECharts is retained as the selected Phase 2 process-duration timeline
  library but is not installed, loaded, or bundled for the host-only Phase 1
  proof.
- The canonical producer contract is OpenAPI 3.1 with JSON Schema 2020-12,
  specifically the normative files under `CIM_Specification`. Phase 1 receives
  its immutable ECS host-observation document and adds only the companion
  collection-run lifecycle plus bounded browser read/update contracts.
- Both repositories consume the same schemas, examples, and golden fixtures.
  HostHunter validates before sending and the visualizer validates again before
  activation.
- The HostHunter integration is a narrow private host-metadata adapter invoked
  by `Set-HHTarget` and the confirmed future public
  `Get-TargetHostDetails` cmdlet. Implementing that twelfth cmdlet requires an
  explicit HostHunter repository-contract change; it must not restore the
  removed general API/Forensics/outbox subsystem.
- If the visualizer is unavailable, HostHunter preserves its original evidence
  and records delivery failure; later replay uses the same stable identities,
  observation digest, and idempotency key.

## 7. Users And Actors

| Actor | Role In Workflow | Required Access | Notes |
| --- | --- | --- | --- |
| Local operator | Reviews the current host map and fundamental host details | Local authenticated browser session | One operator in Phase 1 |
| HostHunter producer | Registers collection runs and sends immutable CIM host-details observations | Scoped write credential over the private producer network | Cannot read investigations, browser sessions, PostgreSQL, or control the UI; future collection entrypoints are `Set-HHTarget` and `Get-TargetHostDetails` |
| Visualizer application | Validates, stores, projects, queries, and renders derived information | Producer-network listener plus scoped PostgreSQL role over the private database network | Has no managed-host credential, database-superuser access, or SSH capability |
| PostgreSQL service | Persists visualizer sessions, normalized observations, projections, and migration state | Dedicated database volume; private Compose network only | Publishes no host port and is not an original-evidence store |
| Managed computer | Source of explicitly collected computer metadata and event logs | Reached only by HostHunter | Never contacted by the visualizer |
| Docker administrator | Starts/stops/replaces the local container | Local Docker authority | Break-glass access remains outside application authorization |

## 8. Source-Of-Truth Model

| Source | Represents | Used For | Conflict Handling |
| --- | --- | --- | --- |
| Immutable HostHunter CIM host-details observation | Actual endpoint claims collected during authenticated connection and recorded by HostHunter | Stable host identity, node labels, target details, membership, OS, hardware, network, time, collection truth, provenance, and audit links | JSON Schema and semantic validation gate acceptance; identical bytes replay safely; conflicts fail; `failed` never replaces the last usable projection |
| HostHunter process event batch | Phase 2 audit evidence derived from collected event logs | Later process instances, lifecycle boundaries, parent relationships, and timeline | Not accepted by the Phase 1 API; Phase 2 must add a separately versioned compatible contract |
| HostHunter source provenance | Audit evidence | Selected-host details and reproducibility | Missing or conflicting provenance prevents activation |
| Normative `CIM_Specification` OpenAPI, JSON Schema, ECS mapping, and golden fixtures | Expected integration state | Payload/HTTP semantics, producer/consumer validation, compatibility, error behavior, and display mapping | JSON Schema controls payload shape; OpenAPI controls HTTP; any disagreement with prose is a contract defect and blocks implementation |
| Visualizer PostgreSQL store | Derived application state | Active session, indexed host observations, projections, UI queries | Rebuildable; never treated as original evidence |
| Shared investigation state and host-map layout state | Derived presentation state | Selected host, filters, detail visibility, and stable operator view | Application state wins over Cytoscape-local state; disposable and never treated as forensic evidence |
| Browser display | Output/report | Investigation and navigation | Must disclose incomplete, unknown, ambiguous, and failed states |

Domain/workgroup is an asserted, timestamped endpoint observation. It is not
proof of current Active Directory health, trust, reachability, or permissions.

## 9. Numbered Requirements

| ID | Requirement | Source Evidence | Phase | Type | Acceptance Criteria | Proof | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R-001 | The visualizer must be a separate Dockerized application, independently versioned from HostHunter. | User request; current HostHunter boundary | Phase 1 | operational | The visualizer can be built, started, stopped, upgraded, and rolled back without replacing the HostHunter controller. | Container lifecycle integration test | confirmed |
| R-002 | The visualizer must bind only to localhost and support one local operator. | User answer 6 | Phase 1 | security | No application port is published on a non-loopback interface and remote clients cannot connect. | Container/network contract test | confirmed |
| R-003 | HostHunter must create one fresh active investigation when the operator starts a new collection run; ordinary visualizer or PostgreSQL restarts must resume the current investigation. | User answer 7; follow-up decision 1 | Phase 1 | functional | A new collection run establishes an active investigation with zero hosts before accepting new registrations; restarting either service without a new run returns to the same active investigation and data. | Integration and browser journey | confirmed |
| R-004 | Resetting the active investigation must not delete or modify HostHunter's original logs, receipts, audit records, or evidence. | Evidence-preservation constraint | Phase 1 | security | A new investigation changes only visualizer-derived state; hashes and counts of HostHunter evidence remain unchanged. | Cross-boundary integration test | confirmed |
| R-005 | Every computer must have a stable HostHunter-issued endpoint identifier that is not derived solely from hostname, IP address, or display name. | User metadata requirement; technical safety requirement | Phase 1 | data | Renaming a computer or changing its address updates metadata without creating or merging the wrong node. | Identity unit/integration fixtures | confirmed |
| R-006 | HostHunter must collect computer name, FQDN, domain/workgroup, operating-system metadata, and observation time during authenticated endpoint connection. | User answer 3 | Phase 1 | integration | A successful supported connection produces a versioned registration containing each populated field and explicit absence reasons where unavailable. | HostHunter focused unit and live-Windows qualification | confirmed |
| R-007 | Missing or unavailable domain membership must display as `Unknown` and must never be guessed from process events, usernames, DNS suffixes, or network addresses. | Explicit user constraint | Phase 1 | data | Fixtures without authoritative domain/workgroup metadata render `Unknown`; no derived domain value is stored. | Unit and browser negative tests | confirmed |
| R-008 | Computers with the same explicit domain/workgroup observation must be visually identifiable as related without claiming unobserved AD relationships. | User goal | Phase 1 | UX | Domain members share a labelled group/cluster; workgroup and unknown computers are distinguishable; no trust or permission edge appears. | Browser/E2E and screenshot proof | confirmed |
| R-009 | The visualizer ingest contract must accept normalized, provider-neutral Process Start and Process Stop observations derived from event logs when process investigation is introduced. | User answers 1 and 2; host-only Phase 1 re-scope | Phase 2 | integration | A separately versioned valid event batch activates in Phase 2; provider-specific fields remain provenance and do not shape the primary UI contract; the Phase 1 API exposes no process-event endpoint. | OpenAPI/schema contract and Phase 1 absence tests | deferred |
| R-010 | Raw EVTX parsing and provider-specific mapping must remain outside the visualizer. | User answer 1; modular boundary | Phase 1 | integration | The visualizer image contains no EVTX parser and rejects raw-file upload attempts. | Image/static and API negative tests | confirmed |
| R-011 | The system must preserve exact, heuristic, ambiguous, start-only, stop-only, and invalid-time lifecycle outcomes without inventing durations or identities when process investigation is introduced. | Prior plan; forensic correctness; host-only Phase 1 re-scope | Phase 2 | data | Missing partners remain visible; a start-only observation is never labelled running; ambiguous matches remain unmerged. | Projection unit and integration fixtures | deferred |
| R-012 | Selecting a computer must reveal its process tree, duration timeline, filters, and evidence details in one pane of glass when process investigation is introduced. | User answer 4; host-only Phase 1 re-scope | Phase 2 | UX | One computer-selection action exposes the synchronized process workspace without route or page replacement in Phase 2; Phase 1 exposes host details only. | Browser action, Phase 1 absence, and click-count tests | deferred |
| R-013 | Parent/child process edges must be evidence-backed and confidence-labelled; insufficient evidence must remain unresolved when process investigation is introduced. | Forensic correctness; host-only Phase 1 re-scope | Phase 2 | data | Exact parent evidence renders a definite edge; uncertain candidates are labelled or omitted rather than forced. | Projection fixtures and inspector browser test | deferred |
| R-014 | Process timeline entries must show observed start, observed stop, supported duration, and incomplete boundaries truthfully when process investigation is introduced. | Original process-input scope; host-only Phase 1 re-scope | Phase 2 | UX | Matched observations have a duration; unmatched boundaries use explicit missing-start/missing-stop treatment and no fabricated timestamp. | Unit and browser/E2E proof | deferred |
| R-015 | The Phase 1 host map must populate progressively as validated computer registrations and host status/metadata observations arrive. | User answer 5; host-only Phase 1 decision | Phase 1 | functional | A valid registration creates one stable node before enrichment fields are available; later observations update only that host and preserve current selection, filters, and zoom; invalid observations do not partially update it. | Streaming integration and browser journey | confirmed |
| R-016 | Process-event ingestion must be bounded, authenticated, schema-validated, idempotent, and atomically activated when introduced. | API/data-integrity requirement; host-only Phase 1 re-scope | Phase 2 | security | Identical retries do not duplicate data; conflicting retries fail; incomplete/invalid batches never contribute partial process graph or timeline facts. | API, persistence, crash, and replay integration tests | deferred |
| R-017 | The process-investigation phase must support 25 computers and five million process observations in one active investigation. | User answer 7; host-only Phase 1 re-scope | Phase 2 | operational | The benchmark dataset stays within confirmed ingest, query, update, and browser interaction budgets without silently omitting data. | Containerized performance benchmark | deferred |
| R-018 | Over-budget process graph or timeline results must use exact-count aggregation and bounded queries rather than freezing the browser or silently dropping evidence. | Modular/scale requirement; host-only Phase 1 re-scope | Phase 2 | UX | Queries report truncation/aggregation explicitly and the browser remains responsive at the process benchmark boundary. | Performance and browser stress tests | deferred |
| R-019 | The initial model must be extensible to later entity and relationship types without changing existing Phase 1 host semantics. | User modularity requirement | Phase 1 | architecture | Entity/relationship renderers and schemas are registered by version/type; later process and directory entities can be added without reinterpreting stored host identity, metadata, or provenance. | Contract and migration tests | confirmed |
| R-020 | The UI must render all host- and later event-controlled values as inert escaped text and must not execute links, HTML, scripts, images, or commands from collected content. | Security requirement | Phase 1 | security | Hostile hostname, FQDN, domain, OS, hardware, address, and later command-line fixtures cannot create executable DOM or outbound requests. | Security unit and browser tests | confirmed |
| R-021 | The Phase 1 UI must cover waiting, registering, partial metadata, ready, stale, unreachable, reconnecting, failed, unknown-domain, and empty states. | Frontend design requirement; host-only Phase 1 decision | Phase 1 | UX | Each host-map/detail state has distinct truthful copy and is browser-tested at representative viewports; process lifecycle states do not appear in Phase 1. | Browser/E2E, negative assertions, and screenshots | confirmed |
| R-022 | Every Phase 1 user action must have browser coverage, and production logic must meet the workspace coverage and local-container validation rules. | Workspace `AGENTS.md` | Phase 1 | testing | All user actions have Playwright/equivalent proof; unit coverage is at least 90% for statements, branches, functions, and lines; canonical proof runs locally in containers. | Coverage, E2E, and canonical gate receipts | confirmed |
| R-023 | PostgreSQL must be the Phase 1 durable visualizer system of record and must run as a private service in the local Docker Compose project. | Explicit follow-up database decision | Phase 1 | architecture | The application persists sessions, host observations, projections, and migration state in PostgreSQL; the database has a dedicated volume, publishes no host port, accepts the application through a least-privilege role, builds cleanly from committed migrations, and passes the 25-host Phase 1 benchmark. | Compose network, migration, authorization, recovery, and performance tests | confirmed |
| R-024 | After a new HostHunter collection run has successfully established its fresh active investigation, the visualizer must automatically delete every prior derived visualizer session and its dependent observations/projections. | Follow-up decision 2 | Phase 1 | data | Only the newly established active session remains in visualizer-derived storage; pruning is automatic, idempotent, and crash-safe; a failed new-session start preserves the previously active session; HostHunter source logs, receipts, audit records, and evidence remain unchanged. | Transactional persistence, restart, failure-recovery, cross-boundary, and browser negative tests | confirmed |
| R-025 | Phase 1 must use Cytoscape.js for the host map and must not install, load, or bundle Apache ECharts; ECharts remains selected for the deferred Phase 2 process-duration timeline. | Confirmed visualization decision; host-only Phase 1 decision | Phase 1 | UX | Phase 1 renders host nodes and groupings through one Cytoscape instance and a synchronized semantic host list/details view; production assets contain no ECharts runtime; the Phase 2 renderer boundary can add ECharts without changing Phase 1 host semantics. | Dependency/image inspection, shared-state unit tests, Cytoscape adapter integration, browser accessibility/error journeys, and bounded host benchmark | confirmed |
| R-026 | The HostHunter-to-visualizer integration must be contract-first using OpenAPI 3.1 and JSON Schema 2020-12 with shared schemas, examples, and golden fixtures consumable by the PowerShell 7 HostHunter runtime. | Confirmed API compatibility decision; host-only Phase 1 decision | Phase 1 | integration | Phase 1 accepts collection-run, host-registration, and host-status/metadata UTF-8 JSON only; both repositories validate the same fixture bytes; retries are idempotent; unsupported versions and invalid/conflicting payloads fail with machine-readable errors; visualizer downtime leaves HostHunter metadata replayable; process-event endpoints and fields are absent until a compatible Phase 2 extension. | Cross-repository schema, golden-vector, retry, replay, compatibility, process-endpoint absence, and negative contract tests | confirmed |
| R-027 | HostHunter and the visualizer application must communicate only over a dedicated Docker-private producer network while PostgreSQL remains isolated on a separate database network. | Confirmed private-network decision | Phase 1 | security | Only the HostHunter controller and visualizer application join the producer network; only the application and PostgreSQL join the database network; PostgreSQL publishes no port; the application is published only on host loopback; the producer uses a write-only Docker-secret credential and cannot read investigations or access PostgreSQL. | Compose topology, service-discovery, credential-scope, network-isolation, unavailable-service, and remote-access negative tests | confirmed |
| R-028 | Every Phase 1 host node must be backed by the proposed host-node field reference in Section 9.1, with required values or explicit absence reasons and included enrichments never guessed. | User host-only request; proposed technical field set | Phase 1 | data | A successful registration stores every confirmed required contract field; unavailable nullable fields contain no fabricated value and include an absence reason; enrichment fields display only when explicitly observed; each field retains observation time and source/provenance. | Schema, host-normalization, absence, provenance, and browser detail tests | assumed |
| R-029 | The Phase 1 node face should remain compact while one selection reveals the complete host record in the same pane. | User host-only request; frontend-quality recommendation | Phase 1 | UX | The node face shows display hostname, membership, operating-system family, collection status, and freshness; one click/tap or keyboard selection reveals all available fields in a details region; long values do not expand the graph or overflow the viewport. | Click-count, keyboard, long-content, viewport, screenshot, and accessibility tests | assumed |
| R-030 | Missing or stale host metadata should remain visible and truthful for every field, not only domain membership. | User host-only request; forensic-correctness recommendation | Phase 1 | data | Missing values render `Unknown` or `Not reported` with an absence reason; stale values show their observation timestamp; no value is inferred from hostname, address, neighbouring nodes, process data, or display grouping. | Unit, schema, browser negative, and stale-state tests | assumed |
| R-031 | Phase 1 must support at least 25 progressively registered host nodes with responsive selection, grouping, filtering, and details at the confirmed viewport matrix. | Existing 25-computer target; host-only Phase 1 decision | Phase 1 | operational | The 25-host benchmark meets confirmed p95 registration, initial-render, filter, selection, update, and interaction budgets without omitted nodes or frozen input. | Containerized host benchmark and browser performance test | confirmed |
| R-032 | Phase 1 must exclude expanded connection/collection operational telemetry and keep enrichments focused on facts about the target machine. | Current user correction | Phase 1 | data | The host field contract includes the target-machine enrichments in Section 9.1 but excludes connection duration, operational-state derivation, collection duration, completeness counters, failure counters/history, retry scheduling, and similar monitoring data; only collection status, observation time, and provenance needed to qualify the machine facts remain. | Schema allowlist, API negative, browser absence, and contract tests | confirmed |
| R-033 | Phase 1 must include all previously proposed target-machine enrichments in the selected-host record. | Current user clarification | Phase 1 | data | When explicitly observable, the selected-host details include directory role, OS edition, manufacturer, model, logical processor count, total memory, IP addresses, boot time, and time zone; when unavailable, each field shows a bounded absence reason and is never guessed. | Schema, Windows/Linux qualification, absence, integration, and browser detail tests | confirmed |

### 9.1 Phase 1 Host Node Field Reference

The node face must stay compact. It shows:

- hostname, falling back to the HostHunter target name when unavailable;
- domain, workgroup, none, or `Unknown` membership badge;
- operating-system family badge;
- collection status;
- freshness derived from the latest observation time.

Selecting the node reveals the complete available target-machine record below.
The formerly optional target-machine enrichments are now included in Phase 1:
directory role, OS edition, manufacturer, model, processor count, memory, IP
addresses, boot time, and time zone. `Included, nullable with reason` means
HostHunter must attempt or account for the field, but must not fabricate a
value when the platform, permissions, state, or collection method cannot
supply it. The exact contract key names remain subject to Phase 0 validation.
Missing domain data is `Unknown` and no host value is guessed.

| Category | Proposed Contract Key | Requirement | UI Placement | Meaning And Constraint |
| --- | --- | --- | --- | --- |
| Identity | `endpoint_id` | Required | Details/internal identity | Stable opaque HostHunter-issued ID; never derived solely from hostname, IP address, target label, or display metadata |
| Identity | `target_name` | Required | Details; node fallback label | Operator-facing HostHunter target label |
| Identity | `hostname` | Required, nullable with reason | Node face and details | Explicit computer/host name observed during the authenticated connection |
| Identity | `fqdn` | Required, nullable with reason | Details | Explicit fully qualified domain name; never constructed by concatenating hostname and domain |
| Membership | `membership_type` | Required | Node badge and details | Explicit `domain`, `workgroup`, `none`, or `unknown` classification |
| Membership | `membership_name` | Required, nullable with reason | Group label and details | Explicit domain or workgroup name; `Unknown` when not reported and never inferred |
| Membership | `directory_role` | Included, nullable with reason | Details | Explicitly observed role such as member workstation, member server, or domain controller; no hostname-based inference |
| Platform | `os_family` | Required | Node badge and details | Explicit platform family such as Windows or Linux, otherwise `Unknown` |
| Platform | `os_name` | Required, nullable with reason | Details | Reported operating-system product/caption |
| Platform | `os_version` | Required, nullable with reason | Details | Reported operating-system version |
| Platform | `os_build` | Required, nullable with reason | Details | Reported build/release identifier when the platform supplies it |
| Platform | `os_edition` | Included, nullable with reason | Details | Reported edition or distribution variant |
| Platform | `architecture` | Required, nullable with reason | Details | Reported operating-system/host architecture such as x64 or ARM64 |
| Hardware | `manufacturer` | Included, nullable with reason | Details | Reported system manufacturer; not used as identity |
| Hardware | `model` | Included, nullable with reason | Details | Reported physical or virtual system model; not used as identity |
| Hardware | `logical_processor_count` | Included, nullable with reason | Details | Reported logical CPU count |
| Hardware | `total_memory_bytes` | Included, nullable with reason | Details | Reported installed/available total memory using an unambiguous byte unit |
| Network | `connection_address` | Required | Details | Address HostHunter used for this authenticated connection; not a stable identity |
| Network | `ip_addresses` | Included, nullable with reason | Details | Explicitly observed non-loopback addresses with interface/source context; not used as identity |
| Time | `observed_at_utc` | Required | Node freshness and details | RFC 3339 UTC time at which this metadata observation was collected |
| Time | `last_successful_connection_at_utc` | Required | Details | RFC 3339 UTC time of the latest authenticated HostHunter connection |
| Time | `boot_time_utc` | Included, nullable with reason | Details | Explicitly observed boot time; never calculated from an unqualified uptime string |
| Time | `time_zone` | Included, nullable with reason | Details | Reported host time-zone identifier/offset for later forensic interpretation |
| Collection context | `collection_status` | Required | Node badge and details | Minimal state qualifying whether the displayed machine facts are registering, ready, partial, stale, unavailable, or failed; this is not continuous host monitoring |
| Provenance | `collector_version` | Required | Details | HostHunter producer version that made the observation |
| Provenance | `schema_version` | Required | Details/internal validation | Version of the host-registration/metadata contract |
| Provenance | `source_method` | Required | Details | Qualified method used to observe the metadata, without exposing credentials or raw secrets |

Every nullable or included enrichment field must carry its own
observation/provenance when present. A missing nullable field must carry a
bounded absence reason such as unsupported, access denied, not reported, not
applicable, or collection failed. One field's absence must not block truthful
fields from populating the node.

## 10. Phase Plan

### Phase 0 - Contract, Evidence, And Feasibility

- Confirm this requirements document and the Shared Understanding Contract.
- Encode the confirmed lifecycle contract: a new HostHunter collection run
  creates the fresh session; ordinary application/database restarts resume it;
  automatic old-session pruning starts only after the new session commits.
- Obtain representative host-registration/status/metadata observations for
  Windows and Linux, including complete, partial, unsupported, access-denied,
  duplicate, changed, late, stale, unreachable, failed, and malformed examples.
- Freeze the OpenAPI 3.1/JSON Schema 2020-12 collection-run,
  host-registration, host-status/metadata, idempotency, provenance, and
  machine-readable error contracts with cross-repository golden fixtures.
- Prove how HostHunter obtains every Section 9.1 field, including stable
  endpoint ID and explicit domain/workgroup metadata, through its existing
  managed-host engine on each supported platform. Distinguish collected facts,
  visualizer-derived facts, conditional fields, and unsupported fields.
- Verify and pin the current stable Cytoscape.js, layout/adapter, backend,
  PostgreSQL image, database driver, migration-tool, and connection-pool
  versions from authoritative sources. Revalidate ECharts only when Phase 2 is
  approved.
- Prototype the Cytoscape host map with shared application state, isolated
  failure handling, semantic host-list/detail parity, long metadata values,
  and the representative 25-host browser load.
- Prove Docker service discovery and isolation across the existing HostHunter
  runtime, the private producer network, the visualizer application, and the
  private PostgreSQL network.
- Design and benchmark the Phase 1 PostgreSQL host-registration/observation
  schema, indexes, update path, query plans, and connection limits against the
  representative 25-host dataset.
- Run the new repository's `$repo-testing-setup` workflow and stop at its
  `DRAFT - not confirmed` testing design for approval.
- Complete `$feature-design-preflight` and a repository-grounded
  `$security-threat-model` before implementation.

### Phase 1 - Host Foundation And Node Map

- Add the approved HostHunter computer-metadata collection and producer
  integration through the shared contract and private producer network without
  adding an unapproved public cmdlet.
- Build the localhost-only application plus private PostgreSQL Docker Compose
  stack and its committed migrations.
- Implement session lifecycle, automatic old-session pruning, host
  registration, host status/metadata observations, and host queries.
- Implement stable host-node projection and explicit domain/workgroup,
  operating-system, and collection-status grouping/filtering.
- Implement the Cytoscape.js host map, compact node face, one-selection host
  details, shared application state, isolated failure treatment, and
  synchronized semantic host list/details view.
- Prove the 25-host target, every Section 9.1 truthfulness rule, and every
  Phase 1 user action. Do not ship process routes, process UI, or ECharts.

### Phase 2 - Investigation Depth

- Extend the contract with normalized provider-neutral Process Start/Stop
  observations only after the host-only Phase 1 proof is accepted.
- Add process identity/lifecycle correlation, ancestry, evidence links,
  bounded graph queries, and the five-million-observation PostgreSQL benchmark.
- Add the Cytoscape process-tree view and Apache ECharts process-duration
  timeline, synchronized with the existing selected-host state and semantic
  view.
- Add search, saved filters, process comparison, richer provenance navigation,
  and export only after Phase 1 investigation behavior is accepted.
- Add explicitly collected logon, principal, service, file, network, audit,
  domain-controller, user/group, and permission entities through new versioned
  producers and renderers.
- Add real AD relationships only from explicit collected evidence, never from
  display-name inference.

### Phase 3 - Operational Automation And Hardening

- Reconsider configurable history/retention only if saved investigations are
  later approved; Phase 1 automatically deletes prior derived sessions.
- Harden backup/restore and prove that operational backups do not become an
  operator-facing session-history mechanism.
- Qualify larger cases and additional architectures if required.
- Consider networked/multi-investigator access only through a separately
  approved authentication, authorization, and tenancy design.
- Add alerts or automated assessment only through separately confirmed rules
  and evidence explanations.

## 11. Implementation Plan

| Slice | Purpose | Work Included | Exit Evidence | Depends On |
| --- | --- | --- | --- | --- |
| V-0 | Freeze host contracts | OpenAPI 3.1/JSON Schema 2020-12 host schemas, Section 9.1 target-machine field semantics, freshness threshold, absence reasons, golden fixtures, IDs, collection-run/reset/resume/prune semantics, errors, compatibility | Identical target-machine host vectors accepted/rejected by both repos | Requirements confirmation |
| V-1 | Establish the new repo foundation | Container-only test design, application and PostgreSQL test services, producer/database networks, pinned Cytoscape dependency, explicit ECharts absence, hooks, migrations, local gates, dependency policy | Confirmed `$repo-testing-setup` artifacts plus network/dependency prototype | V-0 |
| V-2 | Extend HostHunter host producer | Stable endpoint identity, Section 9.1 metadata collection, private write-only adapter, observation retry/replay through the existing engine | Focused unit, field qualification, contract, service-discovery, cmdlet journey, failure, Windows/Linux, and negative-boundary proof | V-0, V-1 |
| V-3 | Build host ingest/persistence | Auth scopes, host-schema validation, idempotency, PostgreSQL migrations, least-privilege roles, pooled connections, observation intake/indexing, session creation/resume, transactional prior-session pruning | Contract, migration, authorization, replay, restart, pruning, crash, pressure, and query-plan tests | V-0, V-1 |
| V-4 | Build host projection | Stable node projection, metadata freshness/absence, explicit groupings, filters, bounded host/detail queries, update revisions | Golden host projection and 25-host performance fixtures | V-3 |
| V-5 | Build the host-only UI | Cytoscape.js host map, compact node, one-selection details, shared state, semantic host list/details, filters, isolated renderer error, responsive/accessibility states | Full host-action matrix, long-content screenshots, accessibility and browser proof; ECharts/process UI absent | V-4 |
| V-6 | Integrate and qualify Phase 1 | Real HostHunter producer, progressive 25-host journey, partial/stale/unknown metadata, restart/reset/prune, security, recovery, host benchmark | Local container gate and acceptance ledger | V-2, V-3, V-4, V-5 |

### 11.1 Schema rollout and rollback

- Every persisted schema begins as a committed migration.
- Phase 1 uses expand -> deploy -> contract sequencing.
- A clean PostgreSQL database and volume must build from committed migrations
  alone; generated clients/types, fixtures, and migration tests ship with the
  dependent application change.
- A new app image must remain compatible with the current schema until its
  migration has been verified.
- Rollback may use only an image compatible with the current schema.
- The application runtime uses a scoped non-superuser role. Migration
  authority is separate and available only to the controlled migration step.
- Backup and restore must use a documented PostgreSQL-compatible mechanism and
  be proven against the selected image before production qualification.
- A new-session transaction must establish the replacement active session
  before prior derived sessions are pruned. A failed replacement must leave
  the previous active session usable, and retrying the prune must be safe.
- Backup retention and restore procedures must enforce the confirmed
  no-history product behavior rather than silently restoring an old session as
  the active investigation.
- Failed replacement projections leave the last committed active batch intact.
- Visualizer-derived state can be rebuilt from retained producer inputs and
  HostHunter evidence; source evidence is never mutated to make rollback work.

## 12. Open Questions

### 12.1 Technical Validation - Owner: Us

| Question | Why It Matters | What It Blocks | Validation Method | Evidence Needed | Phase | Status |
| --- | --- | --- | --- | --- | --- | --- |
| What exact common event fields and provenance can HostHunter emit for all supported Process Start/Stop event logs? | Freezes later process identity, correlation, and evidence semantics | Phase 2 process API/schema freeze; does not block Phase 1 | Inspect representative event batches and mapper behavior after host-map acceptance | Canonical matched/unmatched/error fixtures | Phase 2 | deferred |
| How should HostHunter create a stable endpoint ID across hostname/IP changes and target removal/re-addition? | Prevents incorrect node merges and duplicates | Computer registration contract | Inspect current target model and prototype candidate identity lifecycle | Identity decision table and tests | Phase 0 | open |
| Which authenticated Windows and Linux mechanisms provide each Section 9.1 field under the supported PowerShell 7/OpenSSH boundary, and which fields are genuinely unavailable per platform/permission level? | Keeps host metadata accurate, least-privileged, and provider-neutral | Host registration schema and producer implementation | Controlled supported-host probes and authoritative platform documentation | Field-by-field source, permission, absence, and qualification matrix | Phase 0 | open |
| What freshness threshold should mark collected target-machine information as stale? | Prevents old machine facts being presented as current without introducing continuous monitoring | Host freshness badge and stale-state contract | Compare the expected collection-run duration and update cadence with representative observations, then qualify the threshold in the 25-host prototype | Threshold rationale, boundary unit vectors, and client-visible stale examples | Phase 0 | open |
| Which current stable Cytoscape.js version, layout, tree-shaken modules, adapter, and Canvas settings meet the 25-host incremental-layout, accessibility, licensing, maintenance, and browser requirements while proving ECharts is absent? | Exact dependency and adapter choices determine Phase 1 performance, bundle size, and supportability | Frontend dependency freeze | Authoritative current research plus bounded host-map prototype | Dated dependency matrix, bundle/image report, screenshots, accessibility results, and host benchmark | Phase 0 | open |
| What PostgreSQL schema, indexes, observation update rules, connection limits, and query plans meet the 25-host Phase 1 target? | PostgreSQL is selected, but the host truth/freshness model and clean future extension must be proven | Phase 1 persistence design and performance gate | Representative Compose host benchmark plus captured query plans and future-extension review | Machine-readable latency, memory, disk, query-plan, and migration report | Phase 0 | open |
| What PostgreSQL schema, indexes, batch size, connection limits, query plans, and partitioning threshold meet the five-million-process-observation target? | Determines later process-ingest and correlation performance | Phase 2 process persistence design; does not block Phase 1 | Representative Phase 2 Compose benchmark plus captured query plans | Machine-readable latency, throughput, memory, disk, and query-plan report | Phase 2 | deferred |
| Which current stable PostgreSQL image, application driver, migration tool, connection pool, and backup/restore mechanism are mutually compatible and support the local container boundary? | Avoids version drift and an unproven recovery path | Repository foundation and schema rollout | Authoritative current research plus clean-cluster migration/restore prototype | Dated dependency matrix and recovery receipt | Phase 0 | open |
| What exact host-registration, initial-render, selection, filter, details, and update budgets constitute Phase 1 success? | Makes the simple host-map experience testable | Phase 1 performance gate | Measure operator-acceptable interactions during the 25-host prototype | Confirmed p95 budgets | Phase 0 | open |
| How are validated host observations replayed to rebuild a lost visualizer volume without coupling HostHunter to PostgreSQL? | Required for Phase 1 recovery and rollback | Operational design | Producer replay proof | Host rebuild journey and receipts | Phase 1 | open |
| How are validated process-event batches replayed later without requiring the visualizer to parse raw EVTX? | Required for Phase 2 process recovery | Phase 2 operational design; does not block Phase 1 | Producer replay proof after process scope is approved | Process rebuild journey and receipts | Phase 2 | deferred |
| How should PostgreSQL transaction boundaries, cleanup jobs, and backup retention make automatic prior-session deletion crash-safe and idempotent? | Prevents partial resets, accidental active-session loss, or hidden long-term derived retention | Session persistence and recovery design | Failure-injection prototype and backup/restore test | Transaction state model, prune receipts, and recovery proof | Phase 0 | open |
| Which exact OpenAPI 3.1 patch, schema validator, PowerShell HTTP adapter, authentication header, host-observation limits, compatibility window, and retry/backoff rules pass the same cross-repository golden vectors? | Prevents a visualizer-authored host contract that HostHunter cannot implement reliably | Producer/API contract freeze | Generate/execute producer and consumer host-contract suites in both containerized repos | Dated tooling matrix plus byte-identical accept/reject/error receipts | Phase 0 | open |
| What external producer-network name, service alias, port, startup/health behavior, and teardown ownership safely connect the separate Compose projects without exposing PostgreSQL or the application to the LAN? | Makes the approved network reproducible and prevents one project from accidentally deleting shared infrastructure | Compose lifecycle and network security | Clean-create, independent restart, unavailable-service, teardown, and network-inspection tests | Compose topology contract and lifecycle receipts | Phase 0 | open |

### 12.2 Client Questions - Phase 1

| Question | Why It Matters | Client Evidence Needed | Default Recommendation | What It Blocks | Owner | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Does the target-machine field list in Section 9.1 contain the right information for the initial node and selected-host details? | Freezes the HostHunter machine-information contract | Confirm additions, removals, or acceptance of the identity, membership, platform, hardware, network, time, and provenance list; expanded operational telemetry is excluded | Keep only hostname, membership, OS family, collection status, and freshness on the node face; show all target-machine fields in selected-host details | Final host schema and Shared Understanding Contract | James | open |

#### Resolved Phase 1 Decisions

| Question | Why It Matters | Confirmed Decision | Source | Owner | Status |
| --- | --- | --- | --- | --- | --- |
| What exact action means “the operator starts” and creates the fresh active investigation? | Container restart must not accidentally erase or hide an active investigation | A new HostHunter collection run creates the fresh visualizer session; ordinary visualizer or PostgreSQL restarts resume the current one. | Follow-up decision 1 | James | resolved |
| What happens to prior visualizer-derived sessions when a new run starts? | Controls privacy, disk use, recovery, and whether an unintended case history exists | After the new session is established, automatically delete all prior derived visualizer sessions; never delete HostHunter source evidence. | Follow-up decision 2 | James | resolved |
| Which visualization libraries should each phase use? | Keeps the first proof simple without discarding the confirmed process-timeline direction | Phase 1 uses Cytoscape.js for the host map only and excludes ECharts; Phase 2 retains Cytoscape.js process graphs plus Apache ECharts timeline through shared state. | Original visualization decision plus 2026-08-28 host-only re-scope | James | resolved |
| How should the Dockerized HostHunter controller reach the visualizer without exposing PostgreSQL or adding LAN access? | Host loopback is not the controller container's loopback and the two Compose projects otherwise remain isolated | Join only the HostHunter controller and visualizer application to a dedicated private producer network; retain a separate private application/PostgreSQL network and loopback-only browser publication. | Follow-up network/API decision | James | resolved |
| What does the initial visualization contain? | Determines the smallest useful proof and prevents process functionality from dominating the foundation | Phase 1 contains progressively populated host nodes and one-selection fundamental host details only; Process Start/Stop ingestion, trees, timelines, and ECharts move to Phase 2. | 2026-08-28 host-only visualization decision | James | resolved |

### 12.3 Later-Phase Questions

| Question | Why It Matters | Default Recommendation | Phase |
| --- | --- | --- | --- |
| Which AD entities and relationships should appear after domain grouping? | Determines future collection and graph schema | Start with explicit domain controller, user, group, logon, and membership evidence only after Phase 1 | Phase 2 |
| Are saved investigations, exports, notes, or annotations required? | Adds retention and operator-authored state | Defer until the core investigation flow is accepted | Phase 2 |
| Will remote or concurrent investigators ever be supported? | Requires a different auth, tenancy, and exposure threat model | Keep localhost/single-user unless separately approved | Phase 3 |

### 12.4 Deferred Decisions And Non-Goals

| Description | Reason For Deferral | Reconsideration Trigger | Risk Of Deferral |
| --- | --- | --- | --- |
| Raw EVTX parsing in the visualizer | Violates the selected modular producer boundary | Only if HostHunter cannot produce normalized events reliably | Producer remains responsible for mapping/replay |
| Full AD/BloodHound-style relationship graph | Process events and basic domain metadata cannot prove it | Explicit AD collection requirements accepted | Domain view remains grouping, not attack-path analysis |
| Automated anomaly or maliciousness scoring | Requires explainable detection semantics and separate evidence | Phase 1 operator workflow accepted | Operator performs manual interpretation |
| Visible case library | User wants reset-on-start and automatic deletion rather than case management | Need for historical comparisons or saved work | Prior derived sessions are unavailable; a future history feature would require a new retention decision |
| Process event ingestion, correlation, process tree, duration timeline, and ECharts runtime | User reduced the initial visualization to fundamental host details | Host-only Phase 1 is accepted and a separate Phase 2 contract is confirmed | Phase 1 cannot investigate processes; this is an explicit staged limitation |

## 13. Assumptions

| Assumption | Why It Is Reasonable | Risk If Wrong | Resolution Plan |
| --- | --- | --- | --- |
| When Phase 2 is approved, “just event logs” means the product accepts common Process Start/Stop observations without exposing provider-specific source choices in the UI. | Preserves the earlier provider-neutral decision without expanding Phase 1 | Required fields may differ across actual logs | Validate representative Phase 2 fixtures and preserve provider fields as provenance |
| Section 9.1 is a proposed smallest useful target-machine record with all previously optional machine enrichments included. | It covers stable identity, membership, platform, hardware, network, time, and provenance without adding process, monitoring, or security inventory | James may still want additional fundamental machine fields | Keep R-028 through R-030 assumed until James confirms or edits the target-machine list; keep R-032 confirmed as the operational-telemetry exclusion |
| HostHunter remains the only endpoint-facing component. | Matches the current security and managed-host boundary | Visualizer could become coupled to endpoint credentials | Enforce negative dependency and network tests |
| Phase 1 uses one local Docker Compose project containing an application service and a private PostgreSQL service. | PostgreSQL is explicitly selected and preserves a small operational boundary while separating application and database concerns | Two services add health, migration, credential, backup, and lifecycle coordination | Define health/startup ordering and prove migration, backup, restore, restart, and failure recovery in Phase 0/1 |
| Domain/workgroup metadata is an observation, not authoritative directory truth. | The connection probe sees one endpoint at one time | UI could overstate membership certainty | Show source/time and never derive trusts or permissions |

## 14. Risks And Mitigations

| Risk | Impact | Mitigation | Owner |
| --- | --- | --- | --- |
| Stable endpoint identity is derived from a changeable hostname/address or two hosts are merged | Incorrect host node identity | HostHunter-issued opaque endpoint ID, identity lifecycle table, rename/address-change fixtures, and no display-field identity fallback | HostHunter and persistence lanes |
| Partial, duplicate, late, or conflicting host observations corrupt the node | Misleading platform, membership, status, or freshness | Versioned schemas, observation digests, idempotency keys, per-field provenance/absence, atomic activation, and stale-update rules | API/persistence lane |
| Domain inference overstates relationships | Incorrect investigative conclusions | Accept only explicit timestamped HostHunter metadata; render `Unknown`; separate grouping from AD graph semantics | HostHunter and frontend lanes |
| Malicious or extreme host metadata attacks or breaks the browser/API | Code execution, exfiltration, or unusable layout | Strict type/size validation, inert text rendering, CSP, no collected-content links/media, output escaping, bounded logs, and long/hostile-value tests | Security and frontend lanes |
| Too much metadata is placed directly on each node | Cluttered graph, overlap, unreadable mobile/short-height layouts | Compact five-item node face, one-selection details region, semantic list, intentional truncation/wrapping, and viewport screenshots | Frontend lane |
| Progressive host updates move the graph while the operator reviews a host | Loss of context and trust | Stable endpoint IDs/positions, host-scoped updates, preserved selection/filters/zoom, and batched announcements | Projection and frontend lanes |
| Previously collected machine facts are mistaken for current/live state | Operator assumes an OS, address, membership, or hardware fact is current when the observation is old | Label observation time, show explicit freshness, document the collection-run boundary, never infer heartbeats, and provide no monitoring or retry controls | Projection and frontend lanes |
| Phase 2 process code or ECharts leaks into the initial build | Larger attack/dependency surface and failure to prove the simpler host foundation | Dependency/image absence checks, no process API/routes/components, and explicit deferred requirements | Main integration and frontend lanes |
| Phase 2 PID reuse, event ambiguity, or five-million-observation load creates incorrect or slow process views | Future false lifecycles, ancestry, or unusable investigation | Keep process requirements deferred; qualify identity/correlation, ECharts, PostgreSQL batching/indexes, bounded queries, and five-million-event budgets before Phase 2 implementation | Phase 2 projection, persistence, and frontend lanes |
| A producer-network or API mistake exposes data, couples HostHunter to the visualizer, or makes collection depend on visualizer uptime | Unauthorized access, lost delivery, or regression against HostHunter's simplified boundary | Dedicated Docker-private network, write-only scoped secret, versioned framework-neutral contract, no PostgreSQL access, no new public cmdlet, preserve original evidence, and idempotent replay after failure | HostHunter, API, and security lanes |
| Automatic prior-session deletion removes derived investigative state too early or fails halfway | Loss of derived context or inconsistent active state | Establish the new active session before idempotent transactional pruning, preserve the prior session on failed start, emit local prune receipts, align backups with the no-history policy, and prove HostHunter evidence is unchanged | Main integration and persistence lanes |
| Reintroducing the removed forensics subsystem inside HostHunter expands attack surface | Regression against the accepted simplified product | Keep a narrow producer adapter and separate visualizer repo; use `$codebase-prune-review` if any removed path is proposed for reuse | Main integration lane |

## 15. Testing And Proof Plan

### 15.1 Unit

- At least 90% independently for statements, branches, functions, and lines;
  target at least 95% changed-scope coverage for host contracts, stable
  identity, normalization, absence/freshness rules, reducers, query builders,
  and validators.
- Cover initial registration, target-machine enrichment, duplicate, late,
  stale, conflicting, malformed, renamed-host, changed-address,
  changed-membership, partial, inaccessible, unknown, unsupported, and
  not-applicable behavior.
- Cover target-machine normalization, nullable-enrichment absence reasons,
  timestamp ordering, and freshness-threshold boundaries.
- Cover all shared investigation-state reducers, the Cytoscape adapter,
  renderer-failure isolation, bounded host view-model conversion, field-level
  provenance, and hostile/long-text handling.
- Prove there is no Phase 1 process identity, correlation, tree, timeline, or
  ECharts production path to test; those unit suites begin with Phase 2.

### 15.2 Integration

- Clean PostgreSQL migration, upgrade, compatible rollback, backup, restore,
  connection-loss recovery, and derived-state rebuild proof.
- Authentication, authorization scope, digest, idempotency, conflicting retry,
  body limits, backpressure, disk pressure, and crash recovery.
- Byte-identical OpenAPI/JSON Schema golden-vector acceptance/rejection in
  HostHunter and the visualizer for collection-run, host-registration, and
  host-status/metadata payloads, including version negotiation,
  machine-readable errors, unavailable-service retry, and host replay.
- Producer-network service discovery and write-only authentication; negative
  proof that HostHunter cannot access browser read APIs or PostgreSQL and that
  neither application nor database port is exposed to the LAN.
- Least-privilege database roles, no published PostgreSQL host port, bounded
  connection pooling, concurrent ingest/read behavior, and failed-migration
  recovery.
- Computer registration before enrichment metadata; target facts before/after
  collection-status changes; 25 computers; Windows/Linux; same domain;
  workgroup; no membership; unknown membership.
- Atomic host-observation activation and prior-active-state preservation on
  failure; stale/conflicting updates cannot silently replace newer truth.
- Progressive update replay, expiry, reconnect, resync, and stale-response
  handling.
- New collection-run creation, ordinary service restart/resume, automatic
  deletion of every prior derived session after successful replacement,
  idempotent prune retry, and preservation of the prior session when
  replacement fails.
- Cross-repo proof that a new active session does not modify HostHunter
  evidence.
- Negative contract and image proof that Phase 1 has no process-event ingest
  endpoint, raw EVTX parser/upload path, process tables, or ECharts runtime.

### 15.3 Browser/E2E and user actions

After plan confirmation, `$user-action-coverage-review` must produce the
source-of-truth action matrix before frontend files are edited. At minimum,
browser proof must cover:

- open the empty investigation;
- receive and display one computer registration;
- receive partial and later enriched metadata without duplicating or moving
  the host unnecessarily;
- display `Unknown` without domain metadata;
- display domain/workgroup grouping from explicit metadata;
- select a computer in one click/tap or keyboard action and inspect every
  available Section 9.1 field with observation/provenance details;
- keep the node face limited to hostname, membership, OS family, status, and
  freshness while the details region handles long values;
- reveal all available target-machine enrichments, including OS edition,
  directory role, manufacturer/model, processor count, memory, addresses,
  boot time, and time zone;
- distinguish observation time, last successful connection, and freshness
  without implying continuous monitoring;
- filter/group by membership, OS family, and collection status and clear each
  filter;
- pan/zoom/fit the computer graph;
- retain selection, filters, and zoom while another host or observation
  activates;
- navigate the synchronized semantic host list/details with equivalent
  selection and information;
- recover from a Cytoscape adapter/render failure while leaving the semantic
  host list/details and application status usable;
- handle waiting, registering, partial, ready, stale, unreachable,
  reconnecting, failed, unknown-domain, and empty states;
- start a new operator session and see an empty active investigation;
- prove prior-session computers/observations are no longer accessible after the
  successful new-run transition;
- restart the application and PostgreSQL containers and resume the current
  investigation without reset or deletion;
- prove the absence of collection, mutation, deletion, remote-access, raw EVTX
  upload, process tree, process timeline, and process evidence controls/routes.

### 15.4 Frontend design quality

- Verify 360x740, 430x932, 768x1024, 1024x768, 1280x720, 1440x900, and
  1920x1080.
- Capture and manually inspect screenshots for the computer graph, selected
  host details, semantic host view, empty, partial, stale, unreachable,
  failure, and unknown-domain states.
- Assert no unintended document-level horizontal overflow or clipped primary
  controls.
- Stress long hostnames, FQDNs, domain/workgroup names, OS names/builds,
  OS editions, manufacturer/models, connection addresses, IP lists, and time
  zone identifiers.
- Measure the pinned/tree-shaken Cytoscape bundle, one-instance lifecycle,
  memory use, incremental-layout behavior, and interaction latency at each
  target viewport and the representative 25-host scale; prove ECharts is
  absent from the production bundle and image.
- Provide keyboard/touch navigation, visible focus, at least 44x44 CSS-pixel
  touch targets, reduced motion, high contrast, and a synchronized semantic
  host list/details view for graph content.

### 15.5 Security and supply chain

- Complete `$security-threat-model` for HostHunter producer changes and the
  visualizer runtime before implementation decisions are final and again for
  changed scope before push.
- Threat boundaries include managed host -> HostHunter, HostHunter -> private
  producer network -> API, API -> private database network -> PostgreSQL, API
  -> projection/rendering, application -> browser, Docker/admin -> container,
  and build dependencies -> runtime image.
- Run repo-scoped gitleaks before every push.
- Run dependency audits, filesystem scan, SBOM, production build, and image
  scan locally in containers.
- Run application and database services as non-root where supported, with
  read-only root filesystems where compatible, a dedicated PostgreSQL volume,
  bounded temporary storage, dropped capabilities, no Docker socket,
  no-new-privileges, explicit CPU/memory/PID ceilings, and no application
  runtime egress beyond the private database connection.
- Do not write producer tokens, browser sessions, command-line contents, or
  sensitive host metadata or later event fields into diagnostic logs.

### 15.6 Canonical validation

- All proof runs locally in containers.
- The new repository must declare `verify:local`, fast containerized
  pre-commit, hook installation verification, and the approved gate-owned
  slim pre-push lanes.
- The standalone laptop PR gate owns the full exact-SHA proof before merge or
  deploy; GitHub does not rerun it.
- `$test-readiness-preflight` runs before the expensive full local gate.

## 16. Security And Privacy Notes

- Hostnames, FQDNs, domains/workgroups, addresses, system details, and status
  reasons may contain sensitive operational information. Later process command
  lines, usernames, paths, and event data will require their own Phase 2 review.
- The visualizer is local-only but still requires authenticated writes and an
  authenticated browser session; localhost is not an authorization boundary.
- HostHunter producer credentials and browser session material must be scoped
  separately and supplied through Docker secrets or an equivalent approved
  local secret boundary.
- The producer credential is write-only and valid only for the versioned
  collection-run/host-registration/host-status-metadata API. It cannot read
  investigations, create a browser session, or access PostgreSQL. An
  unavailable or rejecting visualizer must not cause HostHunter source
  evidence to be discarded.
- Only the HostHunter controller and visualizer application join the producer
  network. Only the visualizer application and PostgreSQL join the database
  network. The producer network publishes no host port; the browser mapping
  remains loopback-only.
- PostgreSQL publishes no host port. The application uses a scoped
  non-superuser database role over the private Compose network; migration and
  backup authority remain separate from ordinary runtime access. Database
  credentials must use Docker secrets or an equivalent approved local secret
  boundary and must never be committed or logged.
- Host metadata payloads are untrusted. Validate types, lengths, identifiers,
  ownership, state transitions, timestamps, and observation sizes before
  storage.
- Do not render host-controlled HTML, URLs, images, markup, or executable
  content.
- Derived visualizer data must be clearly distinguished from immutable source
  evidence. Every material host-node/detail fact must retain its supporting
  observation time, source method, producer version, and schema version.
- No raw evidence or derived host-observation data leaves the machine in
  Phase 1.
- After a new collection-run session is successfully established, all prior
  visualizer-derived sessions are automatically deleted. The operation must be
  crash-safe, idempotent, locally auditable, and must not delete or alter
  HostHunter source evidence. Backup retention must follow the same
  no-history intent.

## 17. Production AI Handoff

1. Use `$clarify-before-build` after James reviews this document. Produce the
    final Shared Understanding Contract and do not implement until confirmed.
2. Use `$feature-design-preflight` to freeze the host metadata/API contracts,
    field sources, performance budgets, failure behavior, and current dependency
    fit. Run a separate preflight before Phase 2 process work.
3. Use `$repo-testing-setup` for the new visualizer repository before feature
    implementation; its first testing design must stop at
    `DRAFT - not confirmed` for approval.
4. Use `$security-threat-model` for the HostHunter producer change and the new
    application before implementation and before any push.
5. Use `$user-action-coverage-review` after plan acceptance and before
    frontend edits.
6. Use `$frontend-design-quality` throughout implementation and visual proof.
7. Use `$test-readiness-preflight` before the canonical full local container
    gate.
8. Use `$codebase-prune-review` if any implementation proposes reviving the
    removed coupled Forensics/parser/API subsystem rather than adding the
    approved narrow producer boundary.

## 18. Parallel Work Decision

Parallel implementation is applicable only after the contracts and repository
testing design are confirmed. No parallel workers are required to prepare or
confirm this requirements document.

| Lane | Ownership Boundary | Expected Evidence |
| --- | --- | --- |
| Main integration | Shared schemas, migrations, acceptance/test ledgers, compatibility, final gate | Integrated contract and canonical receipts |
| HostHunter producer | Computer metadata collection, shared-schema validation, private write-only adapter, and replay behavior only | Focused unit, golden-vector, service-discovery, cmdlet, failure, live-Windows, and negative-boundary proof |
| API and persistence | OpenAPI/schema contract, producer auth, validation, idempotency, PostgreSQL schema/roles/indexes, migrations, session lifecycle | Cross-repo contract, network, migration, authorization, query-plan, replay, pressure, and recovery tests |
| Projection | Stable host identity, metadata truth/freshness, explicit membership/OS/status groupings, bounded host queries, deltas | Golden host fixtures and 25-host benchmark evidence |
| Frontend | Shared host-selection/filter state, Cytoscape adapter, compact node/details pane, semantic accessible view, browser tests, screenshots | Host action/error matrix, ECharts-absence receipt, bundle/viewport/accessibility/performance proof |
| Security review | Report first; approved remediation only | Threat model with traceable control coverage |

Workers must receive the same final behavior contract, use disjoint write
ownership, avoid reverting other work, and report changed files plus focused
validation. The main agent owns integration, schema sequencing, stale-test
updates, threat review, gitleaks, and final validation.

## 19. Decision Log

| Date | Decision | Owner | Source |
| --- | --- | --- | --- |
| 2026-08-27 | Visualizer receives provider-neutral events through an API | James | Answer 1 |
| 2026-08-27 | Phase 1 product scope is Process Start/Stop event logs, not a source-specific Sysmon/Security UI contract | James | Answer 2 |
| 2026-08-27 | HostHunter will collect explicit computer/domain metadata when it connects | James | Answer 3 |
| 2026-08-27 | The investigation must be one single pane of glass | James | Answer 4 |
| 2026-08-27 | The display populates progressively | James | Answer 5 |
| 2026-08-27 | No network/other-device access in Phase 1 | James | Answer 6 |
| 2026-08-27 | Use a 25-computer/five-million-event Phase 1 benchmark | James | Answer 7 |
| 2026-08-27 | Operator-facing case IDs are not part of Phase 1; each operator run begins with a reset active view | James | Answer 7 |
| 2026-08-27 | PostgreSQL is the Phase 1 visualizer database and runs privately inside the local Docker Compose project | James | Follow-up database decision |
| 2026-08-27 | A new HostHunter collection run creates the fresh investigation; ordinary visualizer or PostgreSQL restarts resume the current one | James | Follow-up decision 1 |
| 2026-08-27 | After a new run is established, automatically delete all prior derived visualizer sessions; preserve HostHunter source evidence | James | Follow-up decision 2 |
| 2026-08-27 | Use Cytoscape.js for computer/domain and process graphs and Apache ECharts for the process-duration timeline, synchronized through shared application state | James | Follow-up visualization decision |
| 2026-08-27 | Use a contract-first OpenAPI 3.1/JSON Schema 2020-12 producer API that the PowerShell 7 HostHunter runtime validates against | James | Follow-up API compatibility decision |
| 2026-08-27 | Connect only the HostHunter controller and visualizer application through a private producer network; keep PostgreSQL on a separate private database network | James | Follow-up network decision |
| 2026-08-28 | Supersede the earlier Process Start/Stop Phase 1 scope: Phase 1 contains fundamental host nodes and selected-host details only; process ingestion, trees, timelines, and evidence views move to Phase 2 | James | Host-only visualization update |
| 2026-08-28 | Phase 1 keeps the 25-host scale target; the five-million-process-observation benchmark moves to Phase 2 | James | Host-only visualization update |
| 2026-08-28 | Phase 1 uses Cytoscape.js only and proves Apache ECharts absent; the selected ECharts process-timeline direction is retained for Phase 2 | James | Host-only visualization update |
| 2026-08-28 | The exact Section 9.1 required/optional field list and compact-node/full-details split are proposed for James's review, not yet confirmed | Us | Requirements update |
| 2026-08-28 | Draft incorrectly interpreted the request for optional target-machine enrichments as expanded operational telemetry; this was not a client requirement | Us | Superseded draft interpretation |
| 2026-08-28 | Include all previously optional target-machine enrichments, such as OS edition and hardware details, while excluding expanded connection, collection, failure, and retry telemetry | James | Target-machine clarification |

## 20. Definition Of Done

### 20.1 Requirements document

- Requirements are numbered, testable, source-backed, and separated from
  technical validation.
- Client questions, technical validation, assumptions, non-goals, risks,
  proof, security, rollout, and parallel work are explicit.
- James confirms or corrects this document.

### 20.2 Phase 1 product

- HostHunter registers explicit, timestamped computer/domain metadata without
  violating its eleven-cmdlet and managed-host-engine contracts.
- A local Docker Compose project starts the visualizer application and
  PostgreSQL; only the application binds to localhost and PostgreSQL publishes
  no host port.
- The separate HostHunter and visualizer Compose projects communicate through
  the dedicated private producer network; PostgreSQL remains reachable only by
  the visualizer application on its private database network.
- HostHunter produces schema-valid UTF-8 JSON through the shared OpenAPI
  3.1/JSON Schema 2020-12 contract using a write-only private adapter, with
  idempotent retry/replay and no new public cmdlet.
- A new HostHunter collection run creates an empty active investigation;
  ordinary application/database restarts resume it without reset.
- After successful new-session establishment, every prior visualizer-derived
  session is deleted automatically and cannot be accessed through the UI or
  API; HostHunter evidence remains unchanged.
- Each successful supported connection produces the confirmed Section 9.1
  fundamental host record with explicit absence reasons and field provenance;
  no host or membership value is guessed.
- The selected-host record contains every included target-machine enrichment:
  directory role, OS edition, manufacturer/model, processor count, memory,
  observed addresses, boot time, and time zone, with explicit absence reasons
  where a value cannot be collected.
- Expanded connection/collection durations, state machines, completeness
  counters, failure history, retry scheduling, and monitoring telemetry are
  absent from the Phase 1 host contract and UI.
- Computers appear progressively as stable Cytoscape nodes and are truthfully
  grouped/filtered by explicit domain/workgroup/unknown, operating-system, and
  collection-status metadata.
- Each node face remains compact. One click/tap or keyboard selection reveals
  the complete available host record in the same pane, with truthful partial,
  stale, unreachable, failed, and unknown states.
- The Cytoscape host map and semantic host list/details remain synchronized
  through shared application state, preserve selection/filter/zoom during
  updates, and retain a usable semantic view if graph rendering fails.
- Phase 1 exposes no process-event ingest endpoint, process tree/timeline or
  evidence UI, raw EVTX parser/upload path, or Apache ECharts
  dependency/runtime.
- Twenty-five progressively registered computers meet confirmed registration,
  query, render, grouping, filtering, update, and selection budgets using
  captured PostgreSQL and browser benchmark evidence.
- Every action/state/viewport has local container browser proof; all required
  coverage, security, dependency, build, and image gates pass.
- PostgreSQL migration, least-privilege access, backup, restore, restart,
  active-session reset, compatible rollback, and derived-state rebuild
  behavior are proven.

## 21. Confirmation Prompt

All previously optional target-machine enrichments are now included and the
mistaken operational-telemetry expansion is removed. Please confirm or edit
the target-machine field list in Section 9.1 and its
compact-node/full-details split. After that decision, confirm the complete
HostHunter Visualizer Requirements document or correct what is still wrong.
Implementation will not begin until this document and the later Shared
Understanding Contract are confirmed.
