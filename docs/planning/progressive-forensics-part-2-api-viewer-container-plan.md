# Progressive Forensics Part 2 - API And Visual Container Plan

Status: DRAFT - not confirmed
Implementation readiness: CONDITIONAL
Date: 2026-08-25
Owner: James Hinton
Proposed repository: HostHunterForensicsApp
Handoff audience: application implementation agent

> Planning artifact only. This document authorizes no repository creation,
> code, database, container, dependency, fixture processing, commit, push, or
> deployment change. Implementation must stop until James confirms the Shared
> Understanding Contract in section 20 and confirms the new-repository testing
> design required by the workspace.
>
> Contract amendment from confirmed Part 1 (2026-08-25): any future Part 2
> implementation must accept ECS 9.5.0 `hosthunter.process_start` events for
> Sysmon event 1 and Security event 4688. References below to OCSF, Process
> Stop, event 5, event 4689, lifetimes, and process graphs are deferred design
> material and are not part of the first Part 1 delivery contract. Part 2 still
> requires its own confirmation before implementation.

## 1. Outcome

Build one independently versioned application container that accepts
HostHunter's normalized event batches, validates and stores them, derives an
evidence-linked temporal property graph, and serves a beautiful responsive
node interface from the same origin.

The first proof supports:

- one local investigator;
- one selected case;
- one and then multiple endpoints;
- progressive endpoint/file status while HostHunter continues acquisition;
- Process Start observations only in the first compatible contract;
- stable Host and ProcessInstance nodes;
- HOSTED_PROCESS and PARENT_OF relationships;
- exact evidence drill-down;
- truthful incomplete, ambiguous, deferred, failed, and empty states.

The API processes HostHunter outputs into durable events and graph
projections. It does not parse EVTX and does not receive raw EVTX uploads.

## 2. Boundary With Part 1

Part 1 / HostHunter owns:

- endpoint SSH and PowerShell acquisition;
- complete event-log directory staging;
- whole-file EVTX transfer to the local Mac;
- immutable evidence spool and source receipts;
- local PowerShell plus evtx_dump parsing;
- ECS 9.5.0 plus `hosthunter.*` provenance normalization;
- deterministic batching and its controller-side durable outbox;
- acquisition/parser/delivery retry and operator commands;
- producer credentials in macOS Keychain.

Part 2 owns:

- versioned event-ingest OpenAPI and JSON Schemas;
- API authentication, authorization, validation, and idempotency;
- independent mounted-source size/hash verification;
- SQLite migrations, persistence, backups, and rebuild behavior;
- file-level run staging and atomic activation;
- process identity, lifecycle correlation, entities, and relationships;
- bounded graph queries, deltas, revisions, and SSE;
- viewer session bootstrap;
- the responsive visual graph, inspector, statuses, and accessibility;
- derived-data observability and operational health.

Part 2 must never:

- invoke SSH, PowerShell, evtx_dump, or HostHunter commands;
- access HostHunter's command-audit database;
- modify, rename, or delete the HostHunter evidence spool;
- accept endpoint credentials;
- accept raw EVTX through the event API;
- run arbitrary uploaded code or parser plugins;
- treat SQLite or graph layout as original evidence;
- send collection, retry, cancel, resume, or delete commands back to
  HostHunter in Phase 1.

## 3. Deployment Shape

Phase 1 deploys one application service:

    HostHunter native controller
        |
        | authenticated event/status PUTs
        v
    127.0.0.1:configured-port
        |
        v
    forensic-app container
        +-- REST/OpenAPI transport
        +-- contract validation and auth
        +-- application/domain services
        +-- SQLite WAL and migrations
        +-- process graph projector
        +-- graph query and SSE endpoints
        +-- compiled React/Sigma viewer
        +-- static assets served same-origin

    mounted inputs:
        HostHunter forensics/evidence/v1 -> /evidence read-only
        API secret material -> read-only secret file

    mounted output:
        app data and SQLite -> /data dedicated persistent local volume

One container is an operational boundary, not a reason to create one coupled
code module. Backend, projection, persistence, notification, and frontend
interfaces remain independently testable and replaceable.

The container:

- publishes only to 127.0.0.1;
- initially qualifies a native linux/arm64 image on the user's Apple Silicon
  Docker Desktop; additional image architectures require separate proof;
- runs as a non-root user;
- has an enforced read-only root filesystem;
- uses /data as its only persistent writable path and a size-bounded tmpfs for
  /tmp scratch;
- drops all Linux capabilities and enables no-new-privileges;
- applies explicit PID, memory, and CPU ceilings plus graceful-stop timeout;
- has no Docker socket;
- has no runtime CDN or external provider dependency;
- runs under an enforced runtime network policy that permits the
  loopback-published API but denies outbound internet/network egress;
- exposes health and readiness probes;
- persists only derived application data in its writable volume;
- can be replaced without changing or deleting acquired evidence.

The mount alias hosthunter-evidence-v1 always resolves to /evidence and exposes
only ready EVTX files plus their file-ready/acquisition-complete receipts.
HostHunter databases, audit artifacts, target profiles, managed known_hosts,
SSH keys, ledger keys/anchors, and clear API tokens are outside the mounted
subtree. An unavailable or wrong-version evidence mount makes ingestion
readiness fail with evidence_mount_unavailable while the last committed
read-only viewer can remain healthy.

Independent verification opens a confined non-symlink file, records file
identity/metadata, streams the hash, and rechecks identity/size/metadata after
reading. Any replacement or hash race quarantines the source. UID/mode
behavior is frozen for Docker Desktop without broadening host permissions.

## 4. Proposed Repository And Module Layout

Create the repository only after plan and repository-testing confirmation:

    HostHunterForensicsApp/
      contracts/
        openapi/
        json-schema/
        canonicalization/
        golden-vectors/
      app/
        backend/
          transport/
          auth/
          application/
          domain/
          persistence/
          projection/
          queries/
          notifications/
          observability/
        frontend/
          graph/
          inspector/
          status/
          accessibility/
          api/
      migrations/
      deploy/
      fixtures/
      tests/
        unit/
        integration/
        e2e/
        performance/
        security/
      docs/
        planning/
        testing/
        operations/
        security/

Dependency direction:

    HTTP and UI -> application use cases -> domain
                                      -> persistence/notification adapters

The domain must not depend on HTTP, SQLite, React, Sigma, PowerShell, or
HostHunter implementation details.

Recommended first viewer stack is React, Sigma.js, and Graphology because the
required experience is a large interactive node graph. Phase 0 must verify
current stable versions, licences, Apple Silicon container support, custom
lifecycle-node rendering, accessibility integration, and measured display
budgets before dependency lock-in.

The backend framework and SQLite driver are a Phase 0 implementation choice.
Selection criteria are:

- first-class OpenAPI/JSON Schema validation without lossy coercion;
- safe SQLite transaction and migration support;
- predictable SSE and graceful shutdown;
- simple static-asset serving;
- container-native ARM64 and AMD64 support;
- current stable maintenance and permissive licence;
- strong unit/integration test seams;
- no external database or service requirement.

## 5. Shared Contract Authority

The Part 2 repository is the physical source of truth for cross-part OpenAPI,
JSON Schemas, canonicalization rules, and golden vectors because it implements
the server.

Stewardship is divided:

- Part 1 specifies and approves hosthunter.file-ready.v1 and
  hosthunter.acquisition-complete.v1 semantics.
- Part 2 specifies and approves event-batch, run, completion/failure, graph,
  problem-response, and SSE semantics.
- A change to either cross-part surface requires compatibility review by both
  parts.
- Part 1 pins an immutable Part 2 contract release and digest.
- No schema is copied and independently edited in both repositories.
- Breaking changes use a new major media type/API version.

Initial named contracts:

- hosthunter.file-ready.v1;
- hosthunter.acquisition-complete.v1;
- hosthunter.event-item/1.x;
- hosthunter.event-batch/1.x;
- hosthunter.run/1.x;
- hosthunter.attempt/1.x;
- hosthunter.run-completion/1.x;
- hosthunter.problem/1.x;
- hosthunter.graph/1.x;
- hosthunter.graph-delta/1.x;
- hosthunter.sse-event/1.x;
- canonical_tuple_v1 and canonical JSON golden vectors.

Normalized event items are a tagged union:

- process_activity containing OCSF 1.9.0 Process Activity plus HostHunter
  provenance;
- unsupported_target_record containing an unsupported reason without invented
  OCSF fields.

Both union members require the same bounded source_record object: media type,
encoding, parser-native bytes, byte count/digest, parser identity, source
ordinal/record ID, and truncation state. The representation is parser-native,
not evtx_dump-specific, so a future Rust producer can preserve its own bounded
record form without reproducing evtx_dump serialization. Records over the
frozen event limit never enter an active run.

The server validates the full schema and computes its own semantic digest. It
must not silently coerce invalid integers, hexadecimal values, timestamps,
GUIDs, nulls, arrays, or duplicate ordered source fields.

## 6. Ingestion API

### 6.1 Mutation resources

    PUT /api/v1/cases/{case_id}
    PUT /api/v1/cases/{case_id}/endpoints/{endpoint_id}
    PUT /api/v1/cases/{case_id}/endpoints/{endpoint_id}/acquisitions/{acquisition_id}
    PUT /api/v1/cases/{case_id}/endpoints/{endpoint_id}/acquisitions/{acquisition_id}/completion
    PUT /api/v1/cases/{case_id}/sources/{source_id}
    PUT /api/v1/cases/{case_id}/sources/{source_id}/deferral
    PUT /api/v1/cases/{case_id}/sources/{source_id}/runs/{run_id}
    PUT /api/v1/cases/{case_id}/sources/{source_id}/runs/{run_id}/attempts/{attempt_id}
    PUT /api/v1/cases/{case_id}/sources/{source_id}/runs/{run_id}/batches/{sequence}
    PUT /api/v1/cases/{case_id}/sources/{source_id}/runs/{run_id}/completion
    PUT /api/v1/cases/{case_id}/sources/{source_id}/runs/{run_id}/attempts/{attempt_id}/failure

Client-chosen identifiers and PUT resources make every mutation replay
addressable.

Phase 1 case authority is fixed: HostHunter generates the forensics case UUID
and creates/upserts it through PUT /cases/{case_id}. Part 2 has no case-creation
UI. An explicitly supplied existing forensics UUID may be attached through the
same idempotent contract; HostHunter's unrelated free-form command CaseId is
provenance only.

The source PUT carries file_id, deterministic source_id, receipt schema,
receipt-relative path, exact receipt-file digest, evidence mount alias
hosthunter-evidence-v1, spool-relative path, verified size/hash, and owning
case/endpoint/acquisition. The server resolves only beneath /evidence, loads
the mounted receipt, verifies its exact digest, and requires every duplicated
identity/path/size/hash value to agree before creating the source.

Acquisition completion carries the final manifest digest and complete
file_id/source_id expected-set pairs. The server stores that complete set in
one transaction even if completion arrives before an individual source PUT;
later source registration fills the expected placeholder. Missing expected
sources remain visible and prevent a false Ready state.

Acquisition completion is immutable. SEALED and ABORTED are terminal for that
acquisition_id; later collection uses a new linked acquisition instead of
rewriting the original expected set or outcome.

Batch semantic identity is run_id plus sequence. HostHunter-Attempt-Id is the
required authenticated execution/delivery-attribution header for a batch. It
is not part of the immutable event-batch body or semantic digest. A later
attempt can therefore replay an identical run/sequence without changing
evidence or causing a false conflict, while the server records every delivery
attempt.

Every PUT requires:

- Idempotency-Key, deterministically derived under the shared contract;
- Content-Digest using sha-256 over the exact request bytes;
- HostHunter-Attempt-Id for batch, run-completion, and attempt-failure
  requests; the attempt-creation PUT establishes that ID and does not require
  the header.

After enforcing Content-Length/body limits, the server verifies
Content-Digest before semantic validation or persistence. Stable problem codes
include missing_content_digest, content_digest_mismatch,
missing_idempotency_key, missing_attempt_id, and unknown_attempt_id. These
transport headers do not enter event semantic identity.

For every mutable resource:

- absent resource plus valid body: 201;
- semantically identical resource: 200 with the original receipt;
- same URI with different semantic content: 409;
- schema, authentication, authorization, or ownership failure: stable RFC
  9457 application/problem+json 4xx;
- request/event too large: 413;
- writer saturation: 429 or 503 with Retry-After;
- disk-pressure refusal: 507 storage_pressure, which pauses producer delivery
  until explicit operator recovery;
- success acknowledgement only after the SQLite transaction commits.

Timeout means unknown commit. The producer safely replays identical bytes.
All persisted evidence-bearing values participate in the semantic digest;
transport property order does not.

Every successful PUT stores canonical resource URI, semantic digest, original
HTTP status, and exact bounded response in resource_put_receipts. After
authentication, ownership, body-limit, digest, and schema checks, identical
replay lookup occurs before current state-transition validation. This allows a
completion retry to return its original receipt after its attempt is already
SUCCEEDED. A conflicting digest still returns 409.

The receipt lookup resolves and authorizes its stored case scope before
returning anything; an out-of-scope token receives the same bounded denial as
an unknown key and cannot enumerate idempotency records.

The server must accept:

- source event times that are not arrival ordered;
- batch PUTs retried at least once;
- sequences received after interruption;
- starts or stops whose partner has not arrived;
- files and endpoints completing in any order.

Activation still requires a complete contiguous batch range from zero to
last_sequence, or a declared empty run with null last_sequence.

### 6.2 Run completion

Completion includes:

    attempt_id
    last_sequence
    expected_unique_event_count
    source_sha256
    parser_exit_code
    lines_seen
    target_record_count
    unsupported_target_count
    warning_count
    fatal_error_count
    stderr_line_count
    normalization_error_count

Activation requires:

- every expected sequence and event count;
- one matching RUNNING attempt with no failure for that attempt; prior failed
  or cancelled attempts for the same deterministic run do not block recovery;
- source ID, size, and SHA-256 agreement;
- independent verification of the read-only mounted source;
- zero parser exit under the frozen strict policy;
- zero fatal JSONL/mapping errors;
- explicitly classified warnings and unsupported counts;
- bounded, valid precomputed graph contributions;
- a valid zero-contribution outcome when no target records exist.

Successful completion marks the attempt SUCCEEDED. A malformed input,
nonzero parser exit, changed source, missing sequence, fatal mapping error, or
projection invariant violation fails the attempt or rejects completion; it
does not activate the run.

### 6.3 Read resources

    GET /api/v1/cases/{case_id}
    GET /api/v1/cases/{case_id}/endpoints/{endpoint_id}/acquisitions/{acquisition_id}
    GET /api/v1/cases/{case_id}/sources
    GET /api/v1/cases/{case_id}/sources/{source_id}
    GET /api/v1/cases/{case_id}/sources/{source_id}/runs/{run_id}
    GET /api/v1/cases/{case_id}/sources/{source_id}/runs/{run_id}/batches/{sequence}
    GET /api/v1/cases/{case_id}/graph/summary
    GET /api/v1/cases/{case_id}/graph?endpoint_id={id}&depth=2&limit=2000
    GET /api/v1/cases/{case_id}/graph/deltas?after_revision={revision}
    GET /api/v1/cases/{case_id}/graph/stream?after_cursor={cursor}
    GET /api/v1/cases/{case_id}/entities/{entity_id}
    GET /api/v1/cases/{case_id}/entities/{entity_id}/neighborhood?depth=1&limit=250
    GET /api/v1/cases/{case_id}/events/{observation_uid}
    GET /api/v1/put-receipts/{idempotency_key}
    GET /healthz
    GET /readyz

graph/summary returns bounded host anchors and aggregate counts for all
endpoints. Graph and neighborhood queries are bounded, support optional
endpoint filters, and return explicit truncation/aggregate metadata.

A graph cursor includes its revision. A cursor from a different revision
returns 409 revision_changed instead of mixing snapshots.

## 7. Authentication And Local Exposure

Phase 1 default:

- the published port binds only to 127.0.0.1;
- producer mutations require a case-scoped or instance-scoped bearer token;
- HostHunter creates the 32-byte producer token, stores its clear value only in
  macOS Keychain, and writes token ID, sha-256 verifier, scopes, and timestamps
  to the owner-private read-only container secret file;
- the server stores/loads only active verifier records, never the clear
  producer token;
- rotation accepts an explicit bounded old/new verifier grace window, then
  revokes the old token; missing-Keychain recovery is explicit rotation and
  does not discard pending work;
- Part 2 separately owns an interactive local viewer bootstrap/login verifier;
  it never reuses the producer credential;
- successful local viewer login creates an HttpOnly, SameSite=Strict session
  cookie;
- same-origin REST and SSE reads use that session;
- state-changing browser routes require origin and CSRF defenses;
- CORS is disabled by default;
- authentication and ownership checks bind case, endpoint, source, run, and
  attempt identifiers;
- case identity is never trusted solely from event content.

The exact viewer password/bootstrap UX, Argon2id-or-equivalent parameters,
session lifetime, recovery, and Keychain option must be frozen in Phase 0 after
the formal threat model. Producer-token ownership and verifier-only container
storage are already fixed above. No secret may be passed in a command argument,
URL, environment dump, log, image layer, or event payload. Loopback binding
alone is not accepted as authentication.

## 8. Persistence Contract

### 8.1 SQLite configuration

- persistent local Docker volume on a local filesystem;
- no SMB/NFS database path;
- WAL mode;
- synchronous FULL;
- foreign keys enabled;
- busy timeout;
- one bounded serialized writer;
- separate read connections;
- bounded transactions and query timeouts;
- online backup API or VACUUM INTO, never a live main-file-only copy;
- clean construction from committed migrations alone;
- expand, deploy, contract migration sequencing.

### 8.2 Minimum tables

| Table | Responsibility |
| --- | --- |
| cases | Case identity, graph revision, created/updated time |
| endpoints | Case-scoped endpoint ID, asserted/resolved names, status |
| acquisitions | Endpoint-scoped OPEN/SEALED/ABORTED state, manifest counts, supersedes_acquisition_id, and current-lineage marker |
| acquisition_expected_sources | Immutable acquisition/file/source expected set and endpoint staging outcome |
| sources | Acquisition, relative path, size/hash, evidence/analysis state, active_run_id |
| producer_runs | Deterministic parser/mapper/schema/config interpretation and state |
| producer_attempts | Runtime execution, timestamps, result, bounded diagnostics |
| event_batches | Run/sequence semantic digest, counts/ranges, original API receipt |
| batch_delivery_attempts | Append-only attempt attribution and bounded HTTP outcome for each batch delivery/reconciliation |
| source_events | Tagged normalized/unsupported items and complete provenance |
| resource_put_receipts | Canonical resource URI/idempotency key, semantic digest, original status/response for every PUT |
| entities | Stable case/entity ID, kind, natural-key digest, current properties |
| entity_aliases | Explicit superseded-to-canonical entity mapping, reason, evidence, revision |
| relationships | Stable relationship ID, kind, endpoints, method/confidence |
| entity_observations | Exact active run/event evidence for one entity |
| relationship_observations | Exact active run/event evidence for one relationship |
| graph_revisions | Primary key case_id plus revision, bounded delta summary, per-case retention floor, time |
| notification_outbox | Monotonic cursor, case_id, optional graph_revision, event type, compact payload, time |

Derived tables are rebuildable from active source events. They never replace
the immutable raw EVTX or HostHunter receipt.

Formal state dimensions:

| Dimension | States |
| --- | --- |
| Acquisition | OPEN, SEALED, ABORTED |
| Source evidence | DISCOVERED, VERIFIED, QUARANTINED |
| Analysis | DEFERRED, STAGING, READY, READY_WITH_WARNINGS, COMPLETE_EMPTY, PAUSED_API, FAILED |
| Run | STAGING, ACTIVE, SUPERSEDED, NONDETERMINISTIC |
| Attempt | RUNNING, SUCCEEDED, FAILED, CANCELLED_BACKPRESSURE |

## 9. File-Level Atomic Activation

The experience is progressive at endpoint and completed-file granularity:

1. Endpoint registration creates a host placeholder immediately.
2. Source registration and batch intake update status and staged counts.
3. Batch transactions validate and stage events plus run-scoped projected
    contributions.
4. Incomplete files do not contribute nodes or edges to forensic graph
    queries.
5. Completion verifies the run and atomically:
    - points sources.active_run_id to the new run;
    - excludes the prior active run for the same source;
    - assigns precomputed contributions one activation revision;
    - applies a bounded precomputed graph delta;
    - increments cases.graph_revision;
    - writes graph.changed to the notification outbox.
6. The viewer applies the completed file as one bounded graph update.

Completion must not rematerialize an unbounded source inside one SQLite
transaction. Contributions and aggregate deltas are prepared during bounded
staging transactions.

A valid no-target source activates as COMPLETE_EMPTY. A failed replacement run
leaves the prior active run visible. Within-file provisional graph facts are
deferred.

This design allows files and endpoints to populate progressively while never
presenting incomplete-file interpretations as evidence.

Entities/relationships are supported by the set of active observations, not
owned by one source row. Superseding a run removes only that run's support; a
fact supported by another active source remains. Lifecycle may truthfully
return from matched to start_only/stop_only when supporting evidence is
superseded.

Staging records run-local facts and affected natural-key buckets. A candidate
delta is tagged with its base graph revision. If another activation advances
the case before completion, the projector rebases only those indexed affected
keys before entering the final transaction. Phase 0 freezes the maximum
affected-key/activation budget and the safe defer/resync behavior; the final
transaction never performs an unbounded whole-case rebuild.

## 10. Graph Model

Use an evidence-backed temporal property graph, not event rows turned directly
into untraceable edges.

Phase 1 entity kinds:

- Host;
- ProcessInstance.

Phase 1 relationship kinds:

- HOSTED_PROCESS;
- PARENT_OF.

Provenance is an explicit union:

- registration_backed_host: endpoint/acquisition registration resource,
  request receipt/digest, asserted identity, and graph revision; it states that
  no event evidence is active when applicable;
- event_backed: active producer run, observation UID, exact source
  hash/file/channel/record/version, mapping version, correlation method/
  confidence, and activation revision.

Placeholder Hosts use only registration_backed_host provenance until event
evidence exists. Every ProcessInstance and PARENT_OF contribution is
event_backed. HOSTED_PROCESS is event-backed for the process side and resolves
to the registered Host. The API and inspector never invent an event reference
for a placeholder.

Future extension registry:

- Principal;
- LogonSession;
- AuditPolicy;
- FileLocation and FileArtifact;
- ServiceInstance;
- ScheduledTask;
- NetworkEndpoint;
- Privilege;
- Permission;
- AccessGrant for n-ary permission facts.

No dormant Phase 2 entities or controls appear in the first UI. The schema and
renderer registry merely preserve a clean extension seam.

### 10.1 Identity

- Host identity starts with the stable HostHunter endpoint ID.
- Folder/target names are aliases/provenance, not rekeying inputs.
- Later canonical hostname evidence updates a label/alias without changing the
  host entity ID.
- Sysmon ProcessInstance identity is endpoint plus valid ProcessGuid.
- Security events never use PID alone as durable identity.
- A Security 4688 start creates the canonical instance ID from endpoint,
  verified coverage/boot epoch when available, and the start observation UID.
- A stop-only 4689 creates an observation-scoped provisional instance ID, not a
  PID identity.
- If a later 4688 uniquely matches that stop, the projector creates/uses the
  same start-derived canonical ID it would have used had the start arrived
  first, records an explicit provisional-to-canonical entity_alias, and moves
  the stop evidence to that entity.
- The graph delta carries supersession metadata so the viewer transfers
  coordinates, selection, focus, and future annotation-ready references to the
  canonical ID without a visual jump. API entity lookup follows the alias.
- Ambiguous matching never supersedes the provisional node.
- Phase 1 does not silently merge Sysmon- and Security-derived process
  instances, even when they appear to describe the same process.
- Cross-provider aliases/coalescing are deferred until an
  arrival-order-independent rule and evidence UX are designed.

All 4688-first, 4689-first, same-file, different-file, and replay arrival
permutations must converge on identical final entity IDs, lifecycle semantics,
evidence links, and relationships.

### 10.2 Lifecycle correlation

Lifecycle states:

- matched_exact;
- matched_heuristic;
- start_only;
- stop_only;
- ambiguous;
- invalid_time_order.

Sysmon 1 and 5 pair exactly by endpoint plus ProcessGuid.

Security 4688 and 4689 use conservative endpoint, PID, start-before-stop,
bounded time window, image corroboration when present, verified boot/coverage
epoch when available, and absence of an intervening start for the same PID.
PID reuse and insufficient evidence preserve ambiguity. Security termination
Subject is not process-owner proof. No duration is fabricated.

Parent relationships use source ProcessGuid/parent evidence when exact.
PID/time/image-only candidates are heuristic and confidence labelled.
Ambiguous candidates remain unresolved/dotted rather than forced.

Unsupported target records remain evidence/warnings and never create invented
process nodes.

## 11. Graph Query And SSE Contract

notification_outbox.cursor is the replay cursor. cases.graph_revision
identifies the active graph state. graph_revisions is keyed by
(case_id, revision); every outbox row carries case_id and optional
graph_revision. Delta/SSE retention floors are calculated per case so activity
in one case cannot expire another case's history.

SSE events:

- acquisition.updated;
- endpoint.updated;
- source.updated;
- coalesced source.progress;
- graph.changed;
- resync_required.

SSE carries compact status/invalidation data, not full graph payloads.
Last-Event-ID takes precedence over after_cursor.

Each retained graph delta includes:

- node_upserts;
- node_removals;
- edge_upserts;
- edge_removals;
- entity_supersessions with old/new IDs and coordinate/selection-transfer
  reason;
- from_revision and to_revision;
- has_more and next_after_revision;
- a bounded summary.

One activation revision is indivisible. A normal delta response may include
multiple complete revisions up to the response cap. If one activation delta
alone exceeds that cap, the API returns graph_delta_resync_required with the
latest revision instead of splitting atomic state; the viewer reloads its
bounded current window. It never applies half an activation.

Expired graph-delta history returns 410 graph_delta_expired. Expired SSE
history emits resync_required with latest_cursor and graph_revision, then
closes. The viewer reloads its bounded current window and reconnects. No event
creates one SSE message per record.

## 12. First Visual Experience

### 12.1 Screen composition

- The graph owns the viewport; there are no permanent sidebars.
- The canonical browser route is /cases/{case_id}/graph.
- Phase 1 opens directly into that operator-selected case; no case library is
  introduced. An unknown/unauthorized case shows a bounded error and never
  falls back to another case.
- Each endpoint occupies a softly bounded stable host island.
- The host anchor sits left and process ancestry grows left-to-right.
- A restrained top region shows case; Indexed X; Discovered Y for open
  acquisitions; Sealed expected Z for finalized expected sets; active process
  observations; warnings; and graph controls. Indexed means sources with
  active_run_id, including COMPLETE_EMPTY. Discovered means source resources
  backed by mounted file-ready receipts; Sealed expected comes only from final
  acquisition manifests.
- Active process observations counts only activated evidence.
- A thin bottom rail shows the selected host's current source and
  acquisition/indexing state. With no selected host and concurrent work it
  says: N files processing across M endpoints.
- While one selected source parses, it may say: Current file: N observations
  validated, pending file completion.
- Selection updates the evidence inspector without moving keyboard focus.
- An explicit Details/Open inspector action transfers focus.
- Empty copy says: Waiting for captured event-log directories.
- Progress copy says: Indexing captured records, never live activity.

Graph controls:

- Follow updates;
- Fit current host;
- Fit all;
- Zoom in;
- Zoom out;
- Legend;
- Graph data.

### 12.2 Visual language

| Evidence fact | Treatment and text |
| --- | --- |
| Host | Large rounded anchor, hostname, ingestion-status ring |
| Matched start/stop | Neutral filled process circle, closed outer ring, observed duration |
| Start only | Hollow circle, open-ring notch, No stop observed |
| Stop only | Broken ring or diamond, warning glyph, No start observed |
| Supported but incomplete | Skeletal process node with explicit missing-field state |
| Ambiguous lifecycle | Dashed outer ring and candidate count |
| Invalid time order | Broken-clock marker and Invalid observed time order |
| Aggregate | Stacked-circle node with exact hidden count |
| Host to root containment | Thin neutral line without a parent claim |
| Exact parent | Solid directional edge |
| Unique heuristic parent | Dashed directional edge with confidence |
| Ambiguous/unresolved parent | Dotted candidate edge; no forced merge |

Host ingestion ring mapping:

| Endpoint-local state | Ring/icon/text |
| --- | --- |
| Registered, no acquisition | Dotted neutral ring, hollow clock, Waiting |
| OPEN, no active source | Open segmented ring, download icon, Acquiring |
| Active plus remaining work | Partially closed ring, index icon, Indexing - partial |
| SEALED plus nonterminal analysis | Double neutral ring, index icon, Indexing |
| All current sources clean/empty | Closed accent ring, check icon, Ready |
| All terminal with warnings | Closed dashed amber ring, warning icon, Ready with warnings |
| Paused | Double-gap ring, pause icon, Paused |
| Failed/deferred/quarantined/aborted/conflict/storage refusal | Broken amber/red ring, attention icon, Needs attention |
| New acquisition after ready | Closed ring plus small open arc, update icon, Updating |

Supported-field completeness is orthogonal to lifecycle. The mapper/projector
freezes reason codes such as missing_process_identity, invalid_pid,
invalid_guid, missing_image, process_account_unknown,
not_populated_placeholder, and supported_optional_absence. A skeletal inner
mark plus short reason badge represents incomplete fields while the outer
lifecycle ring still independently shows matched/start-only/stop-only/
ambiguous/invalid-time state. The legend, semantic table, inspector, high
contrast, and screenshots expose both dimensions.

Design contract:

- one polished Phase 1 theme;
- calm neutral canvas and island surfaces;
- one host accent and neutral process color;
- warning/failure colors describe evidence/operational state, not suspiciousness;
- uniform process size, with aggregates visibly distinct;
- visible hover, selection, and keyboard focus;
- labels prioritize zoom, selection, and available space;
- no decorative continuous motion;
- no benign/malicious red-green semantics;
- every color meaning is duplicated by shape, line, icon, or text;
- all event values render as escaped text, never HTML.

### 12.3 Stable progressive behavior

- Endpoint registration immediately creates a placeholder host island.
- Resolving the canonical hostname changes label/aliases, not identity or
  position.
- A file activation adds one bounded contribution without global reflow.
- A later stop or parent enriches/retargets the process without moving it.
- Existing host anchors and process coordinates remain within two CSS pixels
  at the same viewport/layout seed across file activation, another endpoint,
  reconnect, resync, and same-viewport reload.
- Roots and two ancestry levels show initially.
- Deeper/excess branches become exact-count aggregates.
- Initial placement uses available ancestry, not lifecycle completeness.
  Start-only becoming matched changes styling/duration in place. Only nodes
  with no usable ancestry/root placement use a labelled unresolved shelf.
- Initial auto-fit is allowed only before the investigator first pans/zooms.
- Follow updates follows the investigator-selected host. If none is selected, it
  follows the most recently activated endpoint only until that activation
  settles and never oscillates between concurrent endpoints.
- With Follow updates disabled, changes show a host-scoped N graph updates -
  View action. The count includes added processes, lifecycle changes, parent
  resolution, and removals/supersessions; it is not limited to new nodes.
- File activation is one update, not sequential process animation.
- Reduced-motion mode uses immediate updates and a static highlight.

Layout coordinates are presentation state, never evidence. A local layout
cache may key coordinates by case, renderer version, viewport class, and stable
entity ID. It must be disposable and reproducible from deterministic seeds.

### 12.4 Display budgets

Provisional Phase 0 targets:

- 250 visible process nodes per host;
- 2,000 visible nodes overall;
- 4,000 visible edges overall;
- 250 results per neighborhood expansion.

Over-budget data becomes a truthful exact-count aggregate. It is never silently
dropped and must not freeze the browser.

## 13. Evidence Inspector

Host selection shows:

- canonical hostname and aliases;
- endpoint and acquisition identities;
- registration resource/receipt provenance and, for a placeholder, the exact
  statement No event evidence active yet;
- source files, hashes, observed record-time bounds, manifest completeness,
  known gaps, and status; record-time bounds never imply continuous coverage;
- process, matched, start-only, stop-only, ambiguous, warning, and empty counts.

Process selection shows:

- image, PID, ProcessGuid when present, process account when evidenced, path,
  and command line;
- creation actor and termination actor as separate source-labelled fields;
- parent identity and relationship method;
- observed start, stop, duration, and lifecycle state;
- exact/heuristic/ambiguous method and confidence;
- source hash, channel, record ID/version, parser/mapper version, and exact
  supporting events.

Edge selection shows:

- source and target identities;
- containment or parent-child meaning;
- correlation method, confidence, limitations, and observations.

All long or truncated raw values expose their complete value to keyboard focus
and hover. No event-controlled link, HTML, image, or executable content is
rendered.

A stop-only Security 4689 keeps process account unknown unless independent
process-account evidence exists; its Subject appears only as termination actor.

## 14. User-Facing State Contract

Connection/request state is orthogonal:

- Initial loading: no case response has completed; show a skeleton/progress
  state and never flash Waiting.
- Reconnecting: REST/SSE unavailable while the last stable graph remains.
- Resyncing: the server requested a bounded graph-window reload; retain the
  last stable graph until the replacement is ready.

The primary reducer evaluates the current acquisition lineage for every
endpoint in the case. A newly linked acquisition supersedes the prior one for
status reduction while historical acquisitions remain inspectable. Old
failed/deferred acquisitions do not permanently dominate a recovered endpoint.

An activated source means sources.active_run_id is non-null. COMPLETE_EMPTY
therefore counts as indexed/activated even though it contributes zero nodes.
The reducer quantifies over all current endpoints/acquisitions, not only the
selected host.

Primary case state precedence:

| Order | State | Exact trigger |
| --- | --- | --- |
| 1 | Needs attention | Any current expected source is FAILED, DEFERRED, or QUARANTINED; a current acquisition is ABORTED; a run is NONDETERMINISTIC; an integrity conflict exists; or storage_pressure refuses intake |
| 2 | Paused | Current producer/API work is PAUSED_API or operator-paused without a higher-priority failure |
| 3 | Updating | The case previously reached Ready/Ready with warnings and any endpoint now has a newly OPEN current acquisition/source |
| 4 | Indexing - partial | At least one current source has active_run_id and any other current acquisition/source work remains OPEN or nonterminal |
| 5 | Acquiring | At least one current acquisition is OPEN, no current source has active_run_id, and the case is not Updating |
| 6 | Indexing | All current acquisitions are SEALED, at least one expected source is nonterminal STAGING/VERIFIED/DISCOVERED, and no current source has active_run_id |
| 7 | Ready with warnings | Every current acquisition is SEALED; every current expected source is READY, READY_WITH_WARNINGS, or COMPLETE_EMPTY with active_run_id; at least one current warning exists; and none match higher states |
| 8 | Ready | Every current acquisition is SEALED and every current expected source is clean READY or COMPLETE_EMPTY with active_run_id |
| 9 | Waiting | No current acquisition/source has been registered |

COMPLETE_EMPTY says: Indexed - no supported Process Start/Stop events.
Ready means caught up to sealed acquired evidence, not complete endpoint
activity. Start-only never means running.

## 15. Phase 1 User Actions

1. Pan the graph.
2. Zoom by wheel.
3. Zoom by pinch.
4. Zoom by keyboard or Zoom controls.
5. Fit the selected host.
6. Fit all visible content.
7. Open and close Legend.
8. Select a host.
9. Select a process.
10. Select a containment or parent edge.
11. Expand an aggregate or process branch.
12. Collapse a branch.
13. Toggle Follow updates.
14. Activate N graph updates - View.
15. Open the evidence inspector.
16. Close the evidence inspector.
17. Open exact supporting start/stop evidence.
18. Inspect source warnings and deferred reasons.
19. Open and close the synchronized Graph data table.
20. Retry a failed initial, branch, table, or inspector view request.

Retry, cancel, resume, acquisition, and deletion are HostHunter/operator
actions and have no browser control in Phase 1. Retry view only repeats a
read-only browser request; its label and telemetry must not imply a HostHunter
collection or parser retry.

Request-level behavior:

- initial case/graph load shows Initial loading until success;
- 401/403 shows an unlock/authorization state without leaking case existence;
- 404 shows Case not found and never opens another case;
- initial transport failure shows a bounded Retry view action;
- branch expansion shows an inline loading affordance and preserves the
  current graph on error;
- Graph data and inspector show scoped loading/error/retry states without
  blocking the graph;
- collapse aborts or ignores its stale expansion response;
- changing selection aborts or ignores the prior inspector response;
- reconnect/resync cancels obsolete window requests;
- late/stale responses can never change selection, focus, graph revision, or
  the active inspector.

## 16. Accessibility And Responsive Contract

Accessibility:

- maintain a synchronized semantic HTML treegrid/table with Host, Process,
  PID, Parent, Lifecycle, Confidence, and descendant-count columns;
- when Graph data is open, keep its rows in the accessibility tree and
  keyboard order; when closed, the panel is hidden/inert;
- give every row an explicit expand/collapse button with aria-expanded;
- give Host containment and Parent relationships a focusable button in the
  relationship cell so keyboard/touch users can select each edge type and open
  its evidence;
- synchronize canvas/table selection and focus;
- Tab reaches controls and results;
- arrow keys traverse visible nodes/rows;
- Enter selects; treegrid-standard keys or the explicit button expand and
  collapse;
- a normal button opens and focuses the inspector;
- Escape closes it and restores focus to the actual invoker, whether canvas,
  table, relationship button, or toolbar;
- if a delta removes the focused entity, move focus to the next visible
  sibling, then its host, then the Graph data control, and announce the change
  once;
- focus survives graph deltas, reconnect, and resync;
- a live region announces one batched update per endpoint/file activation,
  never one per process;
- controls have at least 44 by 44 CSS pixel targets;
- WCAG AA contrast and high-contrast distinctions;
- no state relies on color alone;
- reduced motion disables pulses, path drawing, camera animation, and
  sequential entrance;
- complete truncated values are available by keyboard and hover.

Responsive behavior:

| Width | Layout |
| --- | --- |
| 1024 and wider | Full viewport graph, compact top status/controls, right overlay inspector |
| 768 to 1023 | Status row plus bounded control row, dismissible drawer |
| 431 to 767 | Compact status/rail, non-scrolling icon toolbar with names, bottom drawer |
| 430 and narrower | Full-width graph, bounded toolbar, bottom sheet inspector |

The semantic table opens through a visible Graph data control in an in-page
panel/drawer and owns its horizontal scroll. It never creates document-level
overflow. On layouts below 768 pixels, Legend, Graph data, and Inspector are
mutually exclusive modal sheets/drawers with one focus trap and deterministic
focus restoration; opening one closes the other.

Required visual viewports:

- 360 by 740;
- 430 by 932;
- 600 by 900;
- 767 by 900;
- 768 by 1024;
- 1024 by 768;
- 1280 by 720;
- 1440 by 900;
- 1920 by 1080.

## 17. Failure, Recovery, And Observability

| Failure | Server behavior | UI behavior | Recovery |
| --- | --- | --- | --- |
| Bad auth/ownership | Reject without write | Needs attention only if HostHunter reports terminal failure | Correct configuration |
| Invalid batch | Reject entire transaction | Source error, no graph change | Correct producer/schema |
| Identical retry | Return original receipt | No duplicate | Producer reconciles |
| Conflicting retry | 409, mark integrity conflict | Needs attention | Investigate nondeterminism |
| Missing sequence | Refuse completion | Source incomplete | Replay missing batch |
| Source hash mismatch | Quarantine, refuse activation | Needs attention | Reacquire/new source |
| Parser attempt failure | Preserve staged diagnostics, no activation | Source failed/paused | New attempt/run |
| Valid empty file | Activate zero contribution | Indexed - no supported Process Start/Stop events | None |
| Unsupported target version | Store evidence, warning, no node | Ready with warnings | New mapper/new run |
| API restart | SQLite transaction commits or rolls back | Reconnecting | Replay PUT/cursor |
| Viewer disconnect | Keep last graph | Reconnecting | SSE replay or resync |
| SSE history expired | Emit resync_required and close | Reconnecting briefly | Reload bounded window |
| Disk pressure | Refuse before unsafe exhaustion | Needs attention/storage warning | Free/expand storage |
| New mapper fails | Keep previous active run | Prior graph plus failed update | Correct and stage again |
| Acquisition aborts | Preserve verified active files | Needs attention/partial | Investigator decides |

Structured logs include stable IDs, counters, timings, error codes, and bounded
redacted diagnostics. They exclude raw event payloads, complete command lines,
credentials, tokens, and browser session values.

Required metrics:

- request count/latency/result by stable route class;
- SQLite writer queue and transaction duration;
- bytes/events staged and activated;
- graph revision and delta size;
- SSE clients, replay, expiry, and resync;
- query size/latency/truncation;
- disk use and refusal threshold;
- frontend load, delta apply, render, and interaction timings.

## 18. Security And Privacy

Trust boundaries:

1. HostHunter producer to event API;
2. read-only evidence spool to hash verifier;
3. API validation to SQLite;
4. active events to graph projection;
5. database/query payloads to browser;
6. browser session to local API;
7. registries/build inputs to the runtime image.

Required controls:

- loopback-only published port and explicit auth;
- producer token scopes, rotation, verifier storage, and constant-time checks;
- HttpOnly SameSite viewer session, origin checks, and no permissive CORS;
- strict request/event/batch/query/depth/time/disk bounds;
- complete schema validation without lossy coercion;
- case/source/run/attempt ownership at API and database layers;
- read-only path-confined spool mount with traversal/symlink rejection;
- independent file size/hash verification before activation;
- prepared statements, foreign keys, transactions, and migration integrity;
- text-only rendering and strict Content Security Policy;
- no event-controlled HTML/URL execution;
- no runtime CDN, Docker socket, arbitrary child processes, or provider calls;
- non-root/minimal image, immutable dependencies, SBOM, and image scan;
- owner-private volume/backups and no automatic raw-evidence deletion;
- secret, payload, command-line, and PII-safe logging.

A repository-grounded security threat model is mandatory after the repository
testing design is confirmed and before API/frontend implementation. Any
critical/high parser-boundary, authorization, path, injection, evidence,
session, or secret issue blocks implementation/push.

## 19. Requirements Ledger

| ID | Requirement | Acceptance proof | Status |
| --- | --- | --- | --- |
| APP-R-001 | One container owns API, SQLite, projection, SSE, and static UI | Compose/service journey | Confirmed |
| APP-R-002 | API accepts normalized events/status, not raw EVTX | OpenAPI negative/positive tests | Confirmed |
| APP-R-003 | Endpoint placeholder appears at registration | API/browser E2E | Confirmed |
| APP-R-004 | Completed files populate while acquisition remains open | Cross-part E2E | Confirmed |
| APP-R-005 | Incomplete file events never appear as forensic graph facts | Activation integration/browser tests | Proposed |
| APP-R-006 | Every PUT is transactional and idempotent | Duplicate/conflict/crash tests | Proposed |
| APP-R-007 | Mounted source hash is independently verified before activation | Path/hash integration tests | Proposed |
| APP-R-008 | SQLite state is migration-built, restart-safe, and rebuildable | Clean migration/backup/rebuild proof | Proposed |
| APP-R-009 | OCSF/unsupported union is validated without lossy coercion | Schema fixtures | Proposed |
| APP-R-010 | Sysmon identity is exact by endpoint/ProcessGuid | Projection tests | Confirmed |
| APP-R-011 | Security PID correlation is conservative and ambiguity-preserving | PID-reuse fixtures | Confirmed |
| APP-R-012 | Phase 1 does not silently merge cross-provider entities | Arrival-order tests | Proposed |
| APP-R-013 | Every forensic process/relationship reaches exact active event evidence; placeholder Hosts reach registration receipts and disclose no active event evidence | API/browser drill-down | Confirmed |
| APP-R-014 | Host islands and process nodes remain stable across updates | Seeded browser assertions | Confirmed |
| APP-R-015 | Start-only never means running and warning color never means malicious | Copy/visual tests | Confirmed |
| APP-R-016 | Display caps aggregate rather than omit or freeze | Query/browser performance proof | Proposed |
| APP-R-017 | SSE is replayable and resync-safe | Cursor/expiry integration tests | Proposed |
| APP-R-018 | Every Phase 1 user action is keyboard/touch accessible | Playwright matrix | Confirmed |
| APP-R-019 | UI meets exact responsive/overflow/focus/reduced-motion contract | Visual/accessibility E2E | Proposed |
| APP-R-020 | Service is loopback-only and authenticated | Network/auth negative tests | Proposed |
| APP-R-021 | No event value executes as browser content | XSS/CSP tests | Proposed |
| APP-R-022 | New entity types can extend the registry without changing evidence provenance | Architecture/contract tests | Confirmed |
| APP-R-023 | Future Rust uses the same event contract without app changes | Contract-test producer | Confirmed |
| APP-R-024 | Implementation and proof remain local/containerized | Gate evidence | Confirmed |
| APP-R-025 | Source registration is bound to an exact mounted receipt and deterministic source ID | Receipt/mount contract tests | Proposed |
| APP-R-026 | Every PUT retains a durable original idempotency receipt | State-transition replay tests | Proposed |
| APP-R-027 | Security stop-first/start-first permutations converge through explicit aliases | Arrival-permutation projection/browser tests | Proposed |
| APP-R-028 | Case state is total across empty, multi-endpoint, superseded, conflict, storage, and resync states | Reducer/API/browser matrix | Proposed |
| APP-R-029 | Container root, privilege, egress, resource, data, and evidence-mount boundaries are enforced | Runtime negative tests | Proposed |
| APP-R-030 | Initial/branch/table/inspector loading, error, stale-response, and Retry view behavior is explicit | Browser request-state tests | Proposed |

## 20. Shared Understanding Contract

### Confirmed

- Part 2 is a separate containerized application.
- The same container contains the event API and visual display.
- HostHunter sends events and status as acquisition progresses.
- The first graph shows beautiful process start/stop nodes.
- Adding endpoints progressively adds stable host islands.
- Later models must support audit, logon, permission, and related entities.
- Rust and larger-scale parsing remain outside Part 2 Phase 1.
- This document is a plan only.

### Proposed defaults awaiting explicit confirmation

- one new HostHunterForensicsApp repository;
- one local non-root application container and one SQLite volume;
- first runtime qualification on native linux/arm64 under Apple Silicon Docker
  Desktop;
- an enforced hardened runtime with only /data writable, bounded /tmp, no
  capabilities/egress, and explicit resource ceilings;
- a read-only hosthunter-evidence-v1:/evidence mount exposing only the
  dedicated evidence subtree;
- OCSF 1.9.0 plus HostHunter provenance as the atomic event contract;
- file-level atomic graph activation;
- HostHunter creates/upserts the forensics case UUID;
- HostHunter keeps the clear producer token in Keychain and Part 2 receives
  only its scoped verifier;
- one loopback local investigator with authenticated writes and viewer session;
- React plus Sigma.js/Graphology for the graph after Phase 0 validation;
- Host and ProcessInstance as the only first entity types;
- no Phase 1 cross-provider process merge;
- no browser-side acquisition/retry/delete controls;
- deterministic explainable anomaly cues, logons, permissions, search,
  timeline, annotations, and reports are deferred.

### Open technical validations

- backend framework and SQLite driver;
- exact separate local viewer bootstrap/login and recovery UX;
- current graph-library rendering/interaction behavior;
- Docker Desktop read-only mount/hash performance;
- SQLite ingest/query concurrency and disk thresholds;
- accepted maximum time from first verified process-relevant file to graph
  activation;
- final measured display/query/SSE retention budgets.

### Implementation gate

The implementation agent must ask:

Please confirm the Part 2 Shared Understanding Contract is accurate, or
correct what is still wrong. I will not create the repository or container
until it is confirmed.

## 21. Implementation Phases

### Phase APP-0 - Contract And Repository Design

1. Confirm section 20 and repository name/location.
2. Run $repo-testing-setup and stop at its DRAFT - not confirmed repository
    testing design.
3. Confirm tooling matrix, critical paths, E2E workflow inventory, hook/gate
    model, reports, and local container commands.
4. Freeze OpenAPI, JSON Schemas, problem codes, canonical identity/digest
    vectors, OCSF version, request limits, and v1 migration model with Part 1.
5. Select the backend/SQLite stack from current authoritative evidence.
6. Validate graph library, read-only mount, SQLite budgets, auth bootstrap,
    file-activation latency, and performance targets.
7. Run $feature-design-preflight and write the formal
    $security-threat-model.
8. Run $user-action-coverage-review before frontend edits.

Exit: confirmed testing design, frozen contracts, measured limits, and no
critical/high blocker.

### Phase APP-1 - API And Persistence

- implement auth/session bootstrap;
- implement OpenAPI validation and stable problem responses;
- implement clean SQLite migrations and state machines;
- implement transactional/idempotent mutation resources;
- implement independent spool verification;
- implement bounded read APIs, health, readiness, logs, and metrics.

Exit: contract, migration, auth, idempotency, path/hash, crash, pressure, and
backup integration tests pass.

### Phase APP-2 - Projection And Live Updates

- implement source-event storage and active-run selection;
- implement Host/ProcessInstance identities and evidence observations;
- implement Sysmon exact and Security conservative lifecycle correlation;
- implement parent/containment relationships and truthful ambiguity;
- implement bounded contributions, atomic activation, revisions, deltas,
  outbox, SSE replay, expiry, and resync.

Exit: clean/empty/warning/failed/reprocessed/two-endpoint projection journeys
pass with complete provenance.

### Phase APP-3 - Visual Investigation Experience

- implement the full-viewport host-island graph and custom process nodes;
- implement deterministic incremental layout, unresolved shelf, aggregates,
  controls, status rail, and inspector;
- implement the synchronized semantic table and all keyboard/touch/focus
  behavior;
- implement responsive overlays/drawers/sheets and reduced-motion/high-contrast
  behavior;
- cover all user actions, states, copy, viewports, visual quality, and budgets.

Exit: browser, accessibility, screenshot, overflow, and performance evidence
passes.

### Phase APP-4 - Cross-Part And Operational Proof

- integrate the real HostHunter producer;
- prove endpoint registration before files;
- prove files activate progressively before acquisition seal;
- prove second endpoint stability and mixed outcomes;
- prove API/container/viewer restart, duplicate/replay, SSE resync, backup,
  image replacement, and rebuild from immutable evidence;
- document local start/stop/update/backup/restore/rebuild/rollback operations.

Exit: the coordination index's end-to-end contract passes.

### Phase APP-5 - Release Qualification

- reconcile requirements, tests, user actions, migrations, and non-goals;
- run $test-readiness-preflight and focused changed-scope coverage;
- run the canonical full local container gate;
- before push, run changed-scope threat review, gitleaks, dependency audit,
  SBOM/image scan, production build, and slim pre-push lanes;
- record exact image/contract/migration versions and rollback compatibility.

GitHub performs no validation rerun.

## 22. Testing And Proof

Repository-wide unit coverage is at least 90 percent for statements, branches,
functions, and lines. New/material logic targets at least 95 percent
changed-scope coverage with meaningful assertions.

### Unit

- schema validation and canonical golden vectors;
- mounted receipt/source-ID/expected-set validation;
- Content-Digest, Idempotency-Key, HostHunter-Attempt-Id, and stable problem
  mapping;
- auth scopes, ownership, token verification, session, CSRF, and redaction;
- state-machine transitions and idempotency;
- original PUT-receipt replay after the underlying state becomes terminal;
- source/run/attempt/batch completion invariants;
- process identity, exact/heuristic/ambiguous correlation, PID reuse, and
  invalid time order;
- Security stop-first alias/supersession and every arrival permutation;
- registration-backed Host versus event-backed provenance;
- parent/containment projection and evidence references;
- graph stable IDs, aggregates, revisions, and deltas;
- SSE cursor, retention, and resync;
- status precedence and user-facing copy;
- total multi-endpoint/current-lineage reducer, including all-empty,
  nondeterministic, storage, and resync states;
- query, event, batch, and disk limits.

### Integration

- clean database creation from committed migrations;
- migration upgrade, restart, online backup, restore, and compatible rollback;
- identical/conflicting PUT, missing/out-of-order sequence, empty run, warning,
  failure, retry, and reprocessing;
- durable receipt replay for every PUT, including completion after SUCCEEDED;
- acquisition completion before individual sources and expected-set
  reconciliation;
- missing/mismatched transport headers and bounded problem responses;
- source receipt digest/ID mismatch, path traversal, symlink, hash race,
  read-only/wrong/unavailable mount, UID/mode, and changed file;
- API commit/crash ambiguity and producer replay;
- bounded staging plus file-level atomic activation;
- prior active run retained after failed replacement;
- active-observation reference support and affected-key rebase after concurrent
  activation;
- Sysmon/Security arrival order and no Phase 1 cross-provider coalescing;
- Security 4689-first provisional alias convergence with coordinate/selection
  metadata;
- exact, heuristic, ambiguous, start-only, stop-only, and invalid-order cases;
- two endpoints with mixed ready, warning, empty, deferred, and failed files;
- graph delta add/remove, per-case retention, bounded multi-revision
  continuation, oversized-activation resync, cursor mismatch, SSE expiry, and
  full resync;
- writer saturation, disk pressure, query caps, and graceful shutdown;
- producer-token verifier rotation/revocation and missing-Keychain recovery
  contract;
- future-producer contract stub accepted without server changes.

### Browser/E2E

Cover every action in section 15 plus:

- every exact state trigger and precedence in section 14;
- sealed all-empty, mixed ready/empty, two-endpoint mixed state, recovered
  acquisition lineage, NONDETERMINISTIC, storage refusal, and Resyncing;
- endpoint placeholder resolving to hostname without movement;
- placeholder inspector registration provenance and No event evidence active
  yet copy;
- current-file staged counts changing while graph revision/nodes do not;
- successful atomic activation and failed-file nonactivation;
- two endpoints and concurrent source updates;
- matched exact/heuristic, start-only, stop-only, ambiguous,
  supported-incomplete, and invalid-time-order visuals;
- every Host ingestion-ring token and retained
  lifecycle-plus-completeness combination in legend, table, high contrast, and
  screenshots;
- start-only to matched and unresolved to parent-resolved updates without node
  movement;
- Security 4689-first to canonical alias while selection/focus/coordinate and
  evidence links transfer;
- stop-only 4689 keeps process account unknown and shows termination actor;
- unsupported target in warnings/evidence but never as a process node;
- exact evidence drill-down for node and edge;
- aggregate count equal to hidden query results;
- no camera stealing and Follow updates on/off, including a stop-only
  activation that updates existing nodes but adds none;
- two-pixel stability across activation, endpoint addition, reconnect, resync,
  and seeded same-viewport reload;
- canvas/table selection parity;
- keyboard/touch selection of containment and each parent-edge type plus
  explicit branch expand/collapse;
- inspector focus transfer/restoration from canvas, table, relationship, and
  toolbar, including retained and delta-removed targets;
- closed Graph data hidden/inert and narrow Legend/Graph data/Inspector mutual
  exclusion without nested focus traps;
- initial/branch/table/inspector loading, unauthorized/not-found, error, Retry
  view, abort, and stale-response suppression;
- one live-region announcement per endpoint/file activation;
- 44 by 44 controls and full-value keyboard/hover disclosure;
- keyboard-only, touch, high-contrast, and reduced-motion journeys;
- long hostname, path, command, user, and hash stress;
- deterministic selected-host and case-wide multi-endpoint progress counters;
- no document overflow at all nine required viewports, including the 767/768
  layout boundary;
- deterministic screenshots reviewed for hierarchy, overlap, label collision,
  edge direction, selection/focus, inspector occlusion, contrast, and density;
- truthful copy: start-only never says running and Ready never claims total
  endpoint knowledge.

### Security And Supply Chain

- formal threat model and critical/high remediation;
- gitleaks through the repo-root wrapper;
- dependency and licence audit;
- SBOM and runtime image scan by immutable image digest;
- token/authz/CSRF/origin negative tests;
- XSS/CSP/text-only evidence tests;
- filesystem/path/mount and resource-limit tests;
- runtime proof that root is read-only, only /data and bounded /tmp are
  writable, all capabilities are dropped, no-new-privileges is active,
  outbound access is denied, and PID/memory/CPU ceilings fail safely;
- negative proof that /evidence excludes HostHunter databases, audit material,
  target profiles, known_hosts, SSH keys, ledger keys, and clear tokens;
- secrets absent from image layers, environment dumps, logs, reports, and
  browser storage.

### Performance

Measure and freeze:

- ingest transaction latency and writer queue;
- staged/activation latency and graph-delta size;
- SQLite size, backup, restore, and bounded query latency;
- SSE delivery, replay, expiry, and resync;
- initial graph load, pan/zoom, selection, expansion, and delta application.

Provisional visual targets on representative Apple Silicon hardware:

- at least 50 frames per second during ordinary pan/zoom at display cap;
- selection/inspector feedback within 100 milliseconds;
- graph delta applied within 500 milliseconds of receipt;
- no main-thread layout task over 50 milliseconds;
- every over-budget result represented by a truthful aggregate.

## 23. Parallel Work

Parallel work is applicable only after the contracts, testing design, and final
behavior are frozen.

| Lane | Write ownership | Expected evidence |
| --- | --- | --- |
| Main integration | Contracts, architecture, migrations, acceptance/test ledgers | Contract releases and integrated proof |
| Backend/persistence | API, auth, SQLite adapters | Contract, migration, idempotency, pressure tests |
| Projection | Domain graph/correlation modules | Semantic/provenance fixture suite |
| Frontend | Viewer and browser tests | Action matrix, screenshots, accessibility, performance |
| Security review | Report first; approved remediation only | Threat model and control traceability |
| Validation audit | Tests/reports without production overlap | Coverage, E2E, image, gate reconciliation |

Every worker must receive the same final behavior contract, disjoint file
ownership, mapped focused tests, and notice that other agents are editing.
The main agent owns migration sequencing, contract integration, stale-test
updates, threat review, gitleaks, and final validation.

## 24. Rollout, Rollback, And Operations

- Phase 1 is local-only and opt-in.
- Part 1 and Part 2 versions are independently pinned through the contract
  compatibility matrix.
- Database migrations use expand, deploy, contract sequencing.
- Back up with SQLite's supported online mechanism before migrations.
- Roll back only to an image compatible with the current schema.
- Keep the previous active source run until a replacement activates.
- If derived storage is lost, create a new volume and replay immutable EVTX
  through Part 1 rather than altering evidence.
- Container replacement must preserve the app volume and read-only spool.
- Layout cache may be discarded without evidence loss.
- No automatic raw-evidence, rejected-batch, or historical-run deletion occurs
  until a separately approved retention/prune contract.

Operator documentation must cover:

- start/stop/status;
- token bootstrap/rotation/recovery;
- data/spool/secret mounts;
- health/readiness;
- storage pressure;
- backup/restore;
- migration and image update;
- compatible rollback;
- rebuild from immutable evidence;
- diagnostic bundle creation with redaction.

## 25. Definition Of Done

Part 2 implementation is done only when:

- the plan and repository testing design are confirmed;
- OpenAPI, schemas, canonical vectors, and compatibility rules are versioned;
- the one-container app starts locally with durable SQLite and read-only spool;
- API auth, validation, idempotency, source verification, and activation pass;
- a registered endpoint appears immediately;
- completed files populate while acquisition stays open;
- one and two endpoints retain stable host islands and process positions;
- every forensic process/edge/lifecycle state links to exact active event
  evidence, while placeholder Hosts link to registration receipts and disclose
  the absence of event evidence;
- uncertainty, empty, deferred, warning, failure, and reconnect states are
  truthful;
- every user action, accessibility state, and viewport has browser proof;
- performance/display caps use aggregates without silent omission;
- backup, restart, image replacement, rollback, and rebuild are proven;
- repository and changed-scope coverage thresholds pass locally;
- threat model, secret scan, dependency audit, SBOM/image scan, build, and
  canonical local gate pass;
- the completion report reconciles every APP-R requirement;
- no GitHub test workflow was added or used.

## 26. Implementation-Agent Start Instructions

1. Read this plan, Part 1, the coordination index, and all applicable
    AGENTS.md files.
2. Do not create the repository until section 20 is confirmed.
3. Run $repo-testing-setup first and stop at its required DRAFT testing design
    for confirmation.
4. Maintain acceptance, test, migration, and user-action ledgers.
5. Freeze schemas and golden vectors before production or parallel edits.
6. Run $feature-design-preflight and the formal $security-threat-model.
7. Run $user-action-coverage-review before frontend edits.
8. Use $frontend-design-quality throughout UI implementation and visual proof.
9. Develop focused tests with every implementation slice.
10. Use $test-readiness-preflight before the full gate.
11. Never weaken coverage, bypass hooks, expose secrets, mutate the spool, or
    use GitHub to discover failures.
