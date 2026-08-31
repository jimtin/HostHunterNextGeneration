# HostHunter Collected Data Structures v1

Status: **NORMATIVE SPECIFICATION DRAFT - IMPLEMENTATION MUST BE RECONCILED**
Date: 2026-08-28
JSON Schema dialect: 2020-12
Encoding: UTF-8 JSON
Time format: RFC 3339 UTC
ECS baseline for host/process documents: 9.5.0

## 1. Contract Authority

This document defines the information HostHunter collects and the structures
the HostHunter Visualizer accepts. The same document must exist in both
repositories. Neither implementation may add, rename, infer, or reinterpret a
wire field without a versioned contract change.

Machine-readable JSON Schema controls payload shape. OpenAPI controls HTTP
behavior. This document controls field meaning. A disagreement between them is
a blocking contract defect.

## 2. Structures And Delivery Phases

| ID | Structure | Phase | Purpose | Producer route |
| --- | --- | --- | --- | --- |
| DS-001 | Collection run activation | 1 | Explicitly create/replay the active mission | `PUT /api/v1/collection-runs/{collection_run_id}` |
| DS-002 | Producer status | 1 | Non-mutating authentication, compatibility, readiness, and active mission proof | `GET /api/v1/producer/status` |
| DS-003 | Host details observation | 1 | One immutable observation of one endpoint | `PUT /api/v1/collection-runs/{collection_run_id}/host-observations/{event_id}` |
| DS-004 | Host field result | 1 | Explain how each attempted host fact was obtained or why it is absent | Embedded in DS-003 |
| DS-005 | Canonical forensic record | 2+ | One immutable registered forensic event or state observation | `PUT /api/v1/collection-runs/{collection_run_id}/events/{event_id}` |
| DS-006 | Ingest receipt | 1 | Prove created/replayed acceptance and exact-byte digest | API response |
| DS-007 | Problem document | 1 | Return bounded machine-readable failures | API response |
| DS-008 | Operator host summary/detail | 1 | Bounded derived browser read model | Operator API only; never producer input |
| DS-009 | Operator process tree/timeline window | 2 | Bounded derived browser read model with correlation disclosure | Operator API only; never producer input |
| DS-010 | Windows event collection receipt | 2+ | Bounded cmdlet result, cursor continuity, and explicit collection gaps | Controller/operator result only; never producer input |

DS-005 is the single forensic-information record route, but it is not an
arbitrary JSON or raw-log bucket. Every accepted event type needs a registered
canonical CIM schema, provenance rules, size limits, fixtures, and version.

## 3. Common Rules

Every producer document must:

- reject undeclared properties;
- carry an exact schema version;
- use lower-case UUID text where a UUID is required;
- use an opaque stable HostHunter endpoint ID, never hostname/IP as identity;
- preserve source event time separately from controller collection/creation time;
- omit unknown optional values rather than invent placeholders;
- bound every string, array, object, and request body;
- contain no password, key, token, SSH fingerprint, raw native machine ID,
  database secret, audit key/anchor, or browser credential;
- be recorded by HostHunter before API delivery;
- be replayed only with the same resource ID and exact request bytes.

For writes, `X-HostHunter-Content-SHA256` is the lower-case SHA-256 digest of
the exact UTF-8 request body. Path identities must equal body identities.

## 4. DS-001 Collection Run Activation

Normative schema: `schemas/collection-run.v1.schema.json`.

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `schema_version` | constant `1.0.0` | Yes | Payload contract |
| `collection_run_id` | UUID | Yes | Mission identity |
| `started_at` | RFC 3339 date-time | Yes | Operator mission start time |
| `producer.name` | constant `HostHunter` | Yes | Producer identity |
| `producer.version` | bounded version string | Yes | Exact HostHunter version |

A restart never creates this document automatically. A different run is
created only by explicit operator choice. An identical replay is harmless.

## 5. DS-002 Producer Status

Normative schema: `schemas/producer-status.v1.schema.json`.

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `status` | constant `ready` | Yes | API and persistence are ready |
| `service` | constant `hosthunter-visualizer` | Yes | Prevents connecting to the wrong service |
| `api_version` | version | Yes | Producer API compatibility |
| `collection_run_schema_version` | version | Yes | DS-001 compatibility |
| `host_observation_schema_version` | version | Yes | DS-003 compatibility |
| `process_event_schema_version` | constant `1.0.0` | Yes | Registered `process.start` contract |
| `registered_forensic_schemas` | array of name/version/kind objects | No | Authoritative runtime-accepted forensic schemas when present |
| `active_collection_run_id` | UUID or null | Yes | Current mission without investigation read access |

This structure grants no host-detail, investigation, operator-session, or
database read capability. `registered_forensic_schemas` is an additive,
backward-compatible capability. When absent, the legacy process-event field
advertises only `process.start/1.0.0`; producers must not infer support for any
other schema.

## 6. DS-003 Host Details Observation

Normative schema: `schemas/host-details-observation.v1.schema.json`. The
existing ECS mapping remains normative for detailed constraints.

### 6.1 Observation envelope

| Field | Required | Meaning |
| --- | --- | --- |
| `@timestamp` | Yes | Endpoint observation time |
| `ecs.version` | Yes | Exact ECS baseline |
| `event.id` | Yes | Immutable event/idempotency identity |
| `event.kind/category/type/action/dataset/module/provider` | Yes | Fixed host-details classification |
| `event.created` | Yes | HostHunter normalization time |
| `event.hash` | Yes | Digest of the finite canonical remote result |
| `agent.id/name/type/version` | Yes | Producing HostHunter installation/version |
| `host.id` | Yes | Stable opaque endpoint identity |
| `hosthunter.collection_run.id` | Yes | Active mission identity |
| `hosthunter.collection.status` | Yes | `complete`, `partial`, `unavailable`, or `failed` |

### 6.2 Fundamental host identity

| Fact | Canonical field | Rule |
| --- | --- | --- |
| Stable endpoint ID | `host.id` | Required opaque `hh_...` ID |
| Hostname | `host.hostname` | Explicit endpoint-reported value |
| FQDN | `host.name` | Explicit lower-case FQDN; omit when unavailable |
| Target name/address/port | `hosthunter.target.*` | Connection metadata, never stable identity |
| Identity strategy | `hosthunter.identity.*` | Discloses strategy/status without raw native ID |

### 6.3 Membership

| Fact | Canonical field | Rule |
| --- | --- | --- |
| Membership type | `hosthunter.membership.type` | `domain`, `workgroup`, `none`, or `unknown` |
| Membership name | `hosthunter.membership.name` | Explicit reported domain/workgroup only |
| Directory role | `hosthunter.membership.directory_role` | Explicit endpoint fact only |
| Confirmed domain | `host.domain` | Present only when membership is confirmed domain |

Process events, FQDN, DNS suffix, IP, and naming patterns must never populate
membership. Missing membership is `unknown`.

### 6.4 Operating system and architecture

| Fact | Canonical field |
| --- | --- |
| OS type/family | `host.os.type`, `host.os.family` |
| Product name/full display name | `host.os.name`, `host.os.full` |
| Version | `host.os.version` |
| Edition | `hosthunter.os.edition` |
| Build | `hosthunter.os.build` |
| Architecture | `host.architecture` |

### 6.5 Hardware, network, and time

| Fact | Canonical field | Rule |
| --- | --- | --- |
| Manufacturer/model | `hosthunter.hardware.manufacturer/model` | Explicit platform facts |
| Logical processors | `hosthunter.hardware.logical_processor_count` | Integer count |
| Physical memory | `hosthunter.hardware.total_memory_bytes` | Integer bytes |
| Host IPs | `host.ip` | Unique non-loopback unicast addresses |
| Interfaces | `hosthunter.network.interfaces` | Interface-qualified finite addresses |
| Boot time | `hosthunter.boot.time` | Explicit time, never inferred from vague uptime |
| Time-zone ID/offset | `hosthunter.time_zone.*` | Endpoint configured zone and observed offset |

### 6.6 Provenance and audit

The document records source method per attempted field, transport, fixed managed
operation, controller platform, target context, observation/creation times, and
HostHunter audit batch/invocation identities. A malicious endpoint can misstate
facts; provenance reports what was observed, not independent truth.

## 7. DS-004 Host Field Result

Each attempted canonical host field appears once in
`hosthunter.collection.field_results`.

| Field | Meaning |
| --- | --- |
| `field` | Canonical field path |
| `status` | `observed`, `unsupported`, `access_denied`, `not_reported`, `not_applicable`, or `collection_failed` |
| `observed_at` | Time of observation when applicable |
| `source_method` | Bounded source method |
| `detail` | Optional bounded inert redacted explanation |

Missing facts are omitted from their value locations and explained here. The
same field path must not occur twice.

## 8. DS-005 Canonical Forensic Record

Normative common schema: `schemas/forensic-event-envelope.v1.schema.json`.
Normative initial event schema: `schemas/process-start.v1.schema.json`.
The producer obligations are defined in
`hosthunter-forensic-event-producer-v1.md`.
The Windows authentication, process-token, and effective-right semantics are
defined in `windows-authentication-and-privilege-records-v1.md`.

The shared envelope accepts immutable source events (`event.kind: event`) and
point-in-time forensic state observations (`event.kind: state`). Every record
still has one immutable identity and one exact registered schema.

### 8.1 Required event identity and timing

| Field | Required | Meaning |
| --- | --- | --- |
| `@timestamp` | Yes | Decoded Windows Security 4688 process start time |
| `ecs.version` | Yes | Exact ECS baseline |
| `event.id` | Yes | Immutable lifecycle event identity |
| `event.action` | Yes | Constant `process-started` |
| `event.type` | Yes | Constant `["start"]` |
| `event.created` | Yes | HostHunter normalization/collection time |
| `host.id` | Yes | Stable endpoint ID |
| `hosthunter.collection_run.id` | Yes | Mission identity |
| `process.pid` | Yes | Decoded decimal PID, scoped to the host and event time |

### 8.2 Process facts

| Field | Required | Rule |
| --- | --- | --- |
| `process.name` | Yes | Reported image/process name |
| `process.entity_id` | No | HostHunter-backed identity derived from a start event or verified PID/start-time pair |
| `process.executable` | Yes | Reported executable path |
| `process.command_line` | No | Reported command line; bounded and access controlled |
| `process.token_elevation` | Yes | Decoded elevation classification |
| `process.integrity_level` | No | Decoded integrity classification when Event 4688 version provides it |
| `process.parent.pid` | Yes | Decoded reported parent PID |
| `process.parent.name` | No | Reported parent image/name |
| `user.id/name/domain/logon_id` | Yes | Decoded new-process security context |
| `hosthunter.process.target_user` | Version 2 only | Decoded target security context |

Version 0 omits command line, integrity, and target-user fields. Version 1 may
include command line but omits integrity and target-user fields. Version 2 may
include every canonical field. Optional source-absent values are omitted; they
are never guessed or represented as encoded native strings.

### 8.3 Source and correlation evidence

| Field | Required | Meaning |
| --- | --- | --- |
| `hosthunter.source.provider` | Yes | Constant `Microsoft-Windows-Security-Auditing` |
| `hosthunter.source.channel` | Yes | Constant `Security` |
| `hosthunter.source.event_code` | Yes | Constant `4688` |
| `hosthunter.source.event_version` | Yes | Integer `0`, `1`, or `2` |
| `hosthunter.source.record_id` | Yes | Stable record identity within source |
| `hosthunter.source.computer` | Yes | Original source computer label |
| `hosthunter.provenance.transport` | Yes | HostHunter acquisition transport/method |
| `hosthunter.provenance.collected_at` | Yes | Controller collection time |
| `hosthunter.provenance.normalizer` | Yes | Exact HostHunter normalizer name/version |

`host.boot.id` and `process.entity_id` are optional correlation identifiers in
the enabled `1.0.0` contract. HostHunter should populate
`host.boot.id` whenever it can assign the record to a boot, and should populate
`process.entity_id` consistently across all records that describe the same
process instance. A bare PID or logon ID is never upgraded to exact identity.

HostHunter performs all EVTX/XML decoding, hexadecimal-to-decimal conversion,
SID/logon/token/integrity normalization, and timestamp normalization before
delivery. Raw EVTX, raw XML, native field bags, encoded PIDs, and undecoded
token or integrity values are invalid input and receive `422`.

The visualizer preserves the immutable accepted document. Matching source
identifiers produce `exact` links. When those identifiers are absent, it may
derive process ancestry using the same active collection run, endpoint, boot
when known, reported parent PID, and closest earlier projected process start.
Multiple plausible candidates yield `ambiguous`; no valid candidate yields
`unresolved`; one defensible fallback candidate yields `derived`. Derived
identities never alter immutable input documents.

### 8.4 Windows authentication and privilege record catalogue

| Schema name | Meaning | Specification status |
| --- | --- | --- |
| `process.start/1.0.0` | Security 4688 process creation | Enabled |
| `process.end/1.0.0` | Security 4689 process termination | Enabled |
| `authentication.session.start/1.0.0` | Security 4624 successful logon | Enabled |
| `authentication.logon.failure/1.0.0` | Security 4625 failed logon | Enabled |
| `authentication.session.end/1.0.0` | Security 4634 session end | Enabled |
| `authentication.session.logoff-initiated/1.0.0` | Security 4647 user logoff intent | Enabled |
| `authentication.explicit-credential-use/1.0.0` | Security 4648 explicit credential attempt | Enabled |
| `authentication.session.special-privileges/1.0.0` | Security 4672 sensitive privileges assigned | Enabled |
| `process.access-token/1.0.0` | Primary process-token privilege state | Enabled |
| `user.effective-rights/1.0.0` | Target-host effective rights and origins | Enabled |

`Enabled` establishes mirrored schemas plus registered immutable Visualizer
validation/storage. Specialized projection remains record-specific and does
not change whether the complete canonical evidence was accepted.

The older HostHunter `process-lifecycle-event.v1.schema.json` and legacy
process-stop fixture remain removed. Their mixed lifecycle model is replaced by
the separately versioned `process.start/1.0.0` and `process.end/1.0.0` records.
The process-end record preserves Security 4689 v0 evidence without inferring
duration, outcome, or stable identity from a reusable PID.

## 9. DS-006 Ingest Receipts

Collection-run receipt fields:

- `status`: `activated` or `replayed`;
- `collection_run_id`;
- exact `content_sha256`;
- `activated_at`;
- `pruned_run_count`.

Event receipt fields:

- `status`: `created` or `replayed`;
- `collection_run_id`;
- `event_id`;
- `host_id`;
- `event_type` and `schema_version` for forensic events;
- `processing_state` for forensic events;
- exact `content_sha256`;
- `received_at`.

A receipt proves durable API acceptance, not completed asynchronous projection
or independent truth of the endpoint claims.

### 9.1 Exact-byte forensic integrity

Forensic records do not contain `event.hash`. The accepted request's exact
UTF-8 bytes are hashed before delivery and returned as lower-case
`content_sha256`; embedding a document digest inside the document would be
recursive. Created and replayed receipts refer to the same immutable bytes.

## 10. DS-007 Problem Documents

Problem responses contain:

- URI-reference `type`;
- bounded `title`;
- HTTP `status`;
- stable machine `code`;
- UUID `correlation_id`;
- optional bounded redacted `detail`.

Required codes include malformed request, digest mismatch, identity mismatch,
unauthorized, forbidden, idempotency conflict, stale/inactive collection run,
payload too large, schema invalid, semantic invalid, capacity exhausted, and
persistence unavailable.

## 11. Derived Browser Structures

Browser structures are not producer contracts and must not be sent back to
HostHunter.

## 12. DS-010 Windows Event Collection Receipt

Normative schema:
`schemas/windows-event-collection-receipt.v1.schema.json`.

The process-start and authentication cmdlets return one bounded receipt per
target. This is controller/operator truth and is never sent through the
forensic event route. It reports the requested window, record counts,
`has_more`, cursor continuity, and every known gap.

- `no_events` with `status: complete`, zero counts, no gaps, and no cursor
  advance means the bounded accessible source contained no matching events. It
  is successful negative evidence, not a failure.
- `audit_disabled` is `unavailable` when the required audit category is proven
  disabled for the entire requested window; it is `partial` when some events
  were preserved but the setting makes the window incomplete.
- `access_denied` is `unavailable` when no source records could be read, or
  `partial` when only part of the requested source was accessible.
- `log_cleared`, `cursor_reset`, and `history_truncated` are explicit gaps. They
  never become an ordinary `no_events` result and never silently claim
  continuity.
- `unsupported_event_version` is `partial` when other records were preserved;
  the unsupported source record is counted as rejected and the cursor does not
  advance past it until the record is explicitly quarantined.
- Cursor mode advances only through the last contiguous canonical record that
  was atomically persisted. Backfill mode never rewinds or advances the normal
  cursor. `has_more` asks the operator to invoke the cmdlet again; it does not
  authorize an automatic loop or retry.

The cursor epoch is a HostHunter-generated UUID for one observed lifetime of
the Windows Security channel. A clear/reset starts a new epoch and creates a
gap receipt linking the old and new cursor states.

Phase 1 host summary contains endpoint ID, optional hostname/FQDN, explicit
membership, bounded OS summary, collection status, observation time, and
freshness. Host detail adds the immutable accepted observation.

Phase 2 process windows contain bounded process-start nodes, disclosed
correlation quality, complete canonical evidence, parent edges, processing
counts/failures, and time/search bounds. They never fabricate stop times.

## 13. Size And Cardinality Limits

- Collection-run, host-observation, and individual process-event requests:
  maximum 262,144 exact bytes before parsing.
- All strings and arrays use schema-specific finite maxima.
- One API resource represents one immutable event.
- Any later batch contract must have its own schema, byte limit, item limit,
  partial-failure rules, and idempotency identity; it must not silently widen
  these v1 routes.

## 14. Compatibility And Change Control

- Producers and consumers reject unsupported major versions.
- New optional semantics require schema, prose, OpenAPI, examples, and contract
  tests in both repositories.
- Breaking changes use a new versioned route/schema and an
  expand/deploy/contract migration.
- Golden fixtures are synthetic and secret-free.
- A contract update is incomplete until corresponding files are byte-compatible
  in HostHunter and HostHunter Visualizer.

## 15. Required Golden Fixtures

Phase 1:

- complete Windows host;
- partial Linux host;
- unavailable host;
- failed host collection;
- unknown membership;
- identical replay and conflicting replay.

Phase 2:

- valid Security 4688 versions 0, 1, and 2;
- valid Security 4624 versions 0, 1, and 2;
- valid Security 4625, 4634, 4647, 4648, and 4672 records;
- a complete primary process-token observation with enabled-state attributes;
- complete, partial, unavailable, and failed process-token observations;
- a complete effective-rights observation with direct and nested-group origins;
- an explicitly unknown policy source and a separately observed GPO/local source;
- failed user identity resolution without a fabricated SID;
- allow/deny logon-right precedence with both assignments retained;
- partial membership or assignment resolution that cannot appear as complete;
- derived and unresolved parent relationships;
- missing version-specific optional values;
- same PID on different hosts;
- out-of-order delivery;
- identical replay and conflicting event/source identity reuse;
- complete, no-event, audit-disabled, access-denied, cleared-log, truncated,
  and unsupported-version collection receipts;
- raw/native/undecoded input rejection.

No fixture may contain real credentials, private hostnames, user data, tokens,
keys, or production evidence.
