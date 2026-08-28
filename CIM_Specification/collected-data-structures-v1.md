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
| DS-005 | Process lifecycle event | 2 | One immutable process start or stop event | `PUT /api/v1/collection-runs/{collection_run_id}/process-events/{event_id}` |
| DS-006 | Ingest receipt | 1 | Prove created/replayed acceptance and exact-byte digest | API response |
| DS-007 | Problem document | 1 | Return bounded machine-readable failures | API response |
| DS-008 | Operator host summary/detail | 1 | Bounded derived browser read model | Operator API only; never producer input |
| DS-009 | Operator process tree/timeline window | 2 | Bounded derived browser read model with correlation disclosure | Operator API only; never producer input |

There is no arbitrary general-log document in v1. New evidence categories need
a named schema, provenance rules, size limits, route, fixtures, and version.

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
| `process_event_schema_version` | version or null | Yes | DS-005 support; null until Phase 2 is enabled |
| `active_collection_run_id` | UUID or null | Yes | Current mission without investigation read access |

This structure grants no host-detail, investigation, operator-session, or
database read capability.

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

## 8. DS-005 Process Lifecycle Event

Normative schema: `schemas/process-lifecycle-event.v1.schema.json`.

### 8.1 Required event identity and timing

| Field | Required | Meaning |
| --- | --- | --- |
| `@timestamp` | Yes | Source process start or stop time |
| `ecs.version` | Yes | Exact ECS baseline |
| `event.id` | Yes | Immutable lifecycle event identity |
| `event.action` | Yes | `process-started` or `process-stopped` |
| `event.type` | Yes | `["start"]` or `["end"]` matching action |
| `event.created` | Yes | HostHunter normalization/collection time |
| `event.hash` | Yes | Digest of finite canonical source event |
| `host.id` | Yes | Stable endpoint ID |
| `hosthunter.collection_run.id` | Yes | Mission identity |
| `process.pid` | Yes | Source PID, scoped to host and boot context |

### 8.2 Process facts

| Field | Required | Rule |
| --- | --- | --- |
| `process.entity_id` | No | Provider-stable process identity when explicitly available |
| `process.name` | No | Reported image/process name |
| `process.executable` | No | Reported executable path |
| `process.command_line` | No | Reported command line; bounded and access controlled |
| `process.args` | No | Finite reported argument array |
| `process.parent.pid` | No | Reported parent PID |
| `process.parent.entity_id` | No | Provider-stable parent identity when available |
| `process.parent.name` | No | Reported parent image/name |
| `process.exit_code` | No | Reported stop exit code |
| `user.id/name/domain` | No | Explicit event user/security context |

A stop event is valid when only its required identity/timing/PID/source fields
are available. A start without a stop remains open. A stop without a matching
start remains unmatched.

### 8.3 Source and correlation evidence

| Field | Required | Meaning |
| --- | --- | --- |
| `hosthunter.source.provider` | Yes | Provider such as Sysmon or Security |
| `hosthunter.source.channel` | Yes | Exact source channel/log |
| `hosthunter.source.event_code` | Yes | Provider event identifier |
| `hosthunter.source.record_id` | Yes | Stable record identity within source |
| `hosthunter.source.computer` | No | Original source computer label |
| `hosthunter.process.boot_id` | No | Qualified boot/session scope |
| `hosthunter.process.source_instance_id` | No | Source-stable process instance ID |
| `hosthunter.process.source_parent_instance_id` | No | Source-stable parent instance ID |
| `hosthunter.provenance.transport` | Yes | HostHunter acquisition transport/method |
| `hosthunter.provenance.collected_at` | Yes | Controller collection time |

Provider-native stable identities are retained as bounded inert identifiers
when safe. PID alone is never a globally stable process identity.

The visualizer's derived correlation uses, in order:

1. explicit source process instance identity;
2. explicit source parent instance identity;
3. otherwise the same host plus boot scope plus PID and closest valid earlier
    unmatched start.

The read model must disclose `source_stable`, `derived`, or `unresolved`
correlation quality. Derived identities never alter immutable input documents.

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
- exact `content_sha256`;
- `received_at`.

A receipt proves API acceptance and persistence, not independent truth of the
endpoint claims.

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

Phase 1 host summary contains endpoint ID, optional hostname/FQDN, explicit
membership, bounded OS summary, collection status, observation time, and
freshness. Host detail adds the immutable accepted observation.

Phase 2 process windows contain bounded process nodes, disclosed correlation
quality, start/stop evidence references, optional open-ended ranges, parent
edges, and pagination/window cursors. They never fabricate absent stop times.

## 12. Size And Cardinality Limits

- Collection-run, host-observation, and individual process-event requests:
  maximum 262,144 exact bytes before parsing.
- All strings and arrays use schema-specific finite maxima.
- One API resource represents one immutable event.
- Any later batch contract must have its own schema, byte limit, item limit,
  partial-failure rules, and idempotency identity; it must not silently widen
  these v1 routes.

## 13. Compatibility And Change Control

- Producers and consumers reject unsupported major versions.
- New optional semantics require schema, prose, OpenAPI, examples, and contract
  tests in both repositories.
- Breaking changes use a new versioned route/schema and an
  expand/deploy/contract migration.
- Golden fixtures are synthetic and secret-free.
- A contract update is incomplete until corresponding files are byte-compatible
  in HostHunter and HostHunter Visualizer.

## 14. Required Golden Fixtures

Phase 1:

- complete Windows host;
- partial Linux host;
- unavailable host;
- failed host collection;
- unknown membership;
- identical replay and conflicting replay.

Phase 2:

- source-stable parent/child start chain;
- start and matching stop;
- start without stop;
- stop without start;
- PID reuse on the same host;
- same PID on different hosts;
- missing command line/user/parent;
- out-of-order delivery;
- identical replay and conflicting replay.

No fixture may contain real credentials, private hostnames, user data, tokens,
keys, or production evidence.
