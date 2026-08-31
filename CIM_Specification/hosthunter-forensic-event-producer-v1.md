# HostHunter Forensic Event Producer Contract v1

Status: **Normative**
Transport: UTF-8 JSON
Envelope: `schemas/forensic-event-envelope.v1.schema.json`
Canonical record catalogue: `windows-authentication-and-privilege-records-v1.md`

## Boundary

HostHunter sends one already-normalized forensic CIM event or state observation
to:

```text
PUT /api/v1/collection-runs/{collection_run_id}/events/{event_id}
```

The route is for forensic activities and artifacts. Collection-run activation
and host-detail observations retain their existing routes. Raw EVTX, XML,
binary evidence, encoded native values, arbitrary field bags, passwords, and
transport/archive metadata are not valid inputs.

Every request uses the producer bearer credential and
`X-HostHunter-Content-SHA256`, calculated over the exact UTF-8 request bytes.
Path identities must equal the canonical body identities. An identical retry
is a replay; reuse of an event ID with different bytes is a conflict.

`content_sha256` in the durable ingest receipt is the only digest of the
complete canonical request document. Forensic records do not contain
`event.hash`: embedding a digest inside the bytes it purports to digest is
recursive and ambiguous. HostHunter records the exact request bytes and their
lower-case SHA-256 before delivery, and the visualizer verifies the header
before parsing or storing them.

## Registered event types

| Name | Version | Initial source | Status |
| --- | --- | --- | --- |
| `process.start` | `1.0.0` | Windows Security Event 4688 v0/v1/v2 | enabled |
| `process.end` | `1.0.0` | Windows Security Event 4689 v0 | enabled |
| `authentication.session.start` | `1.0.0` | Windows Security Event 4624 v0/v1/v2 | enabled |
| `authentication.logon.failure` | `1.0.0` | Windows Security Event 4625 v0 | enabled |
| `authentication.session.end` | `1.0.0` | Windows Security Event 4634 v0 | enabled |
| `authentication.session.logoff-initiated` | `1.0.0` | Windows Security Event 4647 v0 | enabled |
| `authentication.explicit-credential-use` | `1.0.0` | Windows Security Event 4648 v0 | enabled |
| `authentication.session.special-privileges` | `1.0.0` | Windows Security Event 4672 v0 | enabled |
| `process.access-token` | `1.0.0` | Windows primary process token | enabled |
| `user.effective-rights` | `1.0.0` | Target-host effective security policy | enabled |

`enabled` means the schema is registered for immutable validation and storage
through the single event route. It does not imply that every record has a
specialized visual projection; `process.start` retains its process projection,
while `process.end` and the other records remain complete canonical evidence
until bounded read models are added.

`GET /api/v1/producer/status` may add the optional
`registered_forensic_schemas` capability list defined by
`schemas/producer-status.v1.schema.json`. When present, that list is the
authoritative set of schema name/version/kind tuples the running consumer will
accept. HostHunter must not send a tuple absent from the list. When the field
is absent, legacy `process_event_schema_version: 1.0.0` advertises only
`process.start/1.0.0`; no other forensic schema may be inferred. The list is
additive and optional so existing producer-status responses remain valid.

Unregistered names and versions are rejected. Adding a forensic category
requires a schema, semantic rules, bounded fixtures, a processor, a read model,
and operator-display behavior; it never requires a new ingest route.

The `process.access-token` and `user.effective-rights` records are forensic
state observations, not Windows Event Log entries. They use the same eventual
route and validation boundary because they are normalized investigative
evidence. Collection-run activation, producer status, and host observations
remain separate endpoints.

## Windows Security Event 4688 normalization

HostHunter, not the visualizer, parses and decodes the native event. All three
source versions map to the same canonical `process.start/1.0.0` schema.

| Native concept | Canonical field | Rule |
| --- | --- | --- |
| Event time | `@timestamp` | RFC 3339 UTC |
| Boot identity | `host.boot.id` | Source-defined boot identifier when the event can be assigned to a boot |
| New Process ID | `process.pid` | Decoded unsigned integer; native hexadecimal is not sent |
| Process identity | `process.entity_id` | HostHunter-backed stable process instance when available |
| New Process Name | `process.executable` | Complete collected path |
| Executable basename | `process.name` | HostHunter-derived canonical display name |
| Process Command Line | `process.command_line` | Complete collected value; omit only when absent/empty |
| Token Elevation Type | `process.token_elevation` | `full`, `elevated`, `limited`, or `unknown`; native message token is not sent |
| Mandatory Label | `process.integrity_level` | Canonical enum; omit before v2 or when absent |
| Creator Process ID | `process.parent.pid` | Decoded unsigned integer |
| Creator Process Name | `process.parent.executable` and `.name` | v2 only; omit when absent |
| Creator Subject | `user.*` | SID, name, domain, and decimal-string logon ID |
| Target Subject | `hosthunter.process.target_user.*` | v2 only; omit when absent/not applicable |
| Event version | `hosthunter.source.event_version` | Integer `0`, `1`, or `2` retained as provenance |
| EventRecordID | `hosthunter.source.record_id` | Stable bounded source-channel identity |

Version 0 cannot send command line, integrity level, target user, or creator
process name. Version 1 may send command line but not the v2-only fields.
Version 2 may send every canonical field. Command line remains optional because
Windows can omit it when command-line process auditing is disabled.

## Windows Security Event 4689 normalization

Security Event 4689 version 0 maps to `process.end/1.0.0`. It is an immutable
termination event and does not mutate the corresponding process-start record.

| Native concept | Canonical field | Rule |
| --- | --- | --- |
| Event time | `@timestamp`, `process.end` | Identical RFC 3339 UTC values |
| Boot identity | `host.boot.id` | Include only when the event can be assigned to a verified boot |
| Process ID | `process.pid` | Decode the native hexadecimal pointer to an unsigned integer |
| Process identity | `process.entity_id` | Reuse only after verified correlation to a process-start instance |
| Process Name | `process.executable` | Complete collected path |
| Executable basename | `process.name` | HostHunter-derived canonical display name |
| Exit Status | `process.exit_code` | Decode to an unsigned 32-bit integer; do not infer success/failure |
| Subject | `user.*` | SID, name, domain, and decimal-string logon ID |
| Event version | `hosthunter.source.event_version` | Constant integer `0` |
| EventRecordID | `hosthunter.source.record_id` | Stable bounded source-channel identity |

The source does not contain the start time, command line, parent, duration, or
stable process identity. HostHunter must not copy those values from another
record into immutable 4689 evidence. Correlation belongs in derived state.

When Windows supplies a command line, HostHunter preserves the complete value
without content redaction. Command lines are high-value sensitive evidence and
may incidentally contain credentials or tokens; that confidentiality risk is
accepted for this contract. They remain inert bounded strings and must not be
copied into ordinary diagnostics, process arguments, environment variables,
or summary receipts. Dedicated password, hash, ticket, key, token, or other
credential-material fields remain prohibited.

HostHunter must preserve every value it collected by placing it in a declared
canonical field. The contract deliberately has no `raw`, `native`, or
`additional` property. A field that has no CIM definition requires a versioned
schema change before HostHunter collects and sends it.

## Identity and absence

`event.id` is a deterministic RFC 9562 UUIDv5. The namespace is
`7f25f039-42db-597e-a051-b6cf2dee9bdb`. The UTF-8 name is the following exact
line-feed-delimited string, with no trailing line feed:

```text
forensic-source-event/v1
{host.id}
{hosthunter.source.provider}
{hosthunter.source.channel}
{hosthunter.source.event_code}
{hosthunter.source.event_version}
{hosthunter.source.record_id}
{@timestamp}
```

Every value is the exact canonical JSON string or base-10 integer text. This
identity is stable across retry and reprocessing. For point-in-time state
observations, HostHunter assigns and persists `source.record_id` before
normalization; an exact retry reuses the record ID, timestamp, UUID, and bytes.
Hostname, source computer, PID, and EventRecordID are never substitutes for
`host.id`.

`process.entity_id` is a HostHunter-backed process-instance identifier with the
form `hhproc_v1_` plus the lower-case SHA-256 hex of one of these exact UTF-8
names, again without a trailing line feed:

```text
process-start-event/v1
{host.id}
{process.start event.id}
```

or, when no canonical start event exists but PID/start time were read and PID
reuse was checked:

```text
verified-pid-start/v1
{host.id}
{host.boot.id or an empty line}
{process.pid as base-10 text}
{process.start as RFC 3339 UTC}
```

A bare PID never produces `process.entity_id`. HostHunter should populate ECS
`host.boot.id` whenever it can assign a record to one boot, and reuse the same
`process.entity_id` across record types. Neither field is required in the
backward-compatible `1.0.0` schemas; absence prevents identifier-exact links.

HostHunter omits source fields that were not present. It must not fabricate a
command line, target identity, parent executable, integrity level, process
start, duration, domain membership, boot identity, or process identity.

## Semantic validation

JSON Schema validation is necessary but not sufficient. Before persistence and
again at the consumer boundary, semantic validation must reject a record when:

- `event.id` does not recompute from the declared canonical source identity;
- a logon-type ID and canonical name are not an approved pair;
- a 4624 target principal has no decimal `logon_id`;
- privilege names repeat within one 4672, access-token, or rights record;
- a process-token observation marked `complete` has only a reusable PID;
- a group-membership origin path does not begin at the target user or end at
  its `assigned_to` principal;
- a direct rights origin includes a membership path, or a group origin omits it;
- an observed policy source lacks separately collected causal evidence;
- `complete` rights use incomplete membership/assignment resolution, or an
  empty complete result was not positively proven;
- an event-version-specific field appears in a source version that cannot
  supply it; or
- a native placeholder, encoded identifier, raw event bag, or undeclared field
  survives normalization.

Policy evidence obtained only from effective LSA assignment enumeration is
not causal attribution. It must use the explicit unknown policy-source shape.

## Receipt boundary

A `created` or `replayed` receipt proves authentication, validation and durable
immutable storage. It does not prove that asynchronous correlation and visual
projection have completed. The visualizer retries projection from stored CIM
without requiring HostHunter to resend accepted evidence.
