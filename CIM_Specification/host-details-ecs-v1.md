# HostHunter ECS Target Host Details v1

Status: CONFIRMED PRODUCT CONTRACT; TECHNICAL QUALIFICATION REQUIRED BEFORE
IMPLEMENTATION

## 1. Purpose

One document represents one immutable HostHunter observation of one managed
Windows or Linux host. It is suitable for direct PowerShell output, encrypted
HostHunter evidence, deterministic replay, and visualizer API ingestion.

The document is ECS-compliant rather than ECS-only. Existing ECS `host.*`,
`host.os.*`, `event.*`, `agent.*`, and `related.*` fields are used where their
semantics match. HostHunter-specific facts without an ECS equivalent are placed
under the proper-name `hosthunter.*` namespace.

Authoritative ECS references checked on 2026-08-28:

- <https://www.elastic.co/docs/reference/ecs/ecs-field-reference>
- <https://www.elastic.co/docs/reference/ecs/ecs-guidelines>
- <https://www.elastic.co/docs/reference/ecs/ecs-host>
- <https://www.elastic.co/docs/reference/ecs/ecs-os>
- <https://www.elastic.co/docs/reference/ecs/ecs-agent>
- <https://www.elastic.co/docs/reference/ecs/ecs-event>
- <https://www.elastic.co/docs/reference/ecs/ecs-custom-fields-in-ecs>

## 2. ECS envelope

| Contract field | Type | Rule |
| --- | --- | --- |
| `@timestamp` | RFC 3339 UTC date-time | Time the endpoint observation was made |
| `ecs.version` | keyword | Exactly `9.5.0` for contract v1 |
| `event.id` | UUID | Immutable observation and HTTP idempotency identity |
| `event.kind` | keyword | `asset` |
| `event.category` | keyword array | Exactly `host` |
| `event.type` | keyword array | `info` for complete/partial; `error` for unavailable/failed |
| `event.action` | keyword | `host-details-collected` or `host-details-collection-failed` |
| `event.dataset` | keyword | `hosthunter.host_details` |
| `event.module` | keyword | `hosthunter` |
| `event.provider` | keyword | `HostHunter` |
| `event.created` | RFC 3339 UTC date-time | Controller normalization time; never before `@timestamp` |
| `event.hash` | lower-case SHA-256 hex | Digest of the finite canonical remote result before ECS normalization |
| `event.outcome` | keyword | Omitted for informational observations; `failure` for failed observations |
| `agent.id` | UUID | Stable HostHunter controller-installation identifier |
| `agent.name` | keyword | Human-readable controller name, normally `hosthunter-controller` |
| `agent.type` | keyword | `hosthunter` |
| `agent.version` | version string | Exact producing HostHunter module version |

The visualizer sets its own receipt time in persistence. It must not replace
`@timestamp` or `event.created` with API receipt time.

## 3. ECS and HostHunter field mapping

| Requirement | Canonical field | Type | Collection rule |
| --- | --- | --- | --- |
| Stable endpoint identity | `host.id` | keyword | Opaque HostHunter ID; never hostname/IP alone |
| Hostname | `host.hostname` | keyword | Exact endpoint-reported hostname |
| FQDN | `host.name` | keyword | Lower-case explicitly reported FQDN; omit if unavailable |
| Confirmed domain | `host.domain` | keyword | Populate only for confirmed domain membership |
| Host addresses | `host.ip` | IP array | Unique non-loopback unicast addresses |
| Architecture | `host.architecture` | keyword | Reported OS architecture |
| OS family | `host.os.type`, `host.os.family` | keyword | ECS values where defined |
| OS product | `host.os.name`, `host.os.full` | keyword | Reported product and full display value |
| OS version | `host.os.version` | keyword | Raw reported version |
| Target label/address/port | `hosthunter.target.*` | object | HostHunter connection metadata, never stable identity |
| Identity strategy | `hosthunter.identity.*` | object | Opaque identity derivation and match status; no raw native ID |
| Domain/workgroup state | `hosthunter.membership.*` | object | `domain`, `workgroup`, `none`, or `unknown` |
| Directory role | `hosthunter.membership.directory_role` | keyword | Explicit role; never inferred from hostname |
| OS build and edition | `hosthunter.os.*` | object | Exact reported values |
| Manufacturer/model/CPU/memory | `hosthunter.hardware.*` | object | Explicit system facts, byte units for memory |
| Interface-qualified IP data | `hosthunter.network.interfaces` | object array | Interface name plus finite address list |
| Boot time | `hosthunter.boot.time` | RFC 3339 UTC date-time | Explicit boot time, not guessed from an unqualified uptime string |
| Configured time zone | `hosthunter.time_zone.*` | object | Endpoint zone ID and current UTC offset |
| Collection status | `hosthunter.collection.status` | keyword | `complete`, `partial`, `unavailable`, or `failed` |
| Field truth/provenance | `hosthunter.collection.field_results` | object array | Exactly one finite result per attempted canonical field |
| Run identity | `hosthunter.collection_run.id` | UUID | Active HostHunter/visualizer run |
| Source method | `hosthunter.provenance.*` | object | Engine operation, transport, controller platform, and source methods |
| Audit link | `hosthunter.audit.*` | object | Existing HostHunter batch and invocation IDs |
| Search pivots | `related.ip` | IP array | Copy of unique `host.ip` values when present |

`event.timezone` is not used for the endpoint's configured zone because ECS
defines it as parsing context for an event timestamp. `host.boot.id` may be
populated later for a qualified Linux boot UUID, but it does not replace the
required boot-time observation.

## 4. Missing and partial data

Missing target facts are allowed. A missing field is omitted from its ECS or
`hosthunter.*` value location and represented exactly once in
`hosthunter.collection.field_results` with one of:

- `unsupported`
- `access_denied`
- `not_reported`
- `not_applicable`
- `collection_failed`

Observed fields use `status: observed`, the field's observation timestamp, and
its source method. The same field path must not occur twice. Free-text detail
is optional, bounded, inert, redacted, and must never contain credentials.

`complete` means all contract fields applicable to the platform were observed
or explicitly `not_applicable`. `partial` means at least the stable host ID and
some truthful facts exist, while one or more applicable facts are absent.
`unavailable` means the authenticated host was identified but no useful detail
beyond identity/target context could be collected. `failed` means the fixed
collection phase failed and no new host snapshot is activated.

The visualizer derives `ready`, `partial`, and `stale` presentation states from
the latest accepted observation. `stale` and `registering` are not producer
collection results and are therefore not stored as observation status values.

## 5. Stable endpoint identity

HostHunter obtains a platform instance identifier when permitted, normalizes it
without logging it, and derives an opaque ID with a dedicated controller-side
HMAC-SHA256 subkey. Candidate sources are Windows machine-instance identity and
Linux `/etc/machine-id`. The raw identifier is never returned by the cmdlet,
sent to the visualizer, written to ordinary logs, or used as an API identifier.

If a qualified native identifier is unavailable, HostHunter creates and
persists a random opaque endpoint ID. Hostname, target name, connection address,
FQDN, domain, and SSH fingerprint are never sufficient identity by themselves.

Target removal deletes credentials and the active target mapping but retains a
minimal authenticated identity record. Re-adding a machine reuses the endpoint
ID only when protected identity evidence matches exactly. Conflicting or
ambiguous evidence creates a new endpoint ID and records the mismatch; it never
silently merges nodes.

## 6. Collection sources

The implementation must use a fixed, versioned PowerShell collection script,
not operator-provided command text. It runs through
`Invoke-HHManagedHostOperation` and the sole private SSH adapter.

| Platform | Preferred sources | Intended fields |
| --- | --- | --- |
| Both | `.NET Environment`, `RuntimeInformation`, `NetworkInterface`, `TimeZoneInfo` | Hostname, OS/architecture fallback, interfaces, time zone |
| Windows | `Win32_ComputerSystem` | DNS hostname, domain/workgroup, role, manufacturer, model, logical processors, physical memory |
| Windows | `Win32_OperatingSystem` | Caption, version, build, edition/SKU qualification, architecture, boot time |
| Linux | `/etc/os-release` or `/usr/lib/os-release` | Distribution family/name/version/edition-like variant |
| Linux | `/proc/meminfo`, `/proc/stat` | Total memory and explicit boot-time source |
| Linux | `/sys/class/dmi/id/*` with platform fallbacks | Manufacturer and model when available |
| Linux | `/etc/machine-id` | Protected identity input only; never API data |

Implementation qualification must prove each source under a standard-user
PowerShell 7/OpenSSH session on the supported Windows and Linux fixtures. A
source requiring elevation must return `access_denied` rather than triggering
privilege escalation or failing unrelated fields.

Primary platform references:

- <https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem>
- <https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem>
- <https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.runtimeinformation>
- <https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.networkinterface.getallnetworkinterfaces>
- <https://learn.microsoft.com/en-us/dotnet/api/system.timezoneinfo.local>
- <https://www.freedesktop.org/software/systemd/man/latest/os-release.html>
- <https://www.freedesktop.org/software/systemd/man/latest/machine-id.html>
- <https://www.kernel.org/doc/html/latest/filesystems/proc.html>

## 7. Cmdlet and engine behavior

### `Set-HHTarget`

After trust and authenticated PowerShell identity validation, the existing
`ValidateTarget` engine strategy performs the fixed host-details phase in the
same managed-host session. Truthful partial results are accepted. Host-details
absence never rolls back an otherwise valid target. The target result exposes
the collection status and observation ID, and HostHunter records the complete
normalized document as encrypted, authenticated evidence.

### `Get-TargetHostDetails`

Proposed signature:

```powershell
Get-TargetHostDetails [[-Name] <string[]>] [-Reason <string>] [-CaseId <string>]
```

- No `-Name`: collect every active target.
- `-Name`: collect one to eight saved targets.
- Every call is a live refresh; it never silently returns cached data.
- The public cmdlet validates parameters and calls
  `Invoke-HHManagedHostOperation -Operation GetHostDetails` exactly once.
- The engine registers durable intent, arms each fixed phase, opens the sole
  SSH transport path, captures finite streams, normalizes the result, records
  one terminal outcome, and returns one typed observation result per target.
- There are no automatic remote retries. An uncertain dispatch remains
  `Unknown` and is never redispatched.

The five existing host-facing operations retain their semantic labels. The new
operation is not relabelled as `InvokeCommand` and does not call the public
`Invoke-HHCommand` cmdlet.

## 8. Visualizer ingest behavior

The recommended API stores immutable observations with an idempotent `PUT`:

```text
PUT /api/v1/collection-runs/{collection_run_id}/host-observations/{event_id}
```

The path IDs must equal `hosthunter.collection_run.id` and `event.id` in the
body. The producer sends a lower-case SHA-256 digest of the exact UTF-8 request
bytes. A new observation returns `201`; an identical replay returns `200`; the
same event ID with different bytes returns `409` and never changes stored data.

The visualizer validates authentication, body size, content digest, JSON Schema,
path/body identities, timestamp ordering, field-result uniqueness, and
status/value consistency before one transaction stores and activates the
observation. Invalid or failed writes cannot partially update the host node.

HostHunter records the observation before delivery. One failed API attempt
does not alter the cmdlet's managed-host verdict and does not cause an inner
retry loop. Later automatic synchronization replays the same immutable event
ID and bytes through a separately bounded delivery sweep.

## 9. Security and privacy requirements

- The visualizer producer credential is write-only and limited to collection
  runs and host observations.
- The visualizer cannot reach managed hosts, HostHunter credentials, HostHunter
  SQLite, SSH keys, audit anchors, or PostgreSQL through the producer API.
- Host-controlled strings are bounded and rendered only as inert text.
- Schema objects reject undeclared properties and overlong arrays/strings.
- The API is reachable only on the private producer Docker network; PostgreSQL
  remains on its separate private network with no published host port.
- A malicious endpoint can lie about its own metadata. Provenance shows what
  was observed; the visualizer must not present the values as directory truth.
- API acceptance proves schema/integrity, not the truth of endpoint claims.
- Logs and problem responses contain identifiers and bounded reason codes, not
  full payloads or credentials.

## 10. Compatibility

Contract v1 accepts ECS `9.5.0` exactly. A later ECS or HostHunter schema uses a
new contract version and golden fixtures. Existing v1 documents remain readable
during an expand/deploy/contract migration. Producers and consumers must reject
unsupported major versions with a machine-readable error; they must not coerce
unknown fields or reinterpret prior semantics.
