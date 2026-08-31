# HostHunter CIM Specification

Status: **NORMATIVE SPECIFICATION DRAFT - IMPLEMENTATION MUST BE RECONCILED**

- Contract family: `1.x`
- JSON Schema: 2020-12
- ECS baseline: `9.5.0`

This folder is the shared producer/consumer contract between HostHunter and
HostHunter Visualizer. The normative files must remain byte-compatible in both
repositories. Implementation code and historical planning documents do not
override this folder.

## Normative Files

- [Collected data structures](collected-data-structures-v1.md) defines every
  current and planned structure, its meaning, collection rules, source truth,
  correlation limits, and required fixtures.
- [Host-details ECS mapping](host-details-ecs-v1.md) defines the detailed Phase
  1 host observation semantics.
- [Collection-run schema](schemas/collection-run.v1.schema.json) defines
  explicit mission activation.
- [Producer-status schema](schemas/producer-status.v1.schema.json) defines the
  authenticated compatibility/readiness receipt and its optional registered
  forensic-schema capability list.
- [Host-details schema](schemas/host-details-observation.v1.schema.json) defines
  one immutable Phase 1 endpoint observation.
- [Forensic event envelope](schemas/forensic-event-envelope.v1.schema.json)
  defines the common immutable forensic-event fields.
- [Process-start schema](schemas/process-start.v1.schema.json) defines the first
  registered event type: normalized Windows Security Event 4688 versions 0-2.
- [Process-end schema](schemas/process-end.v1.schema.json) defines normalized
  Windows Security Event 4689 version 0.
- [Windows authentication and privilege records](windows-authentication-and-privilege-records-v1.md)
  defines the canonical Security 4624, 4625, 4634, 4647, 4648, and 4672
  mappings, primary process-token privileges, and policy-effective user rights
  with assignment and transitive membership provenance.
- Authentication schemas define successful logon, failed logon, session end,
  user-initiated logoff, explicit credential use, and special-privilege events.
- [Primary process access-token schema](schemas/process-access-token.v1.schema.json)
  defines point-in-time primary-token privilege state.
- [Effective user-rights schema](schemas/user-effective-rights.v1.schema.json)
  defines target-host effective assignments, origin principals, membership
  paths, deny precedence, and observed or explicitly unknown policy sources.
- [Windows event collection receipt](schemas/windows-event-collection-receipt.v1.schema.json)
  defines bounded cmdlet outcomes, cursor continuity, and explicit source gaps.
- [HostHunter forensic producer contract](hosthunter-forensic-event-producer-v1.md)
  defines the producer-side decoding and canonicalization obligation.
- [Producer OpenAPI](openapi/host-details-ingest.v1.openapi.yaml) defines the
  currently frozen Phase 1 status, mission, and host-observation HTTP behavior.
- [Complete Windows example](examples/windows-complete.v1.json) and
  [partial Linux example](examples/linux-partial.v1.json) are synthetic Phase 1
  fixtures.
- Process-start examples for Security Event 4688 versions 0, 1, and 2 and the
  process-end example for Security Event 4689 version 0 are synthetic
  normalized Phase 2 fixtures.
- Authentication and privilege examples are synthetic specification fixtures
  for each canonical record and every supported 4624 source version.

All ten named forensic schemas are registered for validation and immutable
storage through the single Phase 2 event route. `process.start` additionally
has its established projection and browser read model; the other records remain
complete canonical evidence until specialized bounded read models are added.

## Authority Order

1. JSON Schema controls payload shape.
2. OpenAPI controls HTTP behavior for operations it contains.
3. `collected-data-structures-v1.md` and the ECS mapping control semantics.
4. Golden fixtures demonstrate valid examples but do not widen the schemas.

Any disagreement is a blocking contract defect.

## Confirmed Truth Rules

- One opaque stable `host.id` represents one endpoint.
- Hostname and IP address are not stable identity.
- Domain/workgroup membership is explicit endpoint metadata only.
- Missing membership is `unknown` and is never inferred.
- HostHunter records immutable source evidence before API delivery.
- A restart does not create a mission.
- A new mission requires explicit operator choice.
- Stopping visualization pauses publishing and preserves the mission.
- All forensic information uses one event route with registered named schemas;
  it is not arbitrary JSON or raw-log ingest.
- PID alone is not a stable process identity.
- `host.boot.id` and HostHunter-backed `process.entity_id` are the preferred
  correlation identifiers whenever HostHunter can populate them.
- Missing correlation identifiers never justify an exact link; every derived
  relationship is classified as exact, derived, ambiguous, or unresolved.
- The removed legacy `process-lifecycle-event` schema is non-canonical. Its
  mixed lifecycle shapes are superseded by the separate canonical
  `process.start/1.0.0` and `process.end/1.0.0` records.
- A process-end PID alone is not correlated to a process start. HostHunter may
  reuse `process.entity_id` only when it has verified the process instance.
- Process events never populate or alter host membership.
- A user-right assignment never proves that a process token contains or has
  enabled that privilege.
- Unknown policy origin is displayed as unknown and is never guessed.
- Forensic `event.id` uses the fixed UUIDv5 source-identity algorithm; request
  integrity uses exact-byte `content_sha256`, not recursive `event.hash`.
- Complete collected process command lines are retained as accepted sensitive
  evidence. Dedicated credential fields remain prohibited.

## Change Control

A contract change is complete only when:

- both repositories contain byte-compatible normative files;
- schema and OpenAPI validation pass;
- synthetic secret-free golden fixtures cover success, partial, missing, replay,
  and conflict behavior;
- producer and consumer contract tests pass locally in containers;
- unsupported major versions fail clearly;
- migrations follow expand/deploy/contract sequencing.

## Security Exclusions

No contract document may contain passwords, tokens, keys, SSH fingerprints,
raw native machine IDs, database secrets, audit keys/anchors, browser
credentials, real private hostnames, or production evidence.
