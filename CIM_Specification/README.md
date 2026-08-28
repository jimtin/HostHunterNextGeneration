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
  authenticated compatibility/readiness receipt.
- [Host-details schema](schemas/host-details-observation.v1.schema.json) defines
  one immutable Phase 1 endpoint observation.
- [Process lifecycle schema](schemas/process-lifecycle-event.v1.schema.json)
  defines one immutable Phase 2 process start or stop event.
- [Producer OpenAPI](openapi/host-details-ingest.v1.openapi.yaml) defines the
  currently frozen Phase 1 status, mission, and host-observation HTTP behavior.
- [Complete Windows example](examples/windows-complete.v1.json) and
  [partial Linux example](examples/linux-partial.v1.json) are synthetic Phase 1
  fixtures.
- [Process-start example](examples/process-start.v1.json) and
  [process-stop example](examples/process-stop.v1.json) are synthetic Phase 2
  structure examples; they do not claim that Phase 2 ingestion is implemented.

The Phase 2 process event route is specified in
`collected-data-structures-v1.md` but must not be described as implemented
until its OpenAPI operation, receipts, migrations, producer delivery, golden
fixtures, and tests are accepted together.

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
- Process start/stop data is a narrow named contract, not arbitrary log ingest.
- PID alone is not a stable process identity.
- Missing process stops remain open; unmatched stops remain unmatched.
- Process events never populate or alter host membership.

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
