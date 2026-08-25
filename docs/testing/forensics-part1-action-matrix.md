# HostHunter Forensics Part 1 Action Matrix

## Status

**CONTRACT CONFIRMED 2026-08-25; LOCAL PROCESS START SLICE IMPLEMENTED**

This is the authoritative user-action and critical-path inventory for Part 1.
The canonical event model is ECS 9.5.0. The first semantic scope is Windows
Process Start from Sysmon event 1 and Security event 4688. Process termination,
process graphs, and other event families are deferred.

The first implementation slice is deliberately local: admit a verified EVTX,
run the pinned parser, normalize supported records, create deterministic
batches, encrypt exact request bytes in an outbox, and deliver them to a local
deterministic API stub. Remote acquisition, archives, transfer, and endpoint
cleanup remain later Part 1 slices.

## First-slice critical paths

| ID | Action or boundary | Expected behavior | Required evidence | Status |
| --- | --- | --- | --- | --- |
| FP-EVTX-01 | Admit a local EVTX | Accept only a closed, path-safe file with immutable size and SHA-256 evidence; changed input becomes a new source | admission units plus package integration | focused verified |
| FP-PARSER-01 | Resolve `evtx_dump` | Select only pinned v0.12.2 asset/RID/digest; reject missing, extra, or changed binaries | resolver/package units and package scan | focused verified |
| FP-PARSER-02 | Parse EVTX | Execute out of process with `-t 1 -o jsonl`, bounded time/resources/output, separated stderr, and no network | runner units, real EVTX package integration, native macOS denial proof | focused verified |
| FP-JSONL-01 | Read parser output | Stream complete JSONL records; reject malformed, oversized, unsupported, or truncated output without partial success | JSONL reader units and malicious corpus | focused verified |
| FP-ECS-01 | Normalize Sysmon event 1 | Produce ECS 9.5.0 Process Start with ProcessGuid identity, exact provenance, and protected command line | golden mapper and actual-schema tests | focused verified |
| FP-ECS-02 | Normalize Security event 4688 | Produce ECS 9.5.0 Process Start with deterministic non-PID-only identity and version-aware fields | golden, placeholder, and actual-schema tests | focused verified |
| FP-ECS-03 | Encounter unrelated or unsupported records | Skip unrelated IDs with counters; emit bounded `pipeline_error` events for supported IDs with unsupported versions/shapes | negative golden tests | focused verified |
| FP-ID-01 | Replay or conflict | Same deterministic ID and semantic hash is idempotent; same ID with different hash is quarantined | identity/vector units and persistence integration | focused verified |
| FP-SECRET-01 | Handle command lines | Warn once that command lines may contain plaintext secrets; never write them to console diagnostics, receipts, or plaintext SQLite | secret-surface units and repository secret scan | implemented; canonical scan pending |
| FP-DB-01 | Initialize forensics state | Create a separate migrated `forensics.db`, key, ledger, and external monotonic anchor without changing `hosthunter.db` | clean migration, concurrent-tamper, rollback, and native Keychain proof | focused verified |
| FP-OUTBOX-01 | Build a delivery batch | Serialize deterministic exact request bytes, hash them, AEAD-encrypt before persistence, and never rebuild on retry | batching/outbox units and restart integration | focused verified |
| FP-API-01 | Deliver to Part 2 contract stub | PUT bounded idempotent batches to a loopback deterministic stub; classify success, conflict, retryable, permanent, and unknown outcomes | API client and fault integration | focused verified |
| FP-REC-01 | Restart interrupted local processing | Resume from durable state without reparsing accepted work or duplicating delivery; preserve incomplete states visibly | interrupted-send/commit-unknown/reconciliation tests | focused verified |
| FP-PKG-01 | Import exact package | Explicit nested load order, parser assets, schemas, checksums, licenses, and SBOM are complete and source-tree imports are not accepted as package proof | package-only real-EVTX integration and release scan | package integration verified; canonical scan pending |

## Event mapping actions

| Source action | Canonical result | Required negative coverage |
| --- | --- | --- |
| Process creation recorded by Microsoft-Windows-Sysmon event 1 | one `event.kind=event`, `event.category=[process]`, `event.type=[start]`, `event.action=process-started` ECS event | Sysmon event 5 yields no Process Start event; unsupported event-1 version yields a pipeline error |
| Process creation recorded by Security event 4688 | one equivalent ECS Process Start event retaining Security provenance | Security 4689 yields no Process Start event; malformed hex PID or unsupported version yields a pipeline error |
| The same real process appears in both sources | two source-evidence events, never silently deduplicated across providers | no inferred parent entity ID from PID alone |

## Later Part 1 public actions

These actions remain part of Part 1 but are not exposed until their complete
workflow and package E2E coverage exist.

| User action | Planned cmdlet | Required E2E behavior | Status |
| --- | --- | --- | --- |
| Start acquisition | `Start-HHEventLogAcquisition` | Persist exact target/profile intent before network; package the requested Windows event-log directory and begin verified transfer | deferred to remote slice |
| Inspect acquisition | `Get-HHEventLogAcquisition` | Show acquisition, transfer, parsing, delivery, and cleanup completeness separately | deferred to orchestration slice |
| Resume local processing | `Resume-HHEventLogProcessing` | Resume only durable local work; never repeat endpoint collection implicitly | deferred to orchestration slice |
| Retry transfer | `Retry-HHEventLogTransfer` | Continue the same verified artifact without rebuilding or weakening identity | deferred to transfer slice |
| Retry cleanup | `Retry-HHArtifactCleanup` | Delete only the exact immutable generated outer artifact after verified local custody | deferred to cleanup slice |
| Stop acquisition | `Stop-HHEventLogAcquisition` | Stop future work while preserving acquired and partial evidence | deferred to orchestration slice |
| Configure Part 2 API | `Set-HHForensicsApiConfiguration` | Store only non-secret endpoint configuration; secrets remain in a dedicated Keychain service | deferred to delivery/public slice |

## Deferred and non-goals

- Sysmon event 5 and Security event 4689 normalization.
- Process lifetime correlation and graph materialization.
- OCSF as an intermediate or canonical representation.
- Endpoint-side EVTX parsing.
- Positive Windows acquisition proof in the Linux fixture; this requires the
  later exact-package Windows qualification lane.
- Public exports before the corresponding complete user journey is packaged
  and verified. Until then, the existing exact-eleven export assertion remains
  correct.

## Parallel work decision

Implementation may be parallelized only across disjoint surfaces after the
JSON/ECS and persistence contracts are frozen: parser/ECS mapping, forensics
state/outbox, and archive/transfer can have separate owners. The primary agent
owns module loading, shared integration, action-matrix reconciliation, the
threat-model review, and final container/security gates.
