# Progressive Forensics Plan - Coordination Index

Status: PART 1 ECS PROCESS START CONTRACT CONFIRMED 2026-08-25
Implementation readiness: PART 1 LOCAL SLICE READY; REMOTE SLICE CONDITIONAL
Date split: 2026-08-25
Owner: James Hinton
Handoff audience: main integration agent

> Contract amendment: ECS 9.5.0 is the sole canonical event model and the
> first semantic scope is Sysmon event 1 plus Security event 4688 Process
> Start. Process termination and graph correlation are deferred. James
> confirmed the Part 1 contract on 2026-08-25. Part 2 remains a separate,
> unconfirmed build.

The former monolithic progressive-forensics plan has been split into two
independently executable plans with one frozen integration boundary.

## Part 1 - HostHunter Updates

[Progressive Forensics Part 1 - HostHunter Updates Plan](progressive-forensics-part-1-hosthunter-updates-plan.md)

Part 1 targets the existing HostHunterNextGeneration repository and owns:

- complete endpoint event-log directory acquisition;
- audited PowerShell staging and bounded manifest output;
- one reusable HostHunter capability that gives every extracted file exactly
  two ZIP wrapper layers, password-protects the outer ZIP with a saved random
  HostHunter secret, and is mandatory for every extraction cmdlet;
- encrypted outer-ZIP-only binary transfer, bounded local two-layer
  validation, and immutable outer/inner/raw publication;
- exact generated remote outer-ZIP cleanup eligibility after confirmed receipt
  and successful local outer decryption, with audited dispatch queued until the
  staging operation lock is released and without deleting original/live or
  staged raw endpoint files;
- per-file and acquisition-complete receipts;
- local PowerShell plus pinned evtx_dump processing;
- Sysmon event 1 and Security event 4688 normalization to ECS 9.5.0;
- deterministic event batches, bounded outbox, and API client;
- operator start, status, stop, retry, resume, and reconciliation;
- acquisition/parser/delivery tests and HostHunter release qualification.

Part 1 ends when normalized events and status resources are durably accepted
and reconciled by the Part 2 API.

## Part 2 - API And Visual Container

[Progressive Forensics Part 2 - API And Visual Container Plan](progressive-forensics-part-2-api-viewer-container-plan.md)

Part 2 proposes one new, independently versioned application repository and
one deployable local container. It owns:

- authoritative API/event/graph contracts and compatibility releases;
- authenticated, transactional, idempotent event ingestion;
- read-only source verification and SQLite migrations/persistence;
- file-level atomic graph activation;
- Host and ProcessInstance projection and lifecycle correlation;
- graph queries, revisions, deltas, and SSE;
- the full responsive node interface and evidence inspector;
- browser/accessibility/performance proof and container operations.

Part 2 begins at the versioned event/status API. It never invokes HostHunter,
PowerShell, SSH, evtx_dump, or endpoint collection.

## Evidence Baseline

The split plans preserve the prior read-only research baseline:

- HostHunterNextGeneration/AGENTS.md and the repository testing documents;
- docs/planning/shared-understanding-contract.md and
  docs/planning/sqlite-persistence-plan.md;
- the current Invoke-HHCommand, SSH transport, target model/repository, module
  loader/manifest, and initial SQLite migration;
- evtx/evtx_dump 0.12.2 as the verified initial macOS parser candidate;
- Microsoft Sysmon event 1 and Security event 4688 semantics for the confirmed
  first slice; termination-source research is retained only as deferred work;
- ECS 9.5.0 plus `hosthunter.*` provenance as the confirmed canonical model;
- prior comparisons of evtx_dump, Hayabusa, Chainsaw, Vector/Nano,
  Winlogbeat/ECS, Timesketch, Elastic, Grafana, OpenSearch, BloodHound, and
  graph-viewer options.

Authoritative external references:

- [evtx](https://github.com/omerbenamram/evtx)
- [ECS 9.5.0](https://github.com/elastic/ecs/releases/tag/v9.5.0)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Security event 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688)
- [Security event 4689](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4689)
- [Compress-Archive](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.archive/compress-archive?view=powershell-7.6)
- [SharpZipLib](https://github.com/icsharpcode/SharpZipLib)

All dependency versions, digests, licences, platform artifacts, and
load-bearing external behavior must be reverified from authoritative sources
immediately before implementation.

## Shared End-To-End Goal

Give one local investigator a progressively filling, evidence-backed graph
while HostHunter continues acquiring complete event-log directories.

The first accepted journey is:

1. HostHunter creates/upserts an opaque forensics case UUID or explicitly
    attaches to an existing supplied forensics UUID.
2. HostHunter registers endpoint A and an OPEN acquisition.
3. Part 2 immediately displays endpoint A as a placeholder host island.
4. Endpoint PowerShell requests an artifact-bound password for each closed raw
    file. HostHunter generates and read-backs the random password from Keychain,
    sends it through the qualified secret relay, then the shared artifact
    capability streams raw payload -> inner evidence ZIP -> password-protected
    outer transport ZIP. It emits a bounded typed artifact-staged record only
    after raw/inner/outer hashes are final, while the directory command
    continues.
5. HostHunter transfers only the encrypted outer ZIP, verifies its outer hash,
    retrieves the saved password from Keychain, authenticates/decrypts it, and
    safely validates exactly two wrapper layers before publishing the inner ZIP
    and raw EVTX locally.
6. After durable receipt and successful outer decryption, HostHunter marks only
    that exact generated remote outer ZIP cleanup-eligible. It queues the
    audited, handle-bound delete until the staging operation releases the core
    lock. The original/live file and staged raw source remain.
7. HostHunter processes that immutable raw file locally and sends normalized event
    batches.
8. Part 2 stages the batches but publishes no incomplete-file graph facts.
9. HostHunter submits successful file completion.
10. Part 2 independently verifies the mounted source and atomically activates
    that file's graph contribution.
11. Endpoint A gains stable process nodes while its acquisition remains OPEN.
12. Endpoint B can register and populate without moving endpoint A.
13. HostHunter seals each directory acquisition only after its final manifest.
14. Ready, warning, empty, deferred, failed, paused, and aborted coverage remain
    visibly distinct.
15. Every visible fact reaches the exact source hash, Windows event,
    parser/mapper/run, and correlation method.

## Hard Boundary Rules

These rules apply to both parts:

- EVTX parsing occurs only after local transfer.
- The API receives normalized events/status, never raw EVTX bytes.
- Invoke-HHCommand may stage endpoint logs and return a bounded manifest; it
  exposes bounded typed artifact-secret-request/artifact-staged/final-manifest
  records to the internal acquisition orchestrator, but never transports EVTX,
  JSONL, normalized batches, outbox payloads, API credentials, or archive
  passwords.
- Every file-extraction cmdlet uses the same exact-two-ZIP artifact services;
  no direct Compress-Archive, Expand-Archive, raw SFTP read, or remote delete
  bypass is allowed.
- Only a closed, hashed, password-protected outer ZIP crosses the binary
  endpoint-to-controller transfer boundary. The password is HostHunter-
  generated, Keychain-managed, and delivered through a separately qualified
  non-logging secret-input channel, never ordinary command arguments/output.
- Only the exact generated remote outer ZIP may be automatically deleted, and
  only after the local receipt/decryption gate. Original/live and staged raw
  files plus all local evidence are outside cleanup authority.
- The immutable HostHunter spool is the acquired evidence source of truth.
- Part 2 mounts only HostHunter's dedicated
  forensics/evidence/v1 subtree as hosthunter-evidence-v1:/evidence read-only;
  it never sees outer/inner ZIPs, private artifact/secret/transfer/unpack/
  cleanup receipts, password references, HostHunter databases, audit
  artifacts, target profiles, known_hosts, SSH keys, or clear API tokens.
- Part 2 SQLite, entities, relationships, graph revisions, and layout are
  derived and rebuildable.
- HostHunter owns acquisition and local processing controls. The Phase 1
  viewer is read-only.
- HostHunter creates and keeps the clear producer token in macOS Keychain;
  Part 2 receives only a scoped verifier through its read-only secret mount.
- Files may activate progressively; individual records from an incomplete file
  do not appear as graph evidence.
- Starts/stops are atomic observations. Missing partners never prove that a
  historical process is currently running.
- Sysmon ProcessGuid supports exact lifecycle identity. Security PID matching
  is conservative, temporal, confidence-labelled, and ambiguity-preserving.
- Phase 1 does not silently merge Sysmon- and Security-derived process
  instances.
- Unsupported target versions remain warnings/evidence, not invented nodes.
- Rust is a future producer behind the same receipt and event contracts.
- Double ZIP is mandatory packaging, but the second layer is not claimed to
  guarantee further compression or endpoint authenticity. Its Phase 1 value is
  the password-protected versioned transport envelope.
- All proof is local and containerized; GitHub does not rerun it.

## Contract Ownership

There are two independently versioned contract families. HostHunter-internal
artifact contracts are owned and released with Part 1. The machine-readable
cross-part contract is physically owned by the Part 2 repository after that
repository is approved and created, and Part 1 pins its immutable version and
digest.

| Surface | Semantic steward | Consumer |
| --- | --- | --- |
| artifact-secret-request/staged schemas, nested manifests, password/provisioning/transfer/unpack/cleanup receipts | Part 1 internal | Every Part 1 extraction cmdlet/adapter only |
| hosthunter.file-ready.v1 | Part 1 | Part 2 |
| hosthunter.acquisition-complete.v1 | Part 1 | Part 2 |
| Case/endpoint/acquisition/source resource shapes | Joint | Both |
| Event item/batch/run/attempt/completion/failure | Part 2 | Part 1 and future producers |
| OpenAPI errors, idempotency, digests, and limits | Part 2 | Part 1 |
| Graph/query/delta/SSE | Part 2 | Part 2 viewer |
| canonical_tuple_v1 and canonical JSON vectors | Joint | PowerShell, server, future Rust |

Rules:

- Part 1 never publishes its archive/password/cleanup schemas through the
  cross-part release or Part 2 evidence mount.
- Part 1 pins an immutable cross-part contract release and digest.
- A schema is never copied and independently edited in both repositories.
- Contract-first tests and golden vectors precede production implementation.
- Breaking changes use an explicit new major contract/API version.
- Either steward can reject a cross-boundary change that breaks evidence,
  replay, or compatibility guarantees.

## Source Of Truth

| Artifact | Classification | Authority |
| --- | --- | --- |
| HostHunter audited staging invocation | Audit evidence | Exact remote command intent/dispatch/outcome |
| HostHunter separately keyed/anchored forensics ledger | Audit evidence | Acquisition, secret delivery, packaging, transfer, archive authentication, publication, processing, delivery, and cleanup intent/outcome |
| Endpoint directory/artifact manifests | Acquisition evidence | Expected file/artifact set and endpoint-side raw/inner/outer size/hash/protection claims |
| Verified encrypted outer and inner ZIPs in HostHunter private artifact store | Acquired packaging evidence | Immutable transferred bytes and nested evidence envelope for local revalidation |
| Verified EVTX in HostHunter spool | Acquired evidence | Immutable source for local reprocessing |
| HostHunter artifact/file/acquisition/cleanup receipts | Acquisition evidence | Local layer verification, collection coverage, and exact remote outer cleanup outcomes |
| Parser-native bounded record | Derived parser output | One parser's interpretation of a source record |
| Normalized event item | Derived atomic observation | OCSF process semantics plus provenance or unsupported target evidence |
| Active producer run | Derived interpretation | Accepted mapping version for one source |
| Entity/relationship projection | Derived view | Rebuildable investigation graph |
| Browser layout coordinates | Disposable presentation | Never evidence or canonical entity state |

If derived storage is lost, preserve diagnostics, create a new application
volume, and replay the immutable EVTX through Part 1. Never alter evidence to
make derived state agree.

## Shared IDs And State

HostHunter generates/upserts the Phase 1 opaque case_id or explicitly attaches
to an existing supplied forensics UUID. Its existing free-form command CaseId
is provenance only. HostHunter also owns stable endpoint, acquisition,
file/artifact/source, password-reference, package-attempt, run, attempt, batch,
and observation identifiers under the frozen shared rules.

Keep these dimensions independent:

| Dimension | Canonical states |
| --- | --- |
| Acquisition | OPEN, SEALED, ABORTED |
| Archive password | NOT_CREATED, REQUESTED, SAVING, SAVED, DELIVERING, DELIVERY_UNKNOWN, DELIVERED, KEY_UNAVAILABLE, DESTROYED |
| Artifact package | DISCOVERED, PACKAGING_INNER, PACKAGING_OUTER, STAGED, TRANSFERRING, VALIDATING_OUTER, INNER_READY, RAW_READY, QUARANTINED |
| Source evidence | DISCOVERED, VERIFIED, QUARANTINED |
| Analysis | DEFERRED, STAGING, READY, READY_WITH_WARNINGS, COMPLETE_EMPTY, PAUSED_API, FAILED |
| Run | STAGING, ACTIVE, SUPERSEDED, NONDETERMINISTIC |
| Attempt | RUNNING, SUCCEEDED, FAILED, CANCELLED_BACKPRESSURE |
| Remote outer cleanup | NOT_ELIGIBLE, ELIGIBLE, INTENT_RECORDED, HELD_STOPPED, DISPATCHED, COMPLETE, RECONCILED_ABSENT, RECONCILED_PRESENT, FAILED_MISMATCH, FAILED, UNKNOWN |
| Viewer connection | CONNECTED, RECONNECTING, RESYNCING |

Collection completion never implies analysis completion. Analysis completion
never implies complete knowledge of endpoint activity.

## Delivery Order

### Stage 0 - Confirm Both Contracts

1. Confirm the Shared Understanding Contract in Part 1.
2. Confirm the Shared Understanding Contract in Part 2.
3. Amend the current HostHunter product contract for the post-v1 feature.
4. Confirm the Part 2 repository name/location.
5. Do not implement either part until these gates are satisfied.

### Stage 1 - Freeze The Shared Contract

The main integration agent owns:

- internal nested-archive/secret/cleanup contracts plus cross-part receipt,
  event, API, problem, identity, digest, and golden-vector contracts;
- case/endpoint/source/run ownership;
- batch/event/request limits;
- retryable/permanent error taxonomy;
- auth/bootstrap boundary;
- compatibility and contract-version matrix.

Both parts may then build against contract stubs without waiting for the other
implementation.

### Stage 2 - Independent Implementation

Part 1 may develop the shared artifact packager, secret channel, encrypted-
outer transfer/unpack/cleanup, acquisition, spool, parser/mapper, and API client
against deterministic endpoint and contract-test servers.

Part 2 may develop ingestion, persistence, projection, SSE, and UI against a
deterministic contract-test producer and synthetic/redacted fixtures.

Neither side may create a private interpretation of the shared contracts.

### Stage 3 - Cross-Part Integration

Run the complete journey with:

- one then two endpoints;
- multiple files arriving while acquisitions remain open;
- exact two-layer encrypted packages, wrong/missing passwords, corrupt layers,
  unsafe archives, secret-channel failure, and archive resource pressure;
- successful and uncertain exact remote outer deletion while original/live and
  staged raw files remain unchanged;
- clean, warning, empty, deferred, failed, paused, and aborted sources;
- transfer, producer, API, database, container, SSE, and browser restarts;
- duplicate, timeout, conflict, hash mismatch, corruption, oversized record,
  and disk-pressure cases;
- file reprocessing under a new mapper while the prior active run remains;
- a contract-test future producer proving Rust compatibility.

### Stage 4 - Independent Release And Rollback

- Pin exact HostHunter, contract, application image, and migration versions.
- Part 1 can be disabled without deleting spool/evidence.
- Part 2 can roll back only to a schema-compatible image.
- Derived storage can rebuild from immutable evidence.
- Rust cutover is per source class and rolls back to PowerShell without API/UI
  migration.
- Any later removal of a proven PowerShell producer path requires
  $codebase-prune-review and full contract parity first.

## Cross-Part Acceptance Ledger

| ID | Acceptance criterion | Primary owner | Proof |
| --- | --- | --- | --- |
| INT-R-001 | Endpoint registration displays a placeholder before file transfer finishes | Both | Cross-part browser journey |
| INT-R-002 | A file larger than Invoke-HHCommand's output limit transfers without command-output transport | Part 1 | Transfer/audit integration |
| INT-R-003 | Partial, mismatched, traversing, or symlinked files never parse or activate | Both | Fault-injection integration |
| INT-R-004 | Deterministic batches retry without duplication or content drift | Both | Timeout/crash/idempotency tests |
| INT-R-005 | No graph fact appears before file completion and independent source verification | Part 2 | Activation integration/browser tests |
| INT-R-006 | One completed file populates before the full directory acquisition seals | Both | Progressive acquisition E2E |
| INT-R-007 | A second endpoint adds a stable host island without moving the first | Part 2 | Seeded browser assertions |
| INT-R-008 | Empty, warning, deferred, failed, paused, and aborted states remain distinct | Both | State/API/browser matrix |
| INT-R-009 | Start-only never says running and ambiguity is never forced | Part 2 | Semantic/browser fixtures |
| INT-R-010 | Every forensic process/edge reaches exact active event evidence; placeholder Hosts reach registration receipts and disclose no active event evidence | Part 2 | API and inspector E2E |
| INT-R-011 | Restart at each boundary preserves evidence and resumes safely | Both | Kill/restart integration |
| INT-R-012 | Part 1 and Part 2 upgrade independently within the compatibility matrix | Both | Version-skew contract suite |
| INT-R-013 | Future Rust submits the same contract without application change | Both | Contract-test producer |
| INT-R-014 | Full proof runs locally in containers with required native qualification | Both | Gate receipts |
| INT-R-015 | Every extracted file uses the shared exact-two-ZIP capability; only the password-protected outer transfers and Part 2 sees only verified raw EVTX/receipts | Part 1 | Architecture, transfer, mount, and cross-part E2E |
| INT-R-016 | Confirmed receipt/decryption queues a handle-bound delete of only the expected remote outer ZIP after the staging lock releases; original/live and staged raw bytes remain unchanged and uncertain cleanup stays visible | Part 1 | Lock-order, handle-bound cleanup, and crash-reconciliation E2E |
| INT-R-017 | Each outer uses its saved artifact-bound random password; wrong/missing keys prevent publication and cleanup, and no password/reference/archive receipt crosses logs, API data, or the Part 2 mount | Part 1 | Secret-leak, wrong-key, mount-negative, and no-cleanup E2E |

## Shared Non-Goals For Phase 1

- endpoint-side parsing;
- raw EVTX upload to the API;
- archive/password handling inside Part 2;
- legacy ZipCrypto, plaintext outer entries, operator-chosen passwords, or a
  secret passed through ordinary command arguments/output;
- deletion of original/live or staged raw endpoint files and deletion of any
  local acquired archive/raw evidence;
- whole-file JSONL storage;
- a Rust producer;
- graph database, broker, object store, or search cluster;
- remote/multi-user application hosting;
- BloodHound as the primary viewer;
- logons, principals, audit policy, permissions, files, services, tasks,
  registry, or network projections;
- anomaly/weirdness scoring, malware verdicts, or attack-path claims;
- search, timeline, annotations, saved views, reports, and exports;
- browser collection/retry/delete controls;
- automatic deletion or pruning of locally acquired evidence or endpoint
  original/live and staged raw sources; the only automatic endpoint cleanup is
  the confirmed, exact generated outer-ZIP rule above.

These are extension points, not rejected product directions.

## Parallel Work Decision

Parallel work is applicable after Stage 1.

| Lane | Ownership |
| --- | --- |
| Main integration | Shared contracts, migrations compatibility, acceptance/test ledgers, final proof |
| HostHunter artifact security | Shared package schemas, pinned helper provisioning, Keychain password lifecycle, secret relay, AES ZIP, safe unpack, exact cleanup |
| HostHunter acquisition | Endpoint staging, encrypted-outer transfer, spool, receipts |
| HostHunter producer | Parser, mapper, local state, outbox, API client |
| Application backend | API, auth, SQLite, source verification |
| Projection | Identity, lifecycle, graph contributions, revisions/SSE |
| Frontend | Graph UI, inspector, accessibility, browser/performance proof |
| Security | Threat-model report and approved remediation |
| Validation | Independent requirements/test/gate reconciliation |

Workers must have disjoint write ownership, the same frozen behavior contract,
mapped focused tests, and notice of concurrent work. The main agent owns
integration, migration sequencing, stale-test changes, security review,
gitleaks, and the canonical gate.

## Overall Implementation Gate

The main integration agent must ask:

Please confirm that the Part 1 and Part 2 Shared Understanding Contracts,
together with this coordination boundary, are accurate. I will not implement
either part until they are confirmed.

## Overall Definition Of Done

The program is complete only when both part-specific definitions of done and
every INT-R row are verified, the compatibility matrix is pinned, and:

- complete endpoint event-log directories are preserved locally;
- every extracted file has exactly two validated ZIP wrapper layers, the outer
  is protected by a saved HostHunter password, and raw/inner/outer hashes and
  receipts remain linked;
- only verified encrypted outer archives cross binary transfer, and the exact
  matching generated remote outer is removed after local receipt/decryption
  without changing original/live or staged raw sources;
- normalized process observations flow progressively and idempotently;
- multiple endpoints populate a stable evidence-linked node view;
- failures and uncertainty remain truthful and recoverable;
- future event types and a Rust producer can extend frozen seams;
- all required unit, integration, CLI, browser, accessibility, performance,
  migration, security, secret, dependency, image, and production-build proof
  passes locally;
- no GitHub test workflow is added or used.
