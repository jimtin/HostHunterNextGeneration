# Progressive Forensics Part 1 - HostHunter Updates Plan

Status: CONFIRMED BY USER - implementation authorized
Implementation readiness: READY for HH-0 and the local ECS Process Start
vertical slice; CONDITIONAL for remote acquisition until the authenticated
AES-ZIP and non-logging secret-relay qualifications pass
Date: 2026-08-25
Owner: James Hinton
Target repository: HostHunterNextGeneration
Handoff audience: HostHunter implementation agent

> James confirmed the amended Shared Understanding Contract on 2026-08-25.
> Implementation is authorized in the phases and safety boundaries below.
> Live endpoint mutation, destructive cleanup, commit, push, and release still
> require their ordinary explicit gates and evidence.

## 1. Outcome

Extend HostHunter so it can acquire complete Windows event-log directories,
package every extracted file through one reusable exact-two-ZIP capability,
protect each outer ZIP with a high-entropy random HostHunter-managed password,
transfer and validate both archive layers, publish each verified raw EVTX file
into an immutable local spool, remove only the generated remote outer ZIP after
the local receipt-and-decryption gate, process the file locally through
PowerShell and a pinned EVTX parser, and send bounded normalized event batches
to the Part 2 application API.

The first end-to-end proof is deliberately small:

1. An investigator starts an event-log acquisition for one HostHunter target.
2. HostHunter immediately registers the endpoint and an open acquisition with
    the Part 2 API.
3. Endpoint PowerShell stages a complete event-log snapshot. For each closed
    raw file it creates an inner evidence ZIP, then ZIPs that closed inner
    archive into a password-protected outer transport ZIP through the shared
    HostHunter artifact capability. Before an outer archive is sealed,
    HostHunter independently generates its 32-byte CSPRNG password and durably
    saves/read-backs that password by an opaque, artifact-bound Keychain
    reference, then delivers it through the qualified secret relay.
4. A first-class HostHunter acquisition orchestrator consumes each typed
    artifact-staged record while the remote pipeline is still running and
    starts a separate binary transfer of only the closed outer ZIP to the local
    Mac.
5. HostHunter verifies the received outer archive, retrieves its password from
    the controller Keychain, authenticates/decrypts it, validates and unwraps
    exactly two ZIP layers, verifies the raw payload, and preserves the local
    outer archive, inner archive, raw EVTX, manifests, hashes, and receipts.
6. After the outer ZIP is durably received and successfully decrypted to a
    verified inner ZIP, HostHunter marks only that matching generated outer ZIP
    cleanup-eligible. The separately audited cleanup is queued and dispatched
    after the staging invocation releases HostHunter's current core operation
    lock. It never deletes the original/live event log or staged raw source.
7. Local PowerShell invokes a pinned evtx_dump binary, maps Sysmon event 1 and
    Security event 4688 to ECS 9.5.0 Process Start documents, and sends
    deterministic event batches.
8. A second endpoint can be added while the first continues processing.
9. Restart, retry, or API interruption does not require endpoint recollection.

Part 1 stops at successful API delivery and status reconciliation. It does not
implement the database, graph projection, or browser interface.

## 2. Confirmed Product Decisions

- Event-log files are extracted to the local controller before parsing.
- Endpoint-side PowerShell acquires and stages files; it does not normalize
  Windows events.
- The local first producer is PowerShell orchestrating a native EVTX parser.
- The API accepts normalized event observations and status resources, not raw
  EVTX uploads.
- Rust is deferred until measured PowerShell/parser limits justify it.
- HostHunter should start processing a verified file while other files from
  the same endpoint are still arriving.
- Every file-extraction operation must package its source file in exactly two
  nested ZIP layers before binary transfer, including EVTX files, a staged
  oversized directory manifest, an empty file, and an input that is already a
  ZIP.
- Double-ZIP creation, validation, and safe unwrapping are one discrete,
  versioned HostHunter artifact capability used by every extraction cmdlet;
  event-log acquisition must not implement a private zipper or direct-transfer
  bypass.
- Both layers are retained with the verified raw file and layer-specific
  hashes. The outer archive is the only endpoint-to-controller transfer unit.
- Every outer archive has a high-entropy random HostHunter-managed password
  saved in macOS Keychain and retrieved for local decryption. Phase 0 freezes
  the exact CSPRNG, encoding, Keychain namespace, and secret-relay contract; it
  does not replace the per-artifact random password with a shared password or
  deterministic derivation. No password enters command arguments,
  environment variables, archive manifests, audit
  artifacts, receipts, databases, URLs, or logs.
- The outer ZIP must use the frozen authenticated AES-256 ZIP profile. Legacy
  ZipCrypto, an unencrypted entry, and password reuse are rejected.
- Successful local receipt plus authenticated outer decryption to a verified,
  durably published inner ZIP triggers deletion of only the exact matching
  remote outer transport ZIP. Original/live files and staged raw sources are
  outside the cleanup function's authority.
- The first semantic scope is Process Start only: Sysmon event 1 and Security
  event 4688. Process termination and lifecycle pairing are deferred.
- ECS 9.5.0 is the canonical event model for every normalized HostHunter
  event. OCSF is not an intermediate or canonical representation.
- This contract was explicitly confirmed on 2026-08-25.

### 2.1 Feature design preflight

Status: **READY** for HH-0 and the local Process Start vertical slice;
**CONDITIONAL** for remote acquisition.

- Requirement: an investigator acquires complete Windows event-log directories
  and HostHunter progressively emits protected ECS Process Start evidence from
  verified local EVTX files.
- Existing pattern: reuse strict target snapshots, intent-before-network,
  operation locks, pinned native assets, SQLite provider primitives, durable
  no-replace publication, Keychain boundaries, exact receipts, and bounded
  local container gates. Keep `hosthunter.db` unchanged.
- Architecture: add explicit ordered ExtractionArtifacts and Forensics load
  manifests, a separate authenticated `forensics.db`, a pinned parser runner,
  ECS mapping/schema modules, encrypted exact-byte outbox, and later the
  qualified transfer/archive pipeline.
- Rejected naive paths: endpoint-side Get-WinEvent normalization; EVTX or JSONL
  through Invoke-HHCommand output; plaintext SQLite event/request bodies;
  direct file copies that bypass the exact-two-ZIP capability; unpinned parser
  resolution; automatic replay after uncertain remote work; and weakening ZIP
  authentication when the preferred implementation is unavailable.
- Verified 2026-08-25: ECS 9.5.0 is the latest stable schema and its generated
  field artifact is pinned; evtx_dump 0.12.2 is the latest stable parser,
  requires `-t 1` for deterministic ordering, and its osx-arm64 asset digest is
  frozen during HH-0; Process Start sources are Microsoft Sysmon event 1 and
  Security event 4688.
- Persistence rollout: expand by adding a separate v1 `forensics.db`; deploy
  readers/writers together behind the unexported feature slice; contract only
  in a later release. No migration modifies the released core database.
- Sensitive normalized event bodies and pending HTTP bodies are encrypted with
  a separate forensics master key before SQLite storage. Semantic digests,
  ranges, state, and non-sensitive routing metadata remain queryable.
- Failure/recovery: immutable source replay, stable deterministic identities,
  exact-byte resend after ambiguous API delivery, no endpoint recollection for
  local retry, explicit deferred/empty/failed states, bounded parser teardown,
  and no automatic remote-command or delete retry.
- First-slice proof: golden Sysmon 1 and 4688 fixtures, unsupported-version
  pipeline errors, malformed/oversized/parser failure cases, deterministic
  IDs/batches, encrypted outbox recovery, clean migration/reopen, package-only
  CLI boundary, changed-scope coverage at least 95 percent, and repository hard
  gates at least 90 percent.
- Remote-acquisition blocker: authenticated AES-256 ZIP64 interoperability and
  the non-logging secret relay must pass Phase HH-0 security and native proofs
  before any acquisition or cleanup command can dispatch.

## 3. Current HostHunter Boundary

The confirmed HostHunterNextGeneration first-release contract currently
provides accountable PowerShell-over-SSH command execution and explicitly
excludes a graphical application and central collector. It has no released
whole-file EVTX acquisition contract.

Invoke-HHCommand captures all PowerShell streams into audited artifacts and
enforces a 100 MiB plaintext output ceiling per target. That path is suitable
for a staging command and a small manifest. It is not a file-transfer or event
delivery channel.

This plan therefore requires an explicit post-v1 contract amendment. It must
not delay, silently broaden, or destabilize the currently confirmed v1
release. The forensics feature remains modular inside the
HostHunterNextGeneration repository and uses separate mutable workflow state.

Recommended initial qualification is the user's local osx-arm64 controller.
The existing HostHunter core keeps its separately qualified controller RIDs,
but the new forensics commands fail closed before network activity on any RID
whose binary transfer, parser, resource limits, and Keychain/secret behavior
have not been independently qualified.

## 4. Scope

Part 1 owns:

- case attachment and API connection configuration;
- endpoint and acquisition registration;
- audited endpoint-side directory staging;
- a reusable exact-two-ZIP artifact packaging, validation, and safe-unwrapping
  capability for every HostHunter file-extraction command;
- high-entropy per-artifact password establishment, controller Keychain
  storage, secret-reference persistence, non-logging secret delivery to the
  endpoint packaging worker, and authenticated outer-ZIP decryption;
- a binary endpoint-to-controller file-transfer adapter;
- local outer-archive partial handling, layer-by-layer hashing, immutable
  archive/raw publication, and receipts;
- local parser scheduling and resource isolation;
- process-event normalization;
- deterministic identity, batching, and bounded durable outbox delivery;
- retry, resume, status, failure, and reconciliation commands;
- acquisition-complete and per-source status delivery;
- controller-side API credentials;
- local encrypted outer ZIP, inner ZIP, raw EVTX, manifests, receipts, and
  matching Keychain-password retention until a separate coordinated prune/key-
  destruction policy is approved.

Part 1 does not own:

- the Part 2 API server, SQLite schema, projection engine, SSE, or browser UI;
- raw EVTX parsing inside the Part 2 container;
- endpoint-side Get-WinEvent normalization;
- treating nesting or compression by itself as encryption, authentication,
  malware scanning, or proof that a potentially compromised endpoint supplied
  truthful content;
- legacy ZipCrypto, an unauthenticated or unapproved encryption profile, a
  password supplied by an operator, or password reuse;
- EVTX or JSONL transfer through Invoke-HHCommand output;
- a whole-file JSONL derivative;
- lifecycle pairing or graph entity coalescing;
- logon, permission, service, task, network, file, or registry mappings;
- anomaly, weirdness, threat, or malware verdicts;
- the future Rust producer;
- deletion of original/live endpoint files, staged raw sources, locally
  acquired archives/raw evidence, or any remote path other than the exact
  generated outer ZIP after its cleanup gate.

## 5. Architecture And Ownership

    Windows endpoint
        |
        | audited PowerShell staging command
        | HostHunter secret input (never an argument or output)
        | raw snapshot -> inner evidence ZIP
        | -> uniquely password-protected outer transport ZIP
        | bounded typed artifact-staged records
        | final directory manifest
        v
    HostHunter acquisition coordinator
        |
        | pinned, host-key-verified transfer of outer ZIP only
        v
    incoming artifact.transport.zip.partial
        |
        | close and verify outer ZIP
        | validate exact entries and stream inner ZIP to a fixed path
        | verify inner ZIP, then stream raw payload to a fixed path
        | retrieve Keychain password and authenticate/decrypt outer
        | verify every layer and atomically publish inner/raw artifacts
        | durable outer-received-and-decrypted receipt
        v
    owner-private immutable HostHunter artifact store and raw EVTX spool
        |
        | queue exact-path/hash remote outer-ZIP cleanup
        | dispatch only after the staging operation lock is released
        | original/live and staged raw source paths are unreachable
        |
        | hosthunter.file-ready.v1
        v
    local HostHunter PowerShell producer
        |
        | pinned evtx_dump, bounded JSONL stream
        | strict mapper, deterministic batch/outbox
        v
    Part 2 event API on 127.0.0.1

Recommended internal boundaries in the existing repository:

    src/HostHunterNextGeneration/
      HostHunterNextGeneration.psd1
      HostHunterNextGeneration.psm1
      Private/ExtractionArtifacts/
        ExtractionArtifacts.LoadOrder.psd1
        Contracts/
        Packaging/
        Secrets/
        Provisioning/
        Validation/
        Cleanup/
      Forensics/
        Forensics.LoadOrder.psd1
        Public/
        Private/Acquisition/
        Private/Transfer/
        Private/Spool/
        Private/Parser/
        Private/Normalization/
        Private/Delivery/
        Private/Persistence/
        Private/Migrations/

These paths are proposed ownership boundaries, not authorized scaffolding.
Use two versioned explicit load manifests. The root module validates and loads
the framework-wide ExtractionArtifacts manifest before it loads the Forensics
manifest; both are dot-sourced into the existing module scope in dependency
order. This preserves access to approved core-private orchestration seams
without creating a second module scope and lets future extraction cmdlets use
the same capability without depending on Forensics. Update the root loader,
root manifest/package inventory, and explicit export lists. Do not assume the
current non-recursive loader will discover nested files, and do not replace it
with an unordered recursive glob. Clean-process package tests must prove that
importing HostHunterNextGeneration loads exactly the approved functions/files
on every qualified RID and fails closed on missing, extra, duplicate, or
reordered load entries.

The existing append-only/tamper-evident command audit remains authoritative
for remote commands. Mutable acquisition, parser, and delivery workflow state
belongs in a separate owner-private forensics database and must not weaken or
overload the command-audit schema.

Choose a separate authenticated forensics ledger rather than attempting to
reuse the current global command-operation context while Invoke-HHCommand is
still running. forensics.db contains an append-only MAC/hash-chained ledger
with its own macOS Keychain key and monotonic anchor. It records acquisition,
transfer, publication, processing, delivery, cleanup intent/outcome, and links
to the immutable core staging invocation ID. Mutable queues/cursors remain
separate tables and never replace the authenticated ledger.

Before any remote staging or binary retrieval begins, HostHunter must durably
record the acquisition intent, exact target, requested directory, case,
destination acquisition ID, and declared operation in that ledger. The
staging command keeps the existing pre-dispatch accountability barriers.
Before any outer package is sealed, it must generate/save/read back that
artifact's random password in Keychain and record only its opaque reference
plus password-contract version in forensics.db/ledger. Failure at that boundary
prevents package sealing and transfer. Secret delivery records only the fixed
consumer, artifact binding, byte count, channel/session identity, and outcome;
it never records the bytes.
Binary retrieval is a distinct accountable artifact operation with its own
immutable intent, transfer attempts, byte/hash receipts, and outcome linked to
the staging invocation. A mutable retry cursor may live in forensics.db, but it
cannot replace the authenticated record of what HostHunter attempted.

## 6. Proposed Public Commands

The exact names must be frozen with the contract amendment. Recommended
surface:

| Command | Responsibility |
| --- | --- |
| Start-HHEventLogAcquisition | Generate or accept -ForensicsCaseId, register endpoints, stage the selected targets' complete event-log directories, transfer files, and schedule local processing |
| Get-HHEventLogAcquisition | Show collection, transfer, local analysis, delivery, and cleanup dimensions without collapsing them into one success flag |
| Resume-HHEventLogProcessing | Resume locally retryable parsing or API delivery without recollecting immutable files |
| Retry-HHEventLogTransfer | Retry only an explicitly selected safe file transfer; never retry an uncertain remote command |
| Retry-HHArtifactCleanup | Reconcile and explicitly retry deletion of one verified generated remote outer ZIP by acquisition ID and artifact ID; load the expected identity/hash/path only from immutable receipts and never accept them from the caller |
| Stop-HHEventLogAcquisition | Stop scheduling new work while preserving acquired files, receipts, attempts, and uncertain remote outcomes |
| Set-HHForensicsApiConfiguration | Configure the loopback Part 2 base URI, pinned contract version, and Keychain credential reference without accepting plaintext secrets as arguments |

The implementation agent must update the module manifest, root module export
list, comment help, README, critical-path inventory, E2E workflow inventory,
and package qualification for every accepted public command.

Successful start/status output includes the non-secret Part 2 case graph URL
for the opaque case ID. It never embeds a producer token or viewer bootstrap
secret in that URL.

Phase 1 command qualification:

- SSH transport with a direct PowerShell 7 target profile is supported.
- WindowsPowerShell51 target profiles return one stable
  UnsupportedForensicsTargetRuntime error before staging/network mutation until
  separately qualified.
- WinRM remains fail closed under the existing product contract.
- A multi-target Start call creates one acquisition_id per selected target
  beneath the shared case; it never treats the targets as one transaction.
- Every mutating command declares SupportsShouldProcess and implements WhatIf
  with no network, database, Keychain, filesystem, or API mutation.
- Confirm applies to staging, retry, stop, credential rotation, and any later
  cleanup operation.

Start-HHEventLogAcquisition's single ShouldProcess summary explicitly states
that successful receipt/decryption makes each generated remote outer ZIP
eligible for automatic exact cleanup. Once that acquisition is confirmed,
HostHunter does not prompt once per file, but every delete still receives its
own durable intent/outcome. An explicit Retry-HHArtifactCleanup call has its own
ShouldProcess/Confirm boundary.

Stop semantics:

1. stop scheduling new transfer, parser, and API work;
2. request bounded cancellation of work that has a safe cancellation contract;
3. retain partial files, verified evidence, Keychain artifact passwords,
    pending exact API requests, cleanup state, and all receipts;
4. if a staging command was dispatched and its remote outcome cannot be
    proven, preserve Unknown and do not claim that endpoint staging stopped;
5. take the per-acquisition cleanup scheduler interlock and commit the stop
    transition before acknowledging Stop: any ELIGIBLE, queued, or
    INTENT_RECORDED cleanup becomes HELD_STOPPED and cannot begin network
    activity; a cleanup already durably DISPATCHED before that interlock is not
    cancelled because interruption could make its outcome unknowable, and it
    must be reconciled read-only;
6. never resend or reverse an uncertain remote command automatically; and
7. Resume records release of HELD_STOPPED, reconciles remote/acquisition and
    cleanup state, and only then queues still-eligible cleanup or continues
    local work.

## 7. Endpoint Acquisition Contract

### 7.1 Directory snapshot

The default acquisition unit is one endpoint and one complete requested
Windows event-log directory. It is not a filtered four-event export.

The endpoint acquisition workflow, coordinated by the parent PowerShell
staging invocation and fixed child packager, must:

1. enumerate every in-scope EVTX entry;
2. produce a consistent readable staging copy or supported exported snapshot
    for active/locked logs;
3. calculate size and SHA-256 for each staged file;
4. derive the frozen file/package identities and emit the bounded typed
    artifact-secret-request record for that closed raw binding;
5. after the controller's saved-secret child operation completes, validate its
    bounded outcome from the shared artifact packager, never a cmdlet-private
    ZIP or transfer path;
6. require that fixed helper to stream and hash the inner evidence ZIP directly
    into the encrypted outer entry, then close, authenticate, and hash the outer
    transport ZIP;
7. emit one bounded typed artifact-staged record only after the outer ZIP is
    immutable and every raw/inner/outer size and digest is known;
8. record source-relative path, channel hint when known, collection time,
    artifact identity, protection profile, and staging result;
9. write the final directory manifest only after enumeration is complete;
10. emit a final bounded manifest record that reconciles every earlier
    artifact-staged record; and
11. return only bounded status and manifest data through Invoke-HHCommand.

The acquisition orchestrator must receive typed artifact-secret-request and
artifact-staged records from the existing internal live stream observer while
the audited remote pipeline continues. The current public Invoke-HHCommand
behavior, which returns only after the remote pipeline finishes, is not by
itself sufficient for progressive packaging and retrieval. The implementation
must add a first-class internal observer seam plus the narrowly amended secret
relay without bypassing intent, dispatch-arm, stream capture, output bounds,
or uncertain-outcome rules.

Each `hosthunter.artifact-secret-request.v1` record includes schema version,
acquisition nonce, monotonic remote sequence, normalized source role,
manifest sequence, file_id, authorized package-attempt ordinal/ID, artifact_id,
closed raw marker, raw size/SHA-256, and bounded diagnostic state. The helper
resolves the staged raw input from those trusted IDs beneath the restricted
acquisition root; neither the record nor relay accepts an arbitrary source or
destination path. The record contains no password, password-derived verifier,
or Keychain reference.

Each `hosthunter.artifact-staged.v1` record includes schema
version, acquisition nonce, monotonic remote record sequence, file_id,
artifact_id, package_attempt_id, fixed staging-root-relative outer path,
closed marker, remote outer volume/file identity, raw/inner/outer sizes and
SHA-256 values, manifest digests, protection profile, password-contract
version, secret-delivery receipt ID, collection time, and bounded diagnostic
state. It never contains the password, controller Keychain reference, or a
caller-controlled extraction path. The final record includes the last sequence
and manifest identity.

The synchronous stream observer is deliberately tiny: it authenticates the
record framing, validates bounds/nonce/sequence/path shape, and enqueues the
record into one bounded acquisition queue. It performs no SFTP, hashing,
database/API write, JSON event parsing, or other blocking work. A separate
worker records the event in the forensics ledger/state database, handles an
eligible secret request through the fixed child-operation path, or starts an
eligible transfer after a staged record.

After remote completion or controller recovery, reconciliation rereads the
authenticated bounded staging records from the core invocation artifact and
the verified final manifest. This repairs a process crash between observer
enqueue and forensics-ledger persistence without repeating the remote staging
command.

Queue saturation never drops a record. It triggers bounded backpressure and
then cancels the remote pipeline through the existing cancellation contract,
records the acquisition as incomplete/possibly Unknown according to dispatch
evidence, and requires reconciliation. Queue capacity, enqueue timeout, and
cancellation behavior are frozen and fault tested in Phase 0.

On receipt of a valid artifact-staged record, HostHunter may start its distinct
binary transfer immediately. Transfer, local verification, parsing, and API
delivery can therefore overlap later endpoint staging. The final directory
manifest seals the expected set and detects missing, duplicate, or conflicting
announcements.

An inline manifest has strict entry/byte limits. If the complete manifest
exceeds them, endpoint PowerShell closes/hashes it as a staging artifact and
emits only a bounded manifest-staged record containing its relative path, size,
digest, nonce, and sequence. That manifest file must itself pass through the
same exact-two-ZIP, password-protected artifact capability before HostHunter
retrieves it. No file-extraction exception or direct-transfer shortcut exists.

Process-relevant channels such as Security and Sysmon Operational should be
staged/transferred first when present to reduce time to the first useful graph.
This is scheduling priority only: no directory entries are filtered out.

The acquisition record must distinguish an acquired/exported snapshot from an
original physical event-log file. It must not claim byte-for-byte provenance
that the Windows acquisition primitive cannot prove.

Phase 0 must select and qualify the Windows staging primitive against active
and archived logs, permissions, long paths, non-ASCII names, locked files,
empty logs, changing directories, insufficient disk, interruption, and
controller disconnect.

### 7.2 Reusable exact-two-ZIP artifact capability

Every current and future HostHunter command that extracts a file from an
endpoint must use one versioned private capability. Recommended internal
service boundaries are:

For this contract, `file extraction` means any exported HostHunter operation
that retrieves a source or evidence file from a managed endpoint to the
controller. It does not include HostHunter's own local audit-artifact encoding,
build/test fixture archives, controller-to-endpoint helper provisioning, or a
local export that never retrieves endpoint evidence. Those exclusions prevent
unrelated internal compression formats from being silently rewritten while
still making every endpoint evidence-retrieval cmdlet obey the two-ZIP rule.

| Service | Contract |
| --- | --- |
| New-HHArtifactPackage | Turn one closed staged source into one sealed exact-two-ZIP package |
| Test-HHArtifactPackage | Validate schemas, structure, encryption, bounds, and every layer hash without publishing |
| Expand-HHArtifactPackage | Authenticate the outer, validate each layer before its respective atomic publication, and mark raw ready only after the full chain validates |
| Remove-HHVerifiedRemoteTransportPackage | Delete only one cleanup-eligible remote outer ZIP by artifact ID and expected digest |

These are private framework services in Phase 1, not separately exported
operator cmdlets. Event-log acquisition is their first real consumer. An
architecture test must fail if an extraction cmdlet calls Compress-Archive,
Expand-Archive, the raw SFTP/SCP read adapter, or remote file deletion outside
the approved artifact services. A synthetic second extraction consumer proves
that the capability is genuinely reusable rather than event-log-specific.

One source file produces this exact structure:

    {artifact_id}.transport.zip       password-protected outer ZIP
      artifact.evidence.zip           encrypted outer entry
      transport-manifest.json         encrypted outer entry

    artifact.evidence.zip             inner ZIP
      payload.bin                     opaque original/staged file bytes
      evidence-manifest.json

Both archives have exactly two root entries with the fixed ASCII names shown.
There are no directory entries or caller/source-controlled entry names. The
source name and relative path are bounded manifest metadata only. A source
that is itself a ZIP remains opaque payload.bin and still receives these two
wrapper layers; HostHunter never recursively expands the payload.

The endpoint publishes only the sealed outer ZIP as a ready transfer artifact.
The writer hashes and streams the inner ZIP directly into the encrypted outer
entry and is forbidden to create a standalone remote inner ZIP or inner-ZIP
temporary. Therefore the outer transport ZIP is the only generated ZIP on the
target and the only post-receipt ZIP cleanup target. The original/live file and
staged raw snapshot remain untouched. The locally extracted inner ZIP is
preserved as acquired packaging evidence.

The inner manifest binds artifact/file/acquisition identity to the raw size
and SHA-256. The outer manifest binds the same identity to the raw and inner
sizes/digests, manifest digests, packaging implementation/version/RID, fixed
compression profile, password-protection profile, and creation time. The
outer archive digest is recorded outside the archive in the typed staged
record, avoiding a circular hash. No manifest contains a password, Keychain
locator, absolute path, or secret-derived verifier.

Keep these identities distinct:

- file_id identifies the logical directory entry;
- artifact_id identifies one sealed raw/inner/outer package and is never
  reused for rebuilt bytes;
- package_attempt_id identifies one execution attempt;
- outer_password_id is an opaque Keychain reference, not password material;
- source_id remains based on the verified raw payload digest and frozen source
  tuple, never on mutable ZIP metadata or archive bytes.

Archive generation need not reproduce identical ZIP bytes. Once a package is
closed and hashed it is immutable. A packaging rebuild receives a new
artifact_id and password; a transfer retry reuses the exact existing encrypted
outer bytes.

#### 7.2.1 Password and encryption contract

The proposed Phase 1 password model follows the user's requirement literally:
one independently generated password per outer ZIP, saved by HostHunter before
the endpoint can seal that ZIP.

1. The controller creates the acquisition namespace/nonce and authorizes the
    initial package attempt before dispatch. The endpoint derives `file_id`
    from the acquisition namespace, manifest sequence, and normalized relative
    path; deterministically derives the authorized initial
    `package_attempt_id` from file ID plus attempt ordinal 1; and derives
    `artifact_id` from package attempt, file ID, raw size, and raw SHA-256. A
    later rebuild requires a controller-authorized higher attempt ordinal and
    therefore new package/artifact IDs. It emits a bounded
    `hosthunter.artifact-secret-request.v1` only after the staged raw source is
    closed and hashed. The controller independently recomputes and validates
    those non-secret IDs and the raw binding before creating a password.
2. For a first valid request, HostHunter generates exactly 32 bytes with the
    controller CSPRNG and saves those canonical password bytes in macOS
    Keychain under service
    `HostHunter.ExtractionArtifact.v1` and an opaque artifact-bound account. It
    records only `outer_password_id`, reads the item back through the existing
    stdin-based Keychain worker, and requires byte equality before delivery.
    Namespace/account collision or conflicting metadata fails closed. A new
    allowlisted extraction-password action/service is required; audit/anchor
    Keychain namespaces cannot be reused. The worker encodes the bytes as
    unpadded 43-character Base64url only in transient memory when the ZIP
    implementation needs its password string.
3. A duplicate request for the same immutable artifact binding reuses the
    already saved password. A conflicting or uncertain request never generates
    a replacement under the same `artifact_id`; reconciliation must establish
    whether delivery occurred before any new package attempt receives a new ID
    and password.
4. The controller starts one fixed, versioned endpoint packager through a new
    host-key-pinned raw-SSH child-operation adapter and writes exactly the
    transient 43-byte Base64url password to that process's stdin. The helper
    performs the artifact-bound outer packaging itself; it does not try to feed
    stdin into the already-running PSRP process. It resolves the closed raw
    source and output only from the acquisition/artifact IDs beneath the
    restricted root, publishes a non-secret bounded outcome record, and exits.
    The owning PowerShell staging pipeline validates that outcome and emits
    `hosthunter.artifact-staged.v1`. Helper identity, target snapshot,
    acquisition/artifact IDs, byte count, timeout, dispatch intent, and outcome
    are ledgered, but the secret is not. This is a separately amended,
    allowlisted HostHunter child operation, not a general `Invoke-HHCommand`
    secret parameter or arbitrary raw-SSH command.
5. Only after Keychain persistence/read-back and exact secret-delivery
    acknowledgement may the endpoint create and seal the encrypted outer ZIP
    and emit `hosthunter.artifact-staged.v1`. Transfer requires both the staged
    record and its matching secret-delivery receipt.
6. HostHunter later retrieves that same Keychain item only in a short-lived
    local unpack worker. The endpoint packaging worker, relay, Keychain worker,
    and local unpack worker zero mutable secret buffers on every exit path as
    far as the qualified runtimes permit. Process isolation and exit, not
    `SecureString` or post-hoc log redaction, provide the residual-memory
    boundary.

A persisted DELIVERING state found after process restart becomes
DELIVERY_UNKNOWN. HostHunter performs a read-only reconciliation of the fixed
child-operation receipt and the exact expected outer path: a complete sealed
outer whose IDs, file identity, size, and hash match may advance to DELIVERED/
STAGED; absence or a partial/mismatch cannot be retried automatically. It
requires an explicit recovery decision and, when rebuilding is necessary, a
new package attempt/artifact/password. DELIVERY_UNKNOWN never permits transfer,
local publication, or cleanup.

The password item remains available for as long as its local encrypted outer
ZIP exists or remote cleanup is unresolved. There is no in-place password
rotation or deterministic password regeneration: re-encryption creates a new
artifact/package/password and never overwrites evidence. A missing Keychain
item produces `KEY_UNAVAILABLE`, blocks transfer/decryption and remote outer
cleanup, and never triggers a weaker fallback. Password destruction is allowed
only through a later approved retention workflow that has already disposed of
the corresponding local outer and resolved remote cleanup.

The outer ZIP uses one frozen authenticated AES-256 ZIP profile, provisionally
WinZip AES AE-2, and every outer entry is encrypted. The implementation rejects
ZipCrypto, mixed encrypted/plain entries, passwordless or operator-supplied
passwords, unsupported AES strengths/profiles, and any authentication failure.
Fixed entry names are required because ZIP encryption does not necessarily
hide central-directory names and metadata.

The existing audited Invoke-HHCommand argument path serializes arguments and
therefore cannot carry this secret. Phase 0 must prove the secret-input channel
never enters script text, arguments, audit artifacts, event streams, process
command lines, environment, files, crash reports, or diagnostic output. If
that channel or a matching authenticated AES ZIP reader/writer cannot be
qualified on Windows PowerShell 7 endpoints and the osx-arm64 controller, the
feature is BLOCKED. It must never fall back to plaintext ZIP or ZipCrypto.

No ZIP encryption dependency is approved by this plan. Checked 2026-08-25,
Microsoft's current
[Compress-Archive documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.archive/compress-archive?view=powershell-7.6)
shows no password parameter and states a 2 GB file limit, so it is not a viable
generic outer packager. The
[SharpZipLib project](https://github.com/icsharpcode/SharpZipLib) documents AES
and ZIP64, and its current NuGet stable release is 1.4.2; its age means it is a
candidate only, not a selection. Its exact package/digest, supply chain,
licence, large-file streaming, authentication behavior, memory use, and
Windows/macOS interoperability must pass current-source verification,
SBOM/dependency scanning, malicious-fixture tests, and the formal threat model
before selection. A helper that requires `-pPASSWORD` or another secret-
bearing command line is disallowed.

#### 7.2.2 Compression, capacity, and immutable publication

ZIP nesting does not guarantee a smaller second archive. The first ZIP should
provide nearly all useful compression; recompressing already compressed bytes
may save nothing and may increase size. The proposed starting profile deflates
payload.bin in the inner ZIP, stores the already-compressed inner ZIP in the
outer container, and deflates only the small outer manifest. Both layers still
remain ZIP archives and the outer provides the password-protected transport
envelope. Phase 0 records raw/inner/outer sizes and CPU time across realistic
fixtures before freezing methods and levels; product copy never promises a
second-layer size reduction.

Before packaging or unpacking, preflight worst-case raw, inner, outer,
temporary, quarantine, and safety-headroom capacity using checked arithmetic.
Never assume compression savings. Freeze maximum source/inner/outer/expanded
bytes, exact entry counts, manifest bytes, compression ratios, worker
concurrency, CPU, memory, wall time, stall timeout, and per-acquisition disk
quota from measurements.

Packaging uses unique CreateNew partial paths and hashing streams. The selected
writer must stream the inner ZIP directly into the encrypted outer entry while
hashing it, then write the outer manifest, close/authenticate/flush/hash the
outer, and only then emit artifact-staged. Phase 1 creates no standalone remote
inner ZIP or inner-ZIP temporary, so the only generated complete ZIP eligible
for endpoint deletion is the outer transport ZIP. A library that cannot satisfy
that streaming contract is disqualified. Endpoint raw staging is read-only. A
crash or invalid archive leaves a bounded outer partial/quarantine state and
never mutates the source.

#### 7.2.3 Untrusted archive validation

The local worker never calls a general expand-directory operation. It first
validates the central directory, protection profile, fixed exact entry set,
sizes, and bounds. It then streams only the named expected entry to a fixed
CreateNew partial destination chosen from trusted IDs. Data produced before
the outer authentication check completes is never publishable.

Reject missing/additional/duplicate layers or entries; a third wrapper;
absolute, drive, UNC, traversal, backslash, colon/alternate-data-stream,
control, empty, or dot-segment names; case-fold or Unicode-normalization
collisions; directory, symlink, reparse, device, or special entries; archive
comments; prepended self-extractor or trailing data; overlapping entry ranges;
central/local-header disagreement; spanned or malformed ZIP64 archives;
unsupported compression/encryption; an encrypted inner ZIP; truncation; CRC,
authentication, manifest, size, or SHA-256 mismatch; and any resource-limit or
checked-arithmetic failure.

#### 7.2.4 Pinned helper provisioning

The authenticated AES ZIP64 implementation and its fixed secret-relay/cleanup
helpers are HostHunter package artifacts, not assumed endpoint dependencies.
Phase 0 must freeze their exact version, RID, file set, SHA-256 digests,
licence, SBOM, signing expectations, supported Windows runtime, and matching
controller-side reader compatibility.

Before the first source is packaged, a separately audited, narrowly scoped
controller-to-endpoint bootstrap adapter places the approved files beneath a
unique restricted HostHunter tool root. The adapter writes CreateNew partials,
flushes them, reads back exact size/SHA-256 on the endpoint, atomically
publishes only a matching set, and records the version/digests in the
acquisition manifest and forensics ledger. The packaging, secret-relay, and
cleanup workers load/execute only those exact verified paths. PATH lookup,
GAC/global installation, dynamic package download, endpoint package-manager
resolution, and unpinned fallback are prohibited.

Phase 0 must choose either a versioned controller-managed endpoint cache or a
per-acquisition copy and freeze its upgrade, rollback, retention, and
quarantine policy. This bootstrap is controller-to-endpoint tool provisioning,
not evidence extraction, and is never routed through the Part 2 API. The
automatic evidence cleanup rule cannot delete this helper set; helper removal
requires its own later, explicitly approved maintenance contract. Provisioning
or digest/load failure blocks packaging before the source is touched and never
falls back to Compress-Archive, plaintext ZIP, or an arbitrary local library.

### 7.3 Remote-command and secret-input rules

Invoke-HHCommand may carry:

- the exact audited staging command and non-secret arguments;
- bounded typed artifact-secret-request, artifact-staged, final-manifest, and
  status output;
- small hashes, sizes, identifiers, and errors.

It must never carry:

- EVTX bytes, Base64, or file chunks;
- evtx_dump stdout or complete JSONL;
- normalized event batches or outbox bodies;
- API tokens, archive passwords, session secrets, or parser credentials.

The new secret-input channel may carry only one 43-byte, artifact-bound
outer-ZIP password to the approved packaging worker. It has its own byte count,
timeout, consumer identity, success/failure receipt, and ledger link, but never
records the bytes. It is not a general secret-capable Invoke-HHCommand
parameter and cannot be used by arbitrary commands.

Because the owning staging invocation holds the current core operation lock,
the product-contract amendment must define the fixed packager invocation as an
authenticated child operation of that exact core invocation. Before raw SSH
dispatch, the separately keyed forensics ledger records its immutable intent
and parent invocation ID; after exit it records the bounded outcome and links
the parent pipeline's matching staged record. The core command audit remains
authoritative for the parent PowerShell command, while this narrowly scoped
child-operation record is authoritative for the fixed helper dispatch. It
requires the same immutable target snapshot and acquisition nonce and cannot
execute caller script, arbitrary command, transfer, or delete. It is the sole
Phase 1 remote-mutation exception allowed alongside the owning operation lock.
The separately qualified read-only outer-ZIP retrieval may also overlap under
its transfer contract; all other remote mutations, including cleanup, remain
serialized behind the lock. If this child-operation/audit authority cannot be
accepted and qualified, progressive password-protected packaging is BLOCKED.

The existing rule that uncertain commands are not retried automatically still
applies. Transfer retryability must be separate from remote-command
retryability. Secret-delivery failure is a separate pre-packaging failure and
cannot silently regenerate or replace the saved secret.

### 7.4 Binary transfer

Select one endpoint-to-controller binary transfer implementation in Phase 0.
The recommended starting candidate is a host-key-pinned SFTP/SCP adapter over
the existing SSH trust boundary, subject to native controller qualification.

Phase 1 reuses the exact immutable target snapshot captured for the acquisition:
target profile generation, resolved host/port, username, direct PowerShell 7
runtime, managed known_hosts path, pinned host-key fingerprint, authentication
mode, and dedicated key path. Binary retrieval must revalidate that snapshot
and fail on any drift; it must not resolve a fresh mutable target profile.

Initial retrieval requires PublicKey authentication with the approved managed
key. A password-authenticated target must first complete the existing explicit
key-enrolment flow. A second interactive password prompt for SFTP/SCP is not
implicitly supported and requires separate qualification if ever added.

The remote acquisition creates one unique restricted staging root. Every
retrieval path is relative to and securely resolved beneath that root. The
adapter cannot read an arbitrary endpoint path, follow a link/reparse point, or
escape to the live Windows event-log directory.

The adapter must:

- require a durable accountable transfer intent before network activity;
- stream with bounded memory;
- write only to a resolved acquisition-specific partial path;
- support files larger than Invoke-HHCommand's output ceiling;
- accept only a sealed hosthunter.artifact-staged.v1 record and transfer its
  fixed encrypted outer-ZIP path;
- verify remote outer size/hash against the local copy before opening it;
- expose progress and stable error codes;
- append an immutable attempt/outcome receipt for each transfer or resume;
- distinguish restartable transfer from uncertain staging;
- prevent path traversal, symlink, reparse-point, and destination escape;
- never overwrite an existing verified package or source;
- preserve the partial for a declared resume/restart policy.

Whether Phase 1 resumes byte ranges or restarts one partial transfer is a
Phase 0 measurement decision. It must be explicit and safe for the largest
accepted file.

### 7.5 Remote outer-ZIP cleanup

Automatic cleanup becomes eligible only after all of these are durable:

1. the complete encrypted outer ZIP was received and its size/SHA-256 matched;
2. the saved Keychain password authenticated and decrypted every outer entry;
3. the extracted inner ZIP size/SHA-256 matched and it was atomically
    published locally;
4. the outer-received-and-decrypted receipt was written, read back, and linked
    into the authenticated forensics ledger.

This gate intentionally does not wait for EVTX parsing or API delivery: after
successful outer decryption, the complete inner evidence archive is already
durable locally. A wrong/missing password, authentication error, corruption,
partial transfer, receipt failure, or ledger failure leaves the remote outer
ZIP in place.

Eligibility is recorded immediately, but Phase 1 does not dispatch a second
remote mutation while the current `Invoke-HHCommand` staging invocation holds
HostHunter's global operation lock. Cleanup is placed on a durable queue and
is dispatched only after that staging invocation has closed and released the
lock. Parsing, API delivery, and UI progress do not wait for cleanup. Earlier
concurrent dispatch would require a separately confirmed core lock/audit
refactor and is not part of this plan.

The cleanup service accepts only `acquisition_id` and `artifact_id` from its
internal queue or `Retry-HHArtifactCleanup`. It loads acquisition nonce,
expected outer size/digest, recorded remote file identity, and the fixed
staging-root-relative role from the immutable staged and eligibility receipts;
callers cannot supply or override those values. It computes the only permitted
path itself:

    {restricted_staging_root}/{artifact_id}.transport.zip

It records durable intent before network activity and resolves beneath the
exact acquisition staging root. The qualified Windows cleanup helper opens the
leaf without following links/reparse points, obtains an exclusive handle,
requires the recorded volume/file identity plus exact size/hash through that
handle, and deletes by that same handle using the frozen atomic disposition
contract. A path-based check followed by `Remove-Item`/`File.Delete` is
prohibited because replacement between check and delete could remove different
bytes. If handle-bound validation/deletion cannot be qualified, cleanup fails
closed and leaves the file. The helper performs no wildcard, recursive, or
directory deletion, verifies absence, and appends an immutable outcome
receipt. The original/live event log, staged raw snapshot, any other remote
path, and every local archive/raw/receipt are unreachable by this function.

Cleanup states are NOT_ELIGIBLE, ELIGIBLE, INTENT_RECORDED, HELD_STOPPED,
DISPATCHED, COMPLETE, RECONCILED_ABSENT, RECONCILED_PRESENT, FAILED_MISMATCH,
FAILED, and UNKNOWN. HELD_STOPPED is the nonterminal state for eligible/intent-
recorded work blocked by Stop. The scheduler serializes Stop acknowledgement
and the local `INTENT_RECORDED -> DISPATCHED` commit under one per-acquisition interlock;
there is no state in which Stop reports success while a not-yet-dispatched
delete can begin. An uncertain delete is never automatically replayed. A read-only
exact-path reconciliation records absence as RECONCILED_ABSENT without
overstating how it disappeared. Exact handle-bound identity/hash agreement is
recorded as RECONCILED_PRESENT and permits only an explicit
`Retry-HHArtifactCleanup`, which creates a new intent/attempt. A changed,
linked, or mismatched file fails closed. Cleanup failure never invalidates
verified local evidence or blocks parsing.

## 8. Local Spool And Receipts

### 8.1 Publication sequence

For each manifest entry:

1. validate the pre-issued/recomputed acquisition_id, file_id, artifact_id,
    package_attempt_id, secret-delivery receipt, and saved outer_password_id
    against the staged record; never allocate or change package identity during
    local publication;
2. transfer only the encrypted outer archive to
    incoming/{artifact_id}.transport.zip.partial;
3. close/flush it, compute local size/SHA-256, and require exact staged-record
    agreement before opening it;
4. atomically publish the immutable encrypted outer beneath the private
    artifact store;
5. retrieve the password from Keychain in the bounded unpack worker, validate
    the exact outer structure/protection profile, authenticate/decrypt every
    entry to fixed partial paths, and verify the outer manifest;
6. require exact inner size/SHA-256 agreement, validate the complete inner ZIP
    structure, fixed entry set, methods, and resource bounds while it remains a
    private partial, then atomically publish that validated inner packaging
    artifact beneath the private store;
7. durably write/read back the outer-received-and-decrypted receipt, anchor its
    ledger transition, mark only the matching remote outer ZIP cleanup eligible,
    and queue it for dispatch after the staging operation lock is released;
8. stream the already structure-validated inner `payload.bin` to a fixed raw
    partial path and require exact raw size/SHA-256 agreement;
9. atomically publish the raw EVTX into the immutable evidence ready area;
10. durably write/read back the generic artifact-ready receipt and the
    event-log-specific file-ready receipt;
11. enqueue local parsing; and
12. retain the local encrypted outer ZIP, inner ZIP, raw EVTX, manifests,
    receipts, and Keychain password until a separately approved prune/key-
    destruction policy exists.

A partial, mismatched, unauthenticated, open, traversing, symlinked,
quarantined, or key-unavailable artifact is never parseable. Remote outer-ZIP
cleanup and local parser/API work proceed independently after their respective
gates.

Private artifact storage remains outside the Part 2 mount:

    forensics/artifacts/v1/{acquisition_id}/{artifact_id}/
      outer/{artifact_id}.transport.zip
      inner/{artifact_id}.evidence.zip
      receipts/outer-received-and-decrypted.json
      receipts/artifact-ready.json

Only a dedicated evidence export subtree is visible to Part 2:

    forensics/evidence/v1/
      ready/{acquisition_id}/{file_id}.evtx
      receipts/file-ready/{acquisition_id}/{file_id}.json
      receipts/acquisition-complete/{acquisition_id}.json

The versioned Part 2 mount alias is hosthunter-evidence-v1 and its container
root is /evidence. forensics.db, its ledger key/anchor, the core HostHunter
database/audit artifacts, target profiles, API clear token, managed known_hosts,
and SSH keys remain outside this subtree and can never be mounted into Part 2.
The artifact archive tree, archive-password Keychain references, secret-input
state, and remote-cleanup receipts also remain outside the mount. Part 2 sees
only verified raw EVTX plus the narrow file/acquisition receipts; it never
decrypts or expands HostHunter archives.
Phase 0 freezes owner/UID/mode behavior for Docker Desktop while preserving
owner-private host access.

### 8.2 Generic artifact receipts

The reusable capability owns two internal receipt schemas:

- hosthunter.outer-received-and-decrypted.v1 proves the encrypted outer bytes
  matched, every outer entry authenticated/decrypted, the manifest matched,
  and the exact inner archive was durably published. This immutable receipt is
  the remote outer-cleanup eligibility gate.
- hosthunter.artifact-ready.v1 proves the inner structure and raw payload also
  matched and the raw file was durably published.

They preserve separately asserted/observed raw, inner, and outer sizes/hashes;
both manifest digests; artifact/package/password-reference identities;
packager/unpacker implementation, version, RID, configuration digest,
compression and protection profiles; staging invocation, secret-delivery,
transfer, unpack, publication, and ledger receipt IDs; and relative provenance
paths. Password bytes, secret-derived verifiers, and absolute paths are never
present.

### 8.3 File-ready receipt

Persist one append-only receipt at:

    receipts/file-ready/{acquisition_id}/{file_id}.json

Schema name:

    hosthunter.file-ready.v1

Required fields:

| Field | Meaning |
| --- | --- |
| schema | Exact receipt schema identifier |
| evidence_mount_alias | Exact hosthunter-evidence-v1 alias |
| case_id | HostHunter-generated opaque forensics case UUID accepted by Part 2 |
| endpoint_id | Stable HostHunter endpoint identifier |
| acquisition_id | One endpoint-directory acquisition |
| file_id | Stable manifest entry identifier |
| source_id | Deterministic API source identity framed from case, endpoint, acquisition, file, and verified content digest |
| target_name | HostHunter target reference |
| source_relative_path | Endpoint-relative provenance path |
| channel_hint | Optional untrusted scheduling/display hint |
| manifest_size_bytes | Endpoint-asserted raw payload size |
| manifest_sha256 | Endpoint-asserted raw payload digest |
| verified_size_bytes | Controller-observed raw payload size |
| verified_sha256 | Controller-observed raw payload digest |
| spool_relative_path | Path beneath the configured local spool root |
| collected_at_utc | Endpoint snapshot/export time |
| verified_at_utc | Local verification time |
| staging_invocation_id | Link to the audited remote command |

Invariants:

- manifest and verified size/hash pairs agree;
- source_id matches the frozen canonical_tuple_v1 vector for the receipt;
- receipt publication follows durable file publication;
- paths are relative, normalized, and resolve beneath
  hosthunter-evidence-v1:/evidence;
- absolute endpoint/controller paths never cross the API;
- filename and channel are hints, not trusted event semantics;
- changed content receives a new source identity and never mutates the old
  receipt; and
- if this `source_id` already has a published file-ready receipt, HostHunter
  reuses that first receipt byte-for-byte, including its original
  `verified_at_utc` and `staging_invocation_id`; later successful package
  attempts update only private artifact receipts/ledger and never rewrite the
  mounted receipt or source PUT body.

This mounted cross-part receipt is intentionally raw-facing. `artifact_id`,
package-attempt identity, inner/outer sizes or hashes, encryption/compression
profiles, password references, secret-delivery/transfer/unpack receipts, and
cleanup state remain exclusively in HostHunter's private artifact receipts and
ledger. Repackaging the same raw source therefore cannot change the semantic
body of an existing Part 2 source resource. If no file-ready receipt was ever
published, the first successful package may create it normally.

### 8.4 Acquisition completion

Persist:

    receipts/acquisition-complete/{acquisition_id}.json

Schema name:

    hosthunter.acquisition-complete.v1

It includes case, endpoint, acquisition, final manifest digest, expected
file/source ID pairs, total raw file count/bytes, collection start/end times,
per-file endpoint collection/staging status, and outcome SEALED or ABORTED.
Per-file
manifest status is limited to the endpoint snapshot dimension, such as STAGED,
STAGE_FAILED, or NOT_OBSERVED. It does not claim transfer, local verification,
parsing, API delivery, or cleanup completion.

The acquisition remains OPEN until this receipt exists. A complete directory
manifest can seal collection while parsing remains incomplete; acquisition
completion and analysis completion are independent.

SEALED means the endpoint expected set is finalized and immutable, even if
individual entries record staging failures or local transfers remain active.
ABORTED means HostHunter could not finalize a trustworthy expected set. The UI
derives analysis readiness from separate source dimensions.

SEALED and ABORTED are immutable terminal resources. Continuing collection
after ABORTED creates a new acquisition_id and links it as a follow-up; it does
not rewrite the original outcome.

A separate HostHunter-private acquisition artifact roster retains each
file/artifact/package-attempt tuple plus raw/inner/outer counts, hashes,
password reference, transfer receipts, and cleanup state. That roster is not
mounted into or sent to Part 2.

## 9. Local Parser Contract

PowerShell orchestrates parsing; it does not implement the EVTX binary format.

Initial baseline:

    evtx_dump -t 1 -o jsonl verified-file.evtx

Before implementation, Phase 0 must reverify the current stable release,
supported macOS RIDs, exact SHA-256, licence, checksum-validation mode, output
shape, corruption behavior, warning classes, and exit codes. No PATH fallback
is allowed.

The runner must:

- execute the exact pinned binary by absolute validated path;
- use fixed arguments and single-thread deterministic record order;
- run only against a verified immutable source;
- read stdout one bounded line at a time;
- drain bounded stderr concurrently;
- enforce maximum raw line, JSON depth, string, stderr, wall-time, memory, and
  CPU limits;
- run without network access and with minimal filesystem visibility where the
  controller supports enforceable isolation;
- preserve parser identity, executable digest, source ordinal, diagnostics,
  and exit status;
- stop and fail the attempt on malformed JSONL or unsupported root shape;
- keep explicit salvage behavior separate and inactive by default;
- never create a whole-file JSONL artifact.

A valid source with no supported target records is a successful
COMPLETE_EMPTY result, not a parser failure.

## 10. Event Normalization Contract

### 10.1 Supported records

Phase 1 maps only:

- Microsoft-Windows-Sysmon event 1, process create; and
- Microsoft-Windows-Security-Auditing event 4688, new process.

Dispatch uses provider, event ID, and event version. Unknown target versions
become lossless-within-the-frozen-event-limit unsupported_target_record items
and warnings. Other event IDs are counted as ignored non-target records and
are not sent by default.

### 10.2 Common model

Every normalized output item is an ECS 9.5.0 document under the versioned
`hosthunter.process_start` contract. A supported Process Start requires:

- `@timestamp` and `ecs.version = 9.5.0`;
- `event.kind = event`, `event.category = [process]`,
  `event.type = [start]`, and `event.action = process-started`;
- source-specific `event.code`, `event.provider`, and `event.dataset`;
- stable `event.id`, `host.id`, `host.name`, `process.entity_id`,
  `process.pid`, `process.name`, and `process.start`; and
- bounded `hosthunter.*` provenance, parser, mapping, and source metadata.

An unsupported target version becomes a bounded ECS
`event.kind = pipeline_error` document with `error.*` and `hosthunter.*`
provenance. It never invents process facts or becomes a graph node. Other
event IDs are counted as ignored and are not emitted.

Each item preserves:

- case, endpoint, acquisition, source, run, and observation identifiers;
- source SHA-256, source ordinal, and raw record ID;
- provider name/GUID, channel, event ID/version, and computer claim;
- raw and parsed occurrence times;
- parser, producer, runtime, mapper, event-schema, ECS, and configuration
  versions;
- ordered target EventData pairs, including duplicates and null reasons;
- unconsumed fields and normalization warnings;
- a bounded parser-native representation with media type, encoding, bytes,
  digest, producer identity, and parser identity.

No API contract requires a future Rust producer to reproduce evtx_dump's JSON
serialization byte-for-byte.

### 10.3 Semantic rules

- Sysmon ProcessGuid becomes ECS process.entity_id and is retained raw.
- PID alone never becomes durable process identity.
- Security process and logon hexadecimal values preserve raw and parsed forms.
- Security 4688 Creator Subject maps to root ECS user fields.
- Security 4688 version 2 Target Subject maps to process.user only when
  genuinely populated; S-1-0-0, dash, and 0x0 placeholders remain raw and
  normalize as absent with a specific null reason.
- Command line may be absent and may contain secrets.
- Exact command lines are retained in protected canonical evidence when
  present, but never written to receipts, routine logs, console diagnostics,
  filenames, or unencrypted SQLite values. Phase 1 does not heuristically
  split a Windows command line into process.args.
- Invalid, missing, malformed, unsupported, and ambiguous values remain
  explicit.

Part 1 emits atomic Process Start observations only. It does not emit Process
Stop, coalesce Sysmon with Security, infer parent entity IDs from PID alone,
calculate duration, or make threat judgements. Those derived operations belong
to later mappings and Part 2.

## 11. Identity, Runs, Batches, And Outbox

### 11.1 Deterministic identity

Use a frozen length-framed canonical_tuple_v1 format and published
cross-language golden vectors. Never concatenate ambiguous strings.

endpoint_id is a random stable UUID created once for a case plus verified
HostHunter target identity and persisted in forensics.db. It is not derived
from a mutable target alias, folder name, hostname claim, or IP address. A
target profile replacement or authenticated identity/host-key change must
reconcile explicitly and either preserve a proven binding or create a new
endpoint_id; it must never silently reassign an existing host island.

Persist a physical-host binding with endpoint_id, case_id, authenticated
Windows machine identity, SSH host-key fingerprint, target profile generation,
target name, and runtime. Two PowerShell 7/WindowsPowerShell51 profiles may
refer to the same endpoint UUID only after an authenticated identity probe
proves the same physical Windows host; hostname or IP equality is insufficient.
Phase 1 acquisition still fails closed for a WindowsPowerShell51 runtime, but
the binding/migration prevents a future qualified runtime from creating a
duplicate host island. Identity drift creates an explicit reconciliation state
and tests cover profile replacement, host-key rotation, and two-runtime
profiles.

artifact_id identifies one sealed raw/inner/outer package. Rebuilding archive
bytes creates a new artifact_id, package_attempt_id, and random password. A
transfer retry keeps the same artifact_id, password reference, and exact outer
bytes. outer_password_id identifies a Keychain item only; it is never part of
source/event semantic identity. source_id continues to bind the verified raw
payload, so a packaging or encryption-version change does not create a new
forensic source when the raw bytes and frozen source tuple are unchanged.

run_id includes:

- source SHA-256;
- producer and runtime versions;
- serializer version;
- parser version and executable digest;
- mapper, event-schema, and ECS versions;
- configuration digest.

A changed input or interpretation creates a new run. Each execution receives a
random attempt_id. A stable observation ID includes immutable source identity
and deterministic source ordinal.

Event and batch semantic identity belongs to the deterministic run, not to one
execution attempt. attempt_id is delivery/execution metadata and must not
change observation IDs, batch bodies, or semantic digests. The API contract
uses the authenticated HostHunter-Attempt-Id header plus an append-only server
delivery record so a later attempt can replay the same run/sequence without a
false 409 conflict.

### 11.2 Batch boundaries

Initial limits, to validate in Phase 0:

- flush at 250 events; or
- flush at 512 KiB serialized request size, including the full envelope; or
- flush at end of file.

Do not use elapsed time as a boundary. A single event may form a singleton
batch up to a 1 MiB event ceiling. It is never split or truncated. A larger
event blocks the attempt with record_too_large.

For a source record beyond the frozen limit, the runner still records source
ordinal, observed byte count, streaming digest, parser identity, and a bounded
reason, then fails the attempt and marks analysis deferred/blocked for a larger
producer path. It never calls that record lossless, truncates it into an active
run, or continues to a misleading successful completion.

The exact HTTP body digest is sent in Content-Digest. Canonical semantic
digests include every evidence-bearing value and use shared golden vectors.

### 11.3 Generic durable API outbox and bounded batch body

Every API PUT, not only an event batch, is prepared in a generic durable
outbox before HTTP. An entry stores canonical resource URI, method, exact body
bytes, Content-Digest, Idempotency-Key, required attempt-attribution header
HostHunter-Attempt-Id when applicable, dependency resource keys, creation
order, attempt history, and the committed API receipt. Dependencies form a
graph:

Only deterministic non-secret headers are stored. Authorization is loaded from
Keychain and injected at send/reconciliation time, never persisted in the
outbox; token rotation therefore does not alter the semantic request.

    case -> endpoint -> acquisition -> source/deferral
                                      -> acquisition completion

    source -> run -> attempt -> batches -> run completion/failure

Acquisition completion depends only on the registered acquisition and verified
final manifest/expected set. It is sent as soon as that set is available and
does not wait for transfer, parsing, or event delivery. Run completion depends
on all deterministic batches for that run.

On startup, reconcile any SENDING entry through the shared PUT-receipt GET
resource, then replay or advance dependency order. If the API is unavailable
at acquisition start, HostHunter may continue staging, transfer, verification,
and receipt publication, but it does not start a parser until prerequisite API
resources are accepted. This prevents an unbounded normalized-event backlog.

A 507 response pauses API delivery as operator-retryable storage pressure. It
does not loop automatically or become a permanent schema rejection. After the
operator restores space, Resume reconciles the exact pending resource first.

The producer:

1. holds only the current batch in memory;
2. atomically persists the exact request bytes, body digest, run, attempt,
    sequence, ordinal range, and idempotency data before HTTP;
3. sends one PUT at a time;
4. retains identical bytes across timeout ambiguity;
5. advances only after a committed or identical-already-present receipt;
6. on restart, reconciles the pending PUT before launching the parser;
7. applies pipe backpressure while the API is unavailable and keeps draining
    bounded stderr;
8. after the outage budget, terminates/reaps the parser and records
    CANCELLED_BACKPRESSURE rather than parser failure;
9. retains at most one unacknowledged batch for the active file;
10. clears accepted sensitive body bytes only after the API receipt is
    durably recorded, retaining digest/range/count/receipt;
11. can replay the immutable EVTX from the beginning, with deterministic
    accepted batches becoming no-ops.

A rebuilt batch that has a different digest for an existing batch identity
blocks the run as NONDETERMINISTIC. It is never overwritten.

The stored attempt value records which execution prepared/sent the request; it
is not part of the persisted batch's semantic body. Reconciliation may resend
the same body under a later attempt attribution while preserving every delivery
attempt in operational history.

### 11.4 Local workflow database

Use a separate owner-private forensics.db with committed migrations:

| Table | Responsibility |
| --- | --- |
| acquisitions | Case/endpoint IDs, manifest, expected/terminal counts, collection state |
| endpoint_bindings | Stable case endpoint UUID, authenticated physical identity, target profile generations/runtimes |
| artifact_packages | File/artifact/package-attempt IDs, layer claims/verification, package/protection identities, immutable relative paths |
| artifact_secrets | Opaque artifact-bound Keychain references, password-contract version, and lifecycle state; never secret bytes or password verifiers |
| artifact_cleanup | Eligibility, immutable delete intent, fixed path role/hash, attempts, reconciliation, and receipts |
| source_files | File receipt, transfer and parser identities, counts, warnings, evidence and analysis states |
| producer_runs | Deterministic interpretation identity and state |
| producer_attempts | Random executions, timestamps, state, bounded diagnostics |
| event_batches | Deterministic run/sequence, digest, ordinal and event counts, state |
| api_outbox | Exact body/headers/digest/dependencies, attempts, receipt, and reconciliation state for every PUT |
| state_events | Append-only operational transitions for diagnosis and reconciliation |
| forensics_ledger | MAC/hash-chained acquisition, secret delivery, packaging, transfer, archive authentication, publication, processing, delivery, and cleanup intent/outcome |

Database, WAL, receipts, and spool metadata remain owner-private. They are
separate from HostHunter's command-audit database but link to its stable
invocation IDs. The forensics ledger uses its own Keychain key and monotonic
anchor; mutable tables are never presented as tamper-evident audit history.

## 12. API Client Contract

Part 2 owns the authoritative OpenAPI/event schemas and stable problem codes.
Part 1 pins an exact compatible contract release and digest. Part 1 owns the
file-ready and acquisition-complete semantics; their machine schemas are
co-maintained across the frozen boundary.

Phase 1 case authority is fixed: HostHunter generates the forensics case UUID
and creates/upserts it through PUT /cases/{case_id}. A caller may provide an
existing explicit ForensicsCaseId, which HostHunter verifies/attaches through
the same idempotent contract. The existing free-form command CaseId is retained
as optional provenance only and is never parsed or silently reused as the API
case UUID. Part 2 has no Phase 1 case-creation UI.

Part 1 sends:

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
    GET /api/v1/put-receipts/{idempotency_key}

The source PUT carries file_id, deterministic source_id, raw-facing receipt
schema, receipt-relative path, exact receipt-file digest, evidence mount alias,
spool-relative raw path, verified raw size/hash, and owning
case/endpoint/acquisition. It never carries `artifact_id`, package-attempt
identity, inner/outer size or hash, archive profile/path, password/reference,
secret/transfer/unpack receipt, or cleanup control/state. Part 2 loads the
mounted file-ready receipt and raw source and requires exact agreement rather
than trusting duplicated claims in the request; it does not open either ZIP
layer. If archive/package provenance is ever required by Part 2, it must use a
new separately keyed artifact resource rather than mutate a source body.
For an already published `source_id`, the outbox reuses the first exact
file-ready receipt digest and source PUT body bytes; package retries cannot
rebuild either body from newer private timestamps or invocation IDs.

All client-chosen resources use replay-addressable PUT:

- new valid resource: 201;
- semantically identical replay: 200 with original receipt;
- same URI and different semantic content: permanent 409;
- schema/auth/ownership error: stable permanent 4xx;
- oversized event/request: permanent 413;
- writer saturation: retryable 429 or 503 with Retry-After;
- disk pressure: stable 507 and PAUSED_API pending explicit operator resume;
- timeout: unknown commit, so replay identical bytes.

Part 1 must distinguish retryable from permanent errors and never loop on
authentication, authorization, schema, ownership, digest conflict, or size
rejection.

Every PUT carries a deterministic Idempotency-Key and the standard
Content-Digest header using sha-256 over the exact body bytes. Batch,
run-completion, and attempt-failure PUTs also carry HostHunter-Attempt-Id; the
attempt-creation PUT establishes that ID and does not require the header. The
header is authenticated delivery attribution, not semantic evidence identity.
Missing or mismatched headers receive stable problem codes. Receipt
reconciliation is authenticated and returns resource URI, semantic digest,
original status, and original receipt without exposing the request body.

HostHunter owns producer-token bootstrap:

1. Set-HHForensicsApiConfiguration creates 32 random bytes with the platform
    CSPRNG under ShouldProcess.
2. It writes the clear bearer token directly to macOS Keychain using stdin or
    an equivalent no-argument/no-log secret path.
3. It writes only token ID, sha-256 verifier, scopes, and timestamps to an
    owner-private verifier file for the Part 2 read-only secret mount.
4. Part 2 starts/reloads with that verifier and never receives the clear token
    at rest.
5. Rotation creates a new token/verifier, allows a short explicit two-verifier
    grace period, proves the new credential, then revokes the prior verifier.
6. Recovery from a missing Keychain item is explicit rotation; pending outbox
    entries remain intact.

The controller retrieves the clear API producer credential from Keychain only
for loopback API calls. That credential never enters command arguments, remote
PowerShell, audit output, receipts, event payloads, URLs, or diagnostic logs.
The separately scoped archive password follows section 7.2's secret-only input
contract and can never be substituted for the API credential. Viewer session
bootstrap remains a separate Part 2 responsibility.

## 13. State And Recovery

Keep independent dimensions:

| Dimension | States |
| --- | --- |
| Acquisition | OPEN, SEALED, ABORTED |
| Archive password | NOT_CREATED, REQUESTED, SAVING, SAVED, DELIVERING, DELIVERY_UNKNOWN, DELIVERED, KEY_UNAVAILABLE, DESTROYED |
| Artifact package | DISCOVERED, PACKAGING_INNER, PACKAGING_OUTER, STAGED, TRANSFERRING, VALIDATING_OUTER, INNER_READY, RAW_READY, QUARANTINED |
| File evidence | DISCOVERED, STAGING, VERIFIED, QUARANTINED |
| Analysis | QUEUED, STAGING, READY, READY_WITH_WARNINGS, COMPLETE_EMPTY, PAUSED_API, DEFERRED, FAILED |
| Run | STAGING, ACTIVE, SUPERSEDED, NONDETERMINISTIC |
| Attempt | RUNNING, SUCCEEDED, FAILED, CANCELLED_BACKPRESSURE |
| Batch | PREPARED, SENDING, ACCEPTED, RETRYABLE, REJECTED |
| Remote outer cleanup | NOT_ELIGIBLE, ELIGIBLE, INTENT_RECORDED, HELD_STOPPED, DISPATCHED, COMPLETE, RECONCILED_ABSENT, RECONCILED_PRESENT, FAILED_MISMATCH, FAILED, UNKNOWN |

Required behavior:

| Failure | HostHunter behavior | Recovery |
| --- | --- | --- |
| Remote staging uncertain | Preserve Unknown; do not automatically repeat command | Investigator reconciles endpoint state |
| Archive password cannot be saved/read back/delivered | Do not create or accept a sealed outer artifact | Restore Keychain/channel and reconcile the same artifact-bound request; never send through an ordinary argument or generate a replacement under the same artifact_id |
| Password delivery/helper outcome uncertain | Persist DELIVERY_UNKNOWN; do not resend, regenerate, transfer, or clean up | Read-only reconcile the fixed child outcome and exact expected outer; accept only a fully sealed matching result, otherwise require an explicit safe new-attempt decision |
| Crash before sealed outer | Quarantine the bounded outer partial and keep package-attempt evidence; no remote inner exists and nothing is announced/transferred | Repackage from the unchanged staged raw source only under a new authorized attempt/artifact/password; partial pruning needs a separate approved maintenance action |
| Crash after sealed outer | Do not rebuild or change password under that artifact_id | Reconcile the staged record and reuse exact outer bytes |
| Transfer interrupted | Keep partial and transfer receipt | Resume or explicitly restart under chosen policy |
| Missing key, wrong password, or outer authentication failure | Quarantine; never publish inner/raw or delete remote outer | Recover the exact saved Keychain password or investigate; never regenerate/fallback under the same artifact_id |
| Layer/manifest/hash mismatch or archive-limit breach | Quarantine; never parse or delete remote outer | Re-transfer, then operator review on repetition |
| Controller crash after publication | Recover receipt/file mismatch deterministically | Finish receipt or quarantine; never publish twice |
| Secret saved but package absent | Retain orphaned Keychain/state reference and ledger evidence | Audited reconciliation; no silent reuse or deletion |
| Parser digest/RID mismatch | Do not execute | Install approved artifact |
| Parser nonzero/malformed/oversized output | Fail attempt; keep run staged | Retry immutable file or create new run after corrected inputs |
| API timeout | Re-PUT exact pending body | Reconcile idempotently |
| API outage beyond budget | Reap parser, pause source | New attempt replays immutable source |
| Permanent API rejection | Retain diagnostics and rejected digest | Correct contract/config and create valid run |
| Batch content conflict | Mark NONDETERMINISTIC | Investigate; never overwrite |
| File beyond measured PowerShell limits | Register DEFERRED with exact reason | Future compatible Rust producer |
| Remote outer deletion uncertain | Preserve UNKNOWN; never claim cleanup or auto-replay | Read-only handle-bound reconciliation to RECONCILED_ABSENT, RECONCILED_PRESENT, or FAILED_MISMATCH; only RECONCILED_PRESENT permits explicit audited retry |
| Stop races with cleanup dispatch | Take the cleanup scheduler interlock and database transition before acknowledging Stop | Anything not already durably DISPATCHED becomes HELD_STOPPED; only a pre-existing DISPATCHED attempt is reconciled as potentially in flight |
| Remote outer deletion mismatch/fails | Preserve file and bounded diagnostics | Never delete changed bytes; explicit operator review while local acquisition stays valid |

Acquisition sealing does not mean every file is analyzed. A file completion
request to Part 2 is sent only after all deterministic batch sequences and
counts reconcile and the parser exits under the frozen success policy.

## 14. Security And Privacy

Trust boundaries:

1. potentially compromised endpoint to staged EVTX;
2. controller Keychain through the secret-only SSH input to endpoint packager;
3. endpoint encrypted outer ZIP to binary transfer;
4. transfer to password retrieval and untrusted nested-archive validation;
5. validated raw EVTX to native parser;
6. PowerShell producer to loopback API;
7. local state, archives, and credentials to controller user;
8. cleanup coordinator to the exact generated remote outer ZIP.

Required controls:

- strict SSH host-key verification and no trust bypass;
- controller-CSPRNG password, Keychain-only storage/read-back, secret-
  only bounded input, short-lived workers, and no secret argument/environment/
  file/log/audit path;
- one approved authenticated AES-256 ZIP profile for every outer entry and no
  ZipCrypto/plaintext/mixed-entry fallback;
- exact target/path ownership and no endpoint-controlled destination;
- exact two-layer/fixed-entry validation; partial isolation; path, ZIP64,
  expansion, ratio, entry-count, CPU, memory, time, and disk bounds; symlink,
  reparse, ADS, special-entry, overlap, prefix/trailing-data, and collision
  rejection;
- outer authentication plus raw/inner/outer size/hash verification before
  their respective publication gates;
- parser version/digest/RID pinning and no PATH fallback;
- parser network denial and bounded CPU, memory, time, stdout, stderr, JSON
  line, depth, and string limits;
- owner-private encrypted outer, inner, raw spool, receipts, state DB, WAL, and
  configuration; archive passwords remain separately in Keychain;
- Keychain-backed API credential reference;
- request/event/batch bounds and deterministic digests;
- text-only bounded diagnostics;
- no raw event payload, complete command line, archive password, token, or
  credential logging;
- automatic deletion is limited to one exact hash-matching generated remote
  outer ZIP after the durable receipt-and-decryption gate; originals, staged
  raw sources, and all local evidence are excluded;
- dependency/SBOM audit, gitleaks, native parser provenance, and encrypted-ZIP
  library/helper provenance.

Password protection protects a captured outer archive from disclosure; it does
not authenticate a potentially compromised endpoint, replace SSH host-key
verification, or make double compression forensic proof. Layer hashes,
immutable receipts, and the authenticated forensics ledger remain the
provenance and integrity authority.

A repository-grounded security threat model for this feature is mandatory
after contract confirmation and before implementation/push. Critical/high
findings block work until addressed or explicitly rescoped.

## 15. Requirements Ledger

| ID | Requirement | Acceptance proof | Status |
| --- | --- | --- | --- |
| HH-R-001 | Begin implementation only after the Part 1 contract is confirmed | Explicit user confirmation and amended contract | Confirmed 2026-08-25 |
| HH-R-002 | Acquire complete event-log directories, not a four-event filter | Manifest fixture and endpoint journey | Confirmed |
| HH-R-003 | Parse only after local transfer and verification | Partial/hash/path fault tests | Confirmed |
| HH-R-004 | Keep EVTX, JSONL, batches, and secrets out of Invoke-HHCommand output | Large-file integration plus audit inspection | Confirmed |
| HH-R-005 | Publish each verified file progressively | Multi-file journey proves first file starts before acquisition seal | Confirmed |
| HH-R-006 | Use local PowerShell with a pinned native parser | Runner and RID qualification | Confirmed |
| HH-R-007 | Map only Sysmon 1 and Security 4688 initially; defer Process Stop | Golden mapper fixtures and negative event-ID cases | Confirmed |
| HH-R-008 | Emit ECS 9.5.0 Process Start or bounded ECS pipeline-error documents under hosthunter.process_start v1 | Pinned field artifact, JSON Schema, and golden contract suite | Confirmed |
| HH-R-009 | Preserve ordered provenance and explicit null/unsupported states | Mapper boundary fixtures | Proposed |
| HH-R-010 | Deliver deterministic bounded all-or-nothing batches | Cross-language vectors and API stub tests | Proposed |
| HH-R-011 | Persist one pending exact request before HTTP | Kill-point tests | Proposed |
| HH-R-012 | Resume local work without endpoint recollection | Restart journey | Confirmed |
| HH-R-013 | Keep acquisition, secret, package, evidence, analysis, attempt, delivery, and cleanup states separate | State-machine unit/E2E proof | Proposed |
| HH-R-014 | Defer oversized/resource-expensive files truthfully | Limit tests and API deferral receipt | Confirmed |
| HH-R-015 | Choose the PowerShell cutoff from measurements, not file size alone | Benchmark report | Confirmed |
| HH-R-016 | Preserve immutable raw EVTX for reprocessing | Source mutation/rebuild proof | Confirmed |
| HH-R-017 | Scope credentials to the controller and redact diagnostics | Negative security tests | Proposed |
| HH-R-018 | Keep mutable forensics workflow state separate from core command audit | Migration/recovery/audit regression proof | Proposed |
| HH-R-019 | Expose explicit operator start/status/stop/resume/retry actions | Fresh-process CLI E2E for every command | Proposed |
| HH-R-020 | Update Part 2 while acquisition remains open | Cross-part two-endpoint E2E | Confirmed |
| HH-R-021 | Future Rust uses unchanged receipts and event API | Producer parity contract | Confirmed |
| HH-R-022 | Record immutable acquisition and binary-transfer intent/outcome around mutable workflow state | Audit/transfer crash and retry tests | Proposed |
| HH-R-023 | Consume bounded artifact-secret-request and artifact-staged records while the audited remote pipeline is running | Live observer plus overlapping-child/transfer integration test | Proposed |
| HH-R-024 | Bind a stable case endpoint UUID to verified target identity without hostname/alias rekeying | Target replacement and identity-change tests | Proposed |
| HH-R-025 | Fail closed on unqualified forensics controller RIDs without changing core RID claims | RID negative and native osx-arm64 qualification | Proposed |
| HH-R-026 | Load the forensics feature through a validated deterministic load-order/package contract | Clean-process import/package tests | Proposed |
| HH-R-027 | Authenticate acquisition/transfer intent and outcome in a separately keyed/anchored forensics ledger | Chain/anchor rollback and crash tests | Proposed |
| HH-R-028 | Persist and reconcile every API PUT through one dependency-ordered exact-byte outbox | Unknown-commit/startup/API-down tests | Proposed |
| HH-R-029 | Create the Phase 1 case UUID in HostHunter and keep free-form CaseId as provenance only | Case attach/conflict CLI/API tests | Proposed |
| HH-R-030 | Mount only the dedicated versioned evidence subtree into Part 2 | Mount/path/secret-exclusion tests | Proposed |
| HH-R-031 | Bootstrap/rotate the API producer token without plaintext arguments, logs, files, or container storage | Keychain/verifier/rotation tests | Proposed |
| HH-R-032 | Describe unsupported records as lossless only within the frozen event limit | Oversized-record digest/deferred tests | Proposed |
| HH-R-033 | Put every extracted file through exactly two HostHunter ZIP wrapper layers, including already-ZIP inputs | Structure fixtures and cross-cmdlet E2E | Confirmed |
| HH-R-034 | Require every endpoint file-extraction cmdlet to use the root-loaded shared packaging/validation/cleanup capability with no direct bypass | Load-order/AST architecture rule plus event-log and synthetic-consumer contracts | Confirmed |
| HH-R-035 | Protect every outer ZIP with its own independently CSPRNG-generated high-entropy HostHunter-managed password that HostHunter saves/read-backs before sealing and later retrieves for local decryption | Persistence, request/replay, restart, uniqueness/profile, and Keychain tests | Confirmed |
| HH-R-036 | Provision and digest-verify one pinned authenticated AES-256 ZIP64 implementation/helper set, encrypt every outer entry with the frozen profile, and reject ZipCrypto, plaintext, mixed, wrong-key, unpinned, or fallback paths | Provision/load failure, interoperability, and negative corpus | Proposed |
| HH-R-037 | Keep archive passwords/references and private archive receipts out of script/command arguments, PSRP serialization, environment, process command lines, files, logs, audits, cross-part receipts, Part 2 mounts/API data, and crash artifacts | Cross-boundary secret-leak and mount-negative inspection | Proposed |
| HH-R-038 | Transfer only a closed, hashed, immutable password-protected outer ZIP | Partial/close/hash/transfer fault tests | Confirmed |
| HH-R-039 | Publish the inner/raw artifacts only after outer authentication and layer/manifest/hash validation | Corrupt/wrong-key/kill-point tests | Proposed |
| HH-R-040 | Preserve immutable local outer, inner, and raw artifacts with separate hashes and ledger-linked receipts | Readback, mutation, and provenance tests | Proposed |
| HH-R-041 | After durable receipt and successful outer decryption, queue cleanup behind the staging lock and use handle-bound identity/hash deletion for only the matching generated remote outer ZIP, never an original/live or staged raw source | Lock-order/atomic cleanup E2E and byte-identical source assertions | Confirmed |
| HH-R-042 | Treat uncertain remote cleanup independently, reconcile read-only, and never automatically replay a delete | Delete-dispatch crash/reconciliation tests | Proposed |
| HH-R-043 | Fail safely on archive/disk/entry/expansion/ratio/CPU/memory/time bounds | Malicious corpus and pressure benchmarks | Proposed |
| HH-R-044 | Report measured raw/inner/outer sizes and never claim the second ZIP guarantees further compression or evidence authenticity | Benchmark report and documentation assertions | Proposed |

## 16. Implementation Phases

### Phase HH-0 - Amendment And Contract Freeze

1. Confirm section 18.
2. Amend the HostHunter product contract as a post-v1 optional forensics
    capability.
3. Freeze the root-loaded ExtractionArtifacts manifest before the explicit
    Forensics load manifest, plus the root loader, exports, package contents,
    and clean-import qualification.
4. Freeze case ownership, IDs, receipt schemas, event union, canonical
    identity/digest vectors, batch limits, API errors, and credential bootstrap
    with Part 2.
5. Freeze hosthunter.artifact-secret-request.v1,
    hosthunter.artifact-staged.v1, both archive manifest schemas, both generic
    local receipt schemas, exact fixed entry sets, file/artifact/password/
    package-attempt identity, and the no-bypass architecture rule.
6. Select and qualify the Windows directory-snapshot primitive.
7. Select and qualify a pinned in-process authenticated AES-256 ZIP64 reader/
    writer and fixed relay/cleanup helper set on Windows PowerShell 7 and
    osx-arm64. Record exact version, RID, files, digests, licence, SBOM,
    interoperability, authentication semantics, secret handling, large-file
    behavior, malicious-archive limits, controller-to-endpoint provisioning,
    verified-path loading, cache/retention, upgrade, and rollback.
    Compress-Archive, global/PATH resolution, dynamic download, and secret-
    bearing external command lines are excluded.
8. Freeze and prove the controller-CSPRNG/password format, artifact-ID
    pre-issue/recomputation, Keychain namespace/read-back, and bounded
    raw-SSH child packager/secret-input channel, including its parent-invocation
    audit authority and DELIVERY_UNKNOWN reconciliation. Publish deterministic
    ID and encoding vectors and
    fail closed if secret bytes appear in any normal argument/audit/output/file/
    environment/process-list surface.
9. Select and qualify the binary transfer adapter and resume/restart policy.
10. Freeze the exact remote outer-cleanup gate, queue-after-staging-lock order,
    handle-bound identity/hash deletion, read-only uncertain reconciliation,
    Stop/Resume semantics, and password/local archive retention.
11. Reverify evtx_dump version, digest, RIDs, licence, strict checksum behavior,
    and parser resource-isolation mechanism.
12. Obtain approved synthetic/redacted fixtures and representative file-size
    distributions.
13. Benchmark raw/inner/encrypted-outer sizes and packaging/unpack time for
    zero-byte, 100 MiB, 1 GiB, sparse, dense, already-compressed, corrupt, and
    largest-realistic sources. Freeze methods, levels, capacity formula,
    expansion/ratio/entry, time, CPU, memory, and deferral limits without
    assuming the second ZIP is smaller.
14. Freeze the separately keyed/anchored forensics ledger and recovery model.
15. Freeze the authenticated physical-host identity fields and two-runtime
    profile-binding rules.
16. Confirm direct PowerShell 7 plus PublicKey as the first supported
    acquisition profile and fail-closed errors for other profiles/transports.
17. Complete $feature-design-preflight and the formal
    $security-threat-model.

Exit: accepted contract amendment, frozen shared v1 schemas, qualified secret
channel and AES ZIP implementation, measured limits, and no unresolved
critical/high security blocker. Failure to qualify either secret delivery or
authenticated ZIP support is a BLOCKED outcome, never a weaker fallback.

### Phase HH-1 - Acquisition And Immutable Publication

- implement endpoint directory staging and bounded manifest;
- implement the reusable exact-two-ZIP artifact services, Keychain password
  lifecycle, artifact-secret-request/relay, pinned helper provisioning, AES
  outer protection, layer manifests, and no-bypass architecture test;
- add the accountable live artifact-staged observer seam and reconciliation with
  the final manifest;
- implement encrypted-outer-only transfer, bounded safe unwrapping, immutable
  outer/inner/raw publication, private generic/raw-facing file receipts, and
  queued handle-bound remote outer cleanup/reconciliation;
- implement acquisition OPEN/SEALED/ABORTED publication;
- add local state migrations and recovery;
- expose start/status/stop plus explicit safe transfer and cleanup retry.

Exit: two-endpoint fixture proves progressive file-ready publication, large
encrypted binary transfer, password recovery, exact remote outer deletion
without source deletion, crash recovery, and bounded secret-free audited
command output.

### Phase HH-2 - Parser, Normalizer, And Outbox

- implement pinned parser resolver/runner and resource bounds;
- implement strict JSONL shape reader and two versioned Process Start mappers;
- implement event/run/batch identity and golden vectors;
- implement the bounded durable outbox and API client;
- expose local resume and reconciliation status.

Exit: golden, corrupt, oversized, warning, crash, timeout, duplicate, and
permanent-rejection journeys pass without recollection or nondeterminism.

### Phase HH-3 - Cross-Part Integration

- integrate against the real Part 2 contract and container;
- prove case/endpoint/acquisition/source/run/attempt/batch/completion ordering;
- prove one then two endpoints populate progressively;
- prove empty, warning, deferred, failed, retry, restart, and API outage states;
- verify raw EVTX remains immutable and every delivered event traces to its
  source receipt, core staging invocation, and authenticated forensics-ledger
  record.

Exit: Part 1 cross-part acceptance is green.

### Phase HH-4 - Release Qualification

- reconcile the acceptance and test ledgers;
- update docs, help, inventories, package/SBOM, migrations, and rollback;
- run $test-readiness-preflight;
- run focused changed-scope coverage and the canonical full local container
  gate;
- run native macOS RID qualification;
- before push, run feature threat-model review, gitleaks, dependency audit,
  parser/package scan, and the repo's slim pre-push lanes.

GitHub performs no validation rerun.

## 17. Test And Proof Plan

### Unit

- artifact-secret-request, inner/outer manifest, artifact-staged, generic
  receipt, and file receipt validation;
- exact two-layer/fixed-entry schema, raw/inner/outer identity/hash binding,
  and source-versus-artifact identity;
- CSPRNG/Base64url and deterministic ID golden vectors, password/reference
  lifecycle, duplicate/conflicting secret requests, and secret redaction/non-
  serialization;
- archive path/name/type/encryption/compression/entry/depth/size/ratio/ZIP64
  validation and checked capacity arithmetic;
- cleanup eligibility, queue-after-lock ordering, handle-bound file identity/
  hash deletion, Stop/Resume behavior, and uncertain outcome reconciliation;
- AST architecture rule allowing packaging, transfer, expansion, and remote
  outer deletion only through approved private adapters;
- root ExtractionArtifacts-before-Forensics load-manifest ordering and export/
  package inventory;
- path normalization and destination confinement;
- physical endpoint/profile binding and identity-drift reconciliation;
- forensics ledger chain/MAC/anchor transitions;
- acquisition/secret/package/file/run/attempt/batch/cleanup state transitions;
- parser executable identity and argument construction;
- bounded JSONL scalar, array, null, duplicate-field, line, depth, and string
  handling;
- provider/event/version dispatch and the Sysmon 1/Security 4688 mappings;
- raw/parsed GUID, PID, logon, time, placeholder, and null cases;
- canonical tuple, event, run, sequence, and semantic digest vectors;
- event/count/byte batch boundaries and oversized singleton behavior;
- retry classification, redaction, and status projection.

Repository-wide coverage remains at least 90 percent for statements, branches,
functions, and lines. New/materially changed logic targets at least 95 percent
changed-scope coverage with meaningful success, failure, edge, and transition
assertions.

### Integration

- complete directory enumeration and final manifest;
- typed artifact-secret-request and artifact-staged records observed before
  remote completion, with password relay, transfer, and local processing
  overlapping later staging;
- observer queue saturation/cancellation, sequence/nonce/path validation, and
  oversized manifest-artifact reconciliation;
- active/locked log snapshot semantics;
- EVTX, text/log, zero-byte, large, non-ASCII source-name, and already-ZIP
  inputs all receive exactly two wrapper layers through the same capability;
- real event-log plus synthetic second extraction consumers prove reuse and the
  no-direct-ZIP/transfer/delete boundary;
- controller-to-endpoint helper bootstrap verifies the pinned files on the
  endpoint and fails before packaging on altered/missing/wrong-RID/PATH/GAC/
  load errors, with upgrade and rollback compatibility proof;
- files larger than 100 MiB transfer as encrypted outer archives while command
  output remains bounded;
- matching Windows/macOS AES ZIP interoperability, unique random passwords,
  wrong/missing password, ZipCrypto, mixed encrypted/plain, unsupported
  profile/strength, and authentication-tag failure;
- secret channel failure/restart and proof that password bytes are absent
  from script/command arguments, PSRP serialization, environment, process
  list, normal streams, audit artifacts, database, manifests, receipts, API
  data, URLs, logs, temp files, and crash diagnostics;
- duplicate artifact-secret requests reuse only the already saved matching
  password; conflicting/unknown delivery never regenerates under the same
  artifact ID; no standalone remote inner ZIP is created;
- exact target-snapshot/PublicKey/known_hosts/fingerprint enforcement and
  staging-root-only reads;
- partial encrypted-outer exclusion, restart/resume, raw/inner/outer/manifest
  corruption, path traversal, drive/UNC/ADS names, duplicate/case/Unicode
  collisions, symlink/reparse/device entries, third/extra/missing layers,
  header overlap/disagreement, prefix/trailing data, spanned/malformed ZIP64,
  bombs, unsupported methods, and endpoint/controller disk pressure;
- frozen raw/inner/outer size and CPU benchmarks prove actual compression
  results without promising that outer is smaller;
- kill points after secret save/delivery, inner close, outer close,
  artifact-staged announcement, partial transfer, outer verification,
  authenticated decrypt, inner publication, cleanup eligibility/delete intent/
  delete dispatch, raw publication, file receipt, mid-parse, outbox commit, API
  commit, and before local receipt;
- no remote outer deletion on any incomplete receipt/decryption path;
  successful cleanup waits for the staging operation lock, validates and
  deletes through the same exclusive file handle, and removes only the exact
  expected outer ZIP while original/live and staged raw files remain byte-
  identical; Stop suppresses queued cleanup, uncertain delete reconciles
  without automatic replay, and retained local outer reopens from Keychain;
- repackaging identical raw bytes changes private artifact identity while
  byte-for-byte reusing the first file-ready receipt and source PUT, without an
  idempotency conflict;
- real pinned parser with approved EVTX fixtures;
- corrupt checksum, malformed JSONL, oversized line/event, stderr flood,
  timeout, CPU/memory bound, and explicit salvage separation;
- API 429/503/507, timeout, duplicate PUT, conflict, invalid token, schema
  rejection, and accepted receipt reconciliation;
- dependency-ordered exact-byte outbox recovery for every non-batch and batch
  PUT, including API unavailable at startup;
- producer-token bootstrap, verifier mount, rotation grace, revocation, and
  missing-Keychain recovery without plaintext leakage;
- zero target records and unsupported target versions;
- processing a file before acquisition seal;
- the first file reaches raw publication and graph ingestion while later files
  are still packaging;
- immutable replay and new mapper run without overwriting prior evidence;
- PowerShell-deferred source accepted later by a contract-test producer.

### CLI service journeys

Every accepted public command needs black-box fresh-process coverage for:

- help, validation, missing configuration, and permission failures;
- one endpoint and two endpoints;
- acquisition start and status progression;
- WhatIf/Confirm with no mutation and one acquisition ID per selected target;
- direct PowerShell 7/PublicKey success plus stable WindowsPowerShell51,
  password-transfer, unqualified controller RID, and WinRM fail-closed paths;
- safe stop, local resume, and explicit transfer retry;
- automatic cleanup eligibility plus dispatch after the staging lock releases,
  explicit Stop/Resume behavior, and explicit cleanup status/reconciliation/
  retry, including offline, absent, present, changed-hash, link, and unknown
  outcomes;
- uncertain remote command with no automatic replay;
- API offline/online reconciliation;
- clean, warning, empty, deferred, failed, and aborted outcomes;
- archive passwords, credentials, and event values absent from output/
  logs; original/live files remain present after cleanup.

The CLI journeys are Part 1's Playwright-equivalent user-action layer.

## 18. Shared Understanding Contract

### Confirmed

- James confirmed this amended contract on 2026-08-25.
- Part 1 is the set of changes required in HostHunter.
- HostHunter extracts complete event-log directories to the local Mac.
- HostHunter processes each verified local EVTX through PowerShell plus a
  native parser.
- HostHunter sends events to the Part 2 API.
- Files and endpoints fill the downstream view progressively.
- Every file extraction uses one reusable HostHunter capability to put the
  source through exactly two ZIP wrapper layers before transfer.
- The outer ZIP is password-protected with a random HostHunter-managed secret
  that HostHunter saves and later uses for local extraction.
- After confirmed receipt and successful outer decryption, HostHunter removes
  only the generated remote outer ZIP. Eligibility is immediate; audited
  dispatch waits for the current staging operation lock to release. It does
  not remove the original/live file or staged raw source.
- ECS 9.5.0 is the canonical representation for every normalized HostHunter
  event; HostHunter-specific provenance uses the governed `hosthunter.*`
  namespace.
- Initial normalization emits only Sysmon event 1 and Security event 4688
  Process Start documents. Process Stop is deferred.
- Full command lines are retained only in protected canonical evidence when
  present, with a non-blocking sensitivity warning and no routine logging.
- Rust and non-process semantics are deferred.
- The implementation starts with the local verified-EVTX to ECS vertical slice
  before remote acquisition and cleanup are enabled.

### Confirmed implementation defaults

- this is a separately gated post-v1 feature in the
  HostHunterNextGeneration repository;
- the first forensics controller qualification is osx-arm64 and other
  controller RIDs fail closed until separately proven;
- the framework-wide ExtractionArtifacts capability loads into the existing
  module scope through a validated explicit manifest before the separate
  Forensics manifest;
- ECS 9.5.0 plus governed HostHunter provenance is the event model;
- HostHunter generates/upserts the opaque forensics case UUID and owns
  endpoint, acquisition, file/source, run, attempt, and batch IDs;
- each acquisition covers exactly one endpoint and one requested event-log
  directory;
- every outer artifact receives an independently generated 32-byte controller-
  CSPRNG password, encoded as unpadded Base64url and saved/read back under its
  opaque artifact-bound Keychain reference before secret delivery and sealing;
- both outer entries use one authenticated AES-256 ZIP profile, provisionally
  WinZip AES AE-2, and fixed non-sensitive names;
- the matching pinned Windows helper/library is provisioned through a narrowly
  audited controller-to-endpoint bootstrap, digest-verified before exact-path
  load, and never resolved from PATH/GAC or a dynamic download;
- the inner ZIP deflates the raw payload; the outer stores the already-
  compressed inner entry and deflates its small manifest unless benchmarks
  justify another frozen profile;
- double ZIP is mandatory but is never described as guaranteed additional
  compression, encryption by nesting, or proof of endpoint authenticity;
- SFTP/SCP with the frozen target snapshot and PublicKey authentication is the
  first binary-transfer candidate;
- direct PowerShell 7 is the first target runtime; WindowsPowerShell51 and
  WinRM fail closed for this feature until separately qualified;
- mutable workflow state and a separately keyed/anchored forensics ledger
  coexist in forensics.db;
- one parser process runs at a time initially;
- batches flush at 250 events or 512 KiB, with a 1 MiB singleton ceiling;
- local encrypted outer, inner, and verified raw EVTX plus archive passwords
  have no automatic deletion in Phase 1;
- source files beyond measured limits become DEFERRED for future Rust;
- HostHunter creates the scoped producer token, keeps it in Keychain, and gives
  Part 2 only its verifier;
- the exact generated remote outer ZIP becomes automatically cleanup-eligible
  after durable receipt and authenticated outer decryption to a verified inner
  ZIP; dispatch waits for the staging operation lock and uses handle-bound
  identity/hash validation, remains independently visible, and uncertain
  deletion is never automatically replayed;
- original/live endpoint files, staged raw sources, other remote paths, and all
  local evidence are never targets of that automatic cleanup.

### Open technical validations, not client requirements

- exact Windows snapshot/export primitive for active logs;
- exact authenticated AES ZIP64 library/helper, pinned version, endpoint
  provisioning/cache, and upgrade/rollback contract;
- raw-SSH fixed child-packager mechanism, parent-invocation audit authority,
  password/profile, memory-erasure boundary, and Windows/macOS
  interoperability;
- exact raw/inner/outer compression methods, capacity formula, and archive-
  bomb/resource limits from benchmark evidence;
- exact SFTP/SCP implementation and partial-transfer policy;
- parser strict-checksum argument and enforceable macOS resource sandbox;
- PowerShell/Rust cutoff and processing concurrency;
- raw retention and backup policy before production hardening;
- handling of non-EVTX files found in the requested directory.

Feature-preflight verdict: READY for Phase HH-0 and the local verified-EVTX to
ECS Process Start vertical slice. Remote acquisition remains CONDITIONAL until
Phase HH-0 qualifies both the non-logging secret-input channel and one
authenticated AES ZIP64 reader/writer. No safe fallback is pre-approved.

### Implementation gate

Passed on 2026-08-25 when James replied:
`Confirm Part 1 ECS Process Start contract`.

## 19. Parallel Work

Parallel work is applicable only after the contract and final behavior are
frozen.

| Lane | Write ownership | Expected evidence |
| --- | --- | --- |
| Main integration | Contract amendment, module exports, acceptance/test ledgers | Frozen cross-part contract and integrated proof |
| Artifact security | Package schemas, pinned helper provisioning, Keychain password lifecycle, secret relay, AES ZIP writer/reader, safe unpack, cleanup | Cross-platform crypto, secret-leak, malicious-archive, cleanup, and kill-point proof |
| Acquisition/transfer | Forensics directory acquisition, encrypted-outer transfer, spool, receipts | Directory, large-file, path, hash, and crash tests |
| Parser/normalizer | Runner and mapping modules | Golden/malicious fixtures and coverage |
| State/outbox/API client | Forensics DB, delivery, reconciliation | Migrations, kill points, API fault tests |
| Security review | Report first; remediation only after agreement | Threat model and control traceability |
| Validation audit | Test/report surfaces without overlapping production code | Coverage, CLI inventory, gate reconciliation |

Every worker must receive the same final contract, disjoint ownership, mapped
focused tests, and notice that other agents are editing concurrently. The main
agent owns integration, migrations, stale-test updates, threat-model review,
gitleaks, and the canonical gate.

## 20. Definition Of Done

Part 1 implementation is done only when:

- the HostHunter product amendment and public command surface are confirmed;
- the framework ExtractionArtifacts manifest loads deterministically before
  the Forensics manifest from the packaged artifact;
- the shared receipt/event/API contracts are versioned and pinned;
- the separate forensics ledger chain/anchor and mutable workflow recovery are
  proven;
- every extraction command is mechanically prevented from bypassing the shared
  exact-two-ZIP artifact capability;
- complete directories and large EVTX files transfer only as closed, hashed,
  password-protected outer ZIPs without command-output transport;
- archive passwords are independently CSPRNG-generated, saved/read back under
  artifact-bound Keychain references before delivery/sealing, absent from all
  forbidden surfaces, and usable after restart to reopen retained local
  outers;
- the pinned helper/library set is provisioned and endpoint-digest-verified
  before exact-path loading, with no global/dynamic/unpinned fallback;
- both encrypted outer entries authenticate before inner publication, and
  inner/raw manifests, sizes, hashes, and resource bounds validate before raw
  publication;
- only the exact matching generated remote outer ZIP is queued after the
  durable receipt/decryption gate and removed by handle-bound validation after
  the staging lock releases; original/live and staged raw bytes are proven
  unchanged and uncertain cleanup remains truthful/recoverable;
- raw/inner/outer packages, manifests, hashes, password references, and ledger
  links preserve complete local provenance without claiming a second ZIP is
  always smaller;
- each verified file can process before directory completion;
- supported atomic events validate and preserve complete provenance;
- crashes, retries, duplicates, conflicts, and API outages do not recollect,
  lose, duplicate, or silently change evidence;
- every API PUT reconciles through the dependency-ordered exact-byte outbox;
- deferred/empty/warning/failed/aborted states remain truthful;
- one and two endpoint cross-part journeys pass;
- every public command has CLI service-journey coverage;
- migrations build cleanly from committed files and rollback preserves spool;
- repository and changed-scope coverage thresholds pass locally;
- threat model, secret scan, dependency/parser scan, and local gates pass;
- the completion report reconciles every HH-R requirement;
- no GitHub test workflow was added or used.

## 21. Implementation-Agent Start Instructions

1. Read this plan, the coordination index, Part 2, all applicable AGENTS.md
    files, and the current confirmed HostHunter contracts.
2. Do not implement until section 18 is confirmed.
3. Create an acceptance ledger, test ledger, and public-command action
    inventory before editing.
4. Amend the HostHunter product contract before feature code.
5. Freeze cross-part JSON Schema/OpenAPI/golden vectors and the internal
    artifact/encryption/secret/cleanup contracts before parallel edits.
6. Run $feature-design-preflight and the formal $security-threat-model; a
    critical/high secret-channel, archive-parser, encryption, or deletion
    finding blocks implementation.
7. Develop focused tests with each implementation slice.
8. Use only local container gates for canonical validation; native macOS parser
    qualification is supplemental and mandatory for release claims.
9. Use $test-readiness-preflight before the expensive full gate.
10. Never bypass hooks, reduce coverage, expose secrets, mutate evidence, or
    use GitHub to discover failures.
