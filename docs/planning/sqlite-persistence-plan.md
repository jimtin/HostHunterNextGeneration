# SQLite Persistence Shared Understanding Contract

## Status

**AMENDED CONTRACT CONFIRMED BY USER 2026-08-24; IMPLEMENTATION IN PROGRESS**

Feature-design preflight verdict: **READY**. The user confirmed the amended
contract by directing implementation on 2026-08-24.

The user explicitly approved the four product decisions and then confirmed the
reviewed amendment on 2026-08-24. This file is the source of truth for the
persistence migration. The repository-wide shared
contract, implementation ledger, testing inventories, and threat model are
reconciled to it. The readiness review preserved the four user-confirmed
product decisions below, but it added a material technical amendment: the
unreleased `.hhout` format becomes identity-bound, chunked, streaming v2, with
the stricter operation-state and recovery barriers described here. That
storage/recovery refinement requires explicit confirmation before code changes.

## Summary

### Goal

Replace the active `targets.json` and `ledger.jsonl` persistence paths with one
authoritative local SQLite database while preserving HostHunter's existing
target, transport, accountability, output, bootstrap, and recovery contracts.

Keep complete PowerShell stream output in encrypted, compressed `.hhout`
artifacts. Add supported audit-history and output-retrieval cmdlets so the
persisted information is useful for investigation and troubleshooting.

### Primary user and role

- One local HostHunter operator controls the module, its data root, SSH
  credentials, audit key, and GitHub repository.
- There is no multi-user database, tenant boundary, service account, or remote
  database administrator in the first release.

### In-scope repository

- `/Users/jameshinton/Developer/HostHunterNextGeneration`

### Non-goals

- WinRM implementation or qualification.
- A remote, shared, cloud-hosted, or network-filesystem database.
- A graphical audit browser.
- Capturing commands executed outside HostHunter.
- Automatic deletion, pruning, or retention expiry.
- A centrally operated audit collector.
- SQLCipher, SQLite SEE, or a claim that the entire database file is encrypted.
- Automatic import of legacy JSON or JSONL data.
- Runtime dependency downloads or self-updating native binaries.

## User-Confirmed Decisions

The user confirmed on 2026-08-24 that:

1. No real HostHunterNextGeneration data needs migration. The repository has
    not been pushed or released.
2. Target profile fields may remain plaintext inside the private database.
3. `Get-HHAuditRecord` and `Get-HHAuditOutput` are part of this migration.
4. Audit records and `.hhout` artifacts may be retained indefinitely for the
    first release.

## Technical Readiness Resolutions

The post-approval review closed these implementation ambiguities:

| Review concern | Frozen resolution |
| --- | --- |
| A second process could recover live work | Separate operation lock; only its owner may recover, and it holds the lock through final seal |
| The current Keychain worker cannot update a structured head | Bounded anchor envelope plus atomic native expected-value update and exact readback; never delete/recreate |
| Encrypted rows or output could be moved between identities | Row/column/database-bound AEAD and invocation-bound streaming `.hhout` v2 |
| A declared conditional command was indistinguishable from a sent command | Per-operation declared, armed, completed, skipped, and uncertain evidence with an anchor barrier before dispatch |
| Existing DB migration could mutate unauthenticated state | Initial release creates only fresh `0001`; any existing unmatched schema fails before mutation |
| Provider assets might not reach canonical tests | Locked build project, exact RID package layout, lazy initialization, and package-import integration/E2E |
| Eight retained 100 MiB outputs could exhaust memory/disk | Real pre-dispatch capacity reservation, protected recovery margin, chunked streaming, and backpressure |
| Backup/restore semantics were underspecified | No public or active restore in v1; future authenticated maintenance snapshots need separate approval |
| Live Windows proof preceded a candidate SHA | Commit, clean-checkout package/hash, exact-SHA gate, then native macOS/Windows proof of the same package |
| Parallel ownership overlapped schema, loader, anchor, and E2E | Main freezes shared foundation first; later workers have disjoint provider, target, and audit files; main owns integration |

The `.hhout` v2 and operation-state/recovery rows materially refine storage and
recovery behavior. The user confirmed those amendments on 2026-08-24 by
directing implementation of this plan.

## Current State

- Targets are stored in `targets.json` using the existing schema-v2 target
  envelope.
- Audit intentions and terminal records are appended to `audit/ledger.jsonl`.
- The current authenticated ledger head is stored in
  `audit/ledger.head.json`.
- Complete output is already stored separately in encrypted, compressed
  `audit/output/<invocation-id>.hhout` artifacts.
- The macOS audit master key is stored in a data-root-scoped Keychain item.
- `known_hosts` and generated or selected SSH keys are filesystem artifacts and
  are not database candidates.
- There is no current database provider, database schema, migration runner, or
  public product reader for `.hhout` output.
- The normal default data root is absent on the current controller. A legacy
  store discovered later must fail closed rather than being silently imported.

## Target State

### Runtime data root

```text
<data-root>/
├── hosthunter.db
├── hosthunter.db-wal
├── hosthunter.db-shm
├── hosthunter.db.writer.lock
├── hosthunter.operation.lock
├── audit/
│   ├── audit.key            # owner-private Linux/Windows fallback only
│   ├── anchor.bin          # owner-private Linux/Windows fallback only
│   └── output/
│       └── <invocation-id>.hhout
├── recovery/
├── known_hosts
└── keys/
```

- Normal production state remains in the operating system's application-data
  location.
- The only supported repository-local production root is `.hosthunter/`.
- `.hosthunter/` and `.artifacts/` are ignored as complete directory trees.
- `.artifacts/` remains exclusively for test, security, build, and release
  receipts; it is not product storage.
- Crash diagnostics and quarantined remnants belong under `recovery/`.
- SQLite WAL/SHM files, both lock files, and same-filesystem atomic staging files remain beside
  their owning files when required for correctness, but remain inside the same
  ignored data root.
- A repository gate must reject any tracked path below `.hosthunter/` or
  `.artifacts/`, including a path added with `git add -f`.

### Source of truth

- `hosthunter.db` is the sole authoritative structured store after cutover.
- `.hhout` files are the sole authoritative store for complete ordered stream
  events.
- The macOS Keychain holds the audit master key and an independent authenticated
  database-head anchor. Linux and Windows use owner-private authenticated key
  and anchor files inside the data root; that fallback detects database-only
  divergence but cannot detect rollback of the entire data root.
- `known_hosts`, local SSH keys, and remote `authorized_keys` entries remain in
  their existing security boundaries.
- JSON and JSONL are never dual-written with SQLite.

## Provider and Packaging Decision

Use these exact build-time dependencies, checked on 2026-08-24:

- [`Microsoft.Data.Sqlite.Core` `10.0.11`](https://www.nuget.org/packages/Microsoft.Data.Sqlite.Core/10.0.11).
- [`SQLitePCLRaw.bundle_e_sqlite3` `3.0.5`](https://www.nuget.org/packages/SQLitePCLRaw.bundle_e_sqlite3/3.0.5).
- [`SQLite` `3.53.4`](https://www.nuget.org/packages/SQLite/3.53.4), the native
  engine package published by SourceGear.
- [`.NET SDK` `10.0.400`](https://dotnet.microsoft.com/en-us/download/dotnet/10.0),
  used only in the locked build stage.

The dependency source of truth is a build-only .NET 10 SDK project under
`eng/sqlite/`, its committed `packages.lock.json`, package hashes, and licence
inventory. `scripts/dependencies/restore-sqlite.sh` will run
`dotnet restore --locked-mode` and copy only the allowlisted managed and native
assets into the release package. It does not introduce a production helper
assembly or a second language coverage surface. The source module performs no
dependency download at import or execution time.

Database orchestration remains PowerShell in v1 and calls the managed provider
directly. A custom C# persistence helper is not introduced unless a focused
provider spike proves a required operation cannot be implemented reliably from
PowerShell; that would be a contract change with its own .NET coverage gate.

Provider loading must:

1. Resolve the controller OS, process architecture, and Linux libc against the
    release allowlist.
2. Load one runtime-specific dependency directory before any SQLite provider
    type is referenced.
3. Keep the native SQLite library adjacent to the managed provider assemblies.
4. Reject an unsupported runtime or an already-loaded incompatible provider.
5. Call `SQLitePCL.Batteries_V2.Init()` exactly once after asset selection and
    before the first connection.
6. Assert the managed provider versions and `SELECT sqlite_version()` before
    accepting the database as usable.

Provider initialization is lazy. Module import, command discovery, help, and a
true `-WhatIf` path neither load SQLite nor create the data root. The first real
persistence operation initializes the packaged provider or fails
`PersistenceRuntimeUnsupported` without fallback.

The first public release supports only this controller matrix:

| Controller RID | PowerShell proof | Qualification |
| --- | --- | --- |
| `osx-arm64` | 7.4 minimum and current pinned 7.6.5 | Native current Mac |
| `linux-arm64` | 7.4 minimum and pinned 7.6.5 | Canonical container |
| `linux-x64` | 7.4 minimum and pinned 7.6.5 | Executable x64 container |
| `win-x64` | 7.4 minimum and pinned 7.6.5 | Available Windows laptop as controller |

`osx-x64`, `win-arm64`, and musl Linux are deferred and rejected until each has
the same executable package smoke. The Windows controller qualification is
distinct from using that laptop as an SSH target and must prove provider load,
schema CRUD, owner-only ACLs, and reparse-path rejection.

Production resolves assets only below the packaged module's `lib/<rid>/`
directory. Source-level unit tests use an injected provider root. Integration,
CLI E2E, security, and build lanes import the generated package through
`HH_TEST_MODULE_PATH`; importing `src/` directly is not acceptable evidence for
SQLite behavior.

The release artifact includes licence notices, dependency hashes, a locked
dependency graph, and an SBOM. Dependency, filesystem, image, and exact-package
scans cover the provider and native library. The dependency scan must fail if
the lockfile or any expected SQLite package was not discovered.

Load-bearing provider behavior was checked against Microsoft's current guidance
for [custom SQLite versions](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/custom-versions),
[transactions](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/transactions),
[bounded busy/locked handling](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/database-errors),
and [online backup](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/backup),
plus SQLite's [WAL documentation](https://www.sqlite.org/wal.html) and
[integrity pragmas](https://www.sqlite.org/pragma.html). These versions and
capabilities must be rechecked if implementation does not begin against the
pinned graph above.

### Rejected provider approaches

- `PSSQLite`: stale native SQLite and limited platform/test coverage.
- `sqlite3` subprocesses: weaker parameterization and error handling, plus an
  external binary installation requirement.
- `System.Data.SQLite`: more complex native provisioning without a material
  capability advantage for this module.
- Full output stored as SQLite rows: unnecessary database/WAL growth and poorer
  streaming and recovery characteristics than the existing bounded `.hhout`
  format.
- A sealed head stored only inside or beside the database: it cannot detect
  rollback of the complete data-root snapshot.

## Database Contract

### Connection and durability policy

- The database must be on a local filesystem.
- Enable `PRAGMA foreign_keys=ON`.
- Use WAL mode and `synchronous=FULL`.
- Use one connection per operation with pooling disabled.
- Use finite command and busy-lock timeouts; no unlimited wait is allowed.
- Use short explicit write transactions, normally `BEGIN IMMEDIATE`.
- Use one bounded cross-process writer mutex spanning a database commit and its
  monotonic anchor update. Acquire it through a no-follow regular-file handle,
  verify the opened identity/path/owner permissions, re-read the anchor under
  the lock, and reject audit-sequence or target-generation regression.
- Use a separate cross-process operation lock for remote-capable work. Acquire
  it before recovery and hold it through the batch's final artifact, terminal,
  and anchor writes. Only the owning process may recover unterminated work.
  One process may still fan out to eight targets; a second remote-capable
  process fails `OperationBusy` after a bounded wait rather than modifying the
  first process's live invocations.
- Read-only queries take a stable SQLite snapshot and briefly coordinate with
  the writer mutex while comparing that snapshot's head with the anchor. They
  never recover work or advance the anchor. A bounded retry handles a writer
  that committed immediately before the snapshot.
- Never hold a database transaction open across SSH, PowerShell remoting,
  `.hhout` encryption, or general file I/O. The narrowly scoped writer mutex,
  not the SQLite transaction, spans the required anchor update.
- Disable SQLite extension loading and reject an unexpected schema, migration
  checksum, trigger, or integrity state before remote-capable work.
- Before arming dispatch, reserve 128 MiB of real artifact capacity per selected
  target (covering the 100 MiB canonical-event limit plus v2 framing,
  compression, and encryption overhead) and a separate 64 MiB protected
  database/recovery margin. The platform adapter must prove allocation rather
  than rely on a sparse logical length. Failure refuses dispatch with
  `PersistenceCapacityInsufficient`; reservations release only after artifact,
  terminal, and anchor finalization.
- Output capture uses bounded streaming and backpressure; it may not retain
  eight independent 100 MiB buffers in memory. Storage filled by another actor
  after dispatch remains an honest `Unknown` with only already-durable evidence
  and no retry.

There is no public backup or restore command in v1. Raw database copying is
unsupported. A future schema upgrade or operator recovery feature must first
define an authenticated maintenance snapshot containing an online SQLite
backup, every referenced `.hhout`, the exact anchor, and a verified manifest.
Restoring an older snapshot over a newer anchor is never allowed; isolated
read-only forensic opening is deferred.

### Initial schema

The first migration is named `0001_initial_sqlite`; it is not a legacy JSON
schema-v1 importer. The committed SQL migration is the final column-level
source of truth, but it must implement these frozen identities, cardinalities,
and bindings:

| Table | Required identity and invariant |
| --- | --- |
| `schema_migrations` | Integer version primary key, unique name, 32-byte SQL checksum, applied UTC; append only |
| `database_identity` | Singleton row with immutable 16-byte database and ledger IDs, format version, and created UTC |
| `target_store_state` | Singleton non-negative generation, snapshot hash, target-state MAC, and last mutation ID |
| `target_profiles` | One active row per ordinal-ignore-case name and normalized endpoint/runtime; exact 14 target fields plus internal revision |
| `operation_batches` | One immutable batch ID, operation, creation UTC, and one-to-eight invocation relationship |
| `invocations` | Unique monotonic audit sequence and immutable invocation ID, batch ID, encrypted target snapshot/request, and intent UTC |
| `remote_operations` | Unique invocation/ordinal, exact phase/runtime, encrypted script/arguments, and conditional flag |
| `remote_operation_events` | Append-only unique operation/event kind evidence for `DispatchArmed`, `Completed`, `Skipped`, or recovered `DispatchUncertain` |
| `invocation_outcomes` | Zero while pending, then exactly one immutable terminal outcome per invocation |
| `output_artifacts` | At most one complete artifact ID/path/hash/size/format/event count per invocation |
| `target_mutations` | Append-only generation/revision CAS request, encrypted before/after evidence, result, and mutation MAC |
| `audit_events` | Unique monotonic sequence, event identity/kind, projection hash, previous MAC, and event MAC |

All identifiers use a single canonical 16-byte representation internally and
the existing 32-lowercase-hex representation at the CLI boundary. UTC values
use one invariant round-trip format. Enum columns have explicit `CHECK`
constraints. Counts, lengths, generations, revisions, ordinals, and sequences
are non-negative. Foreign keys, uniqueness, expected indexes, and the
allowlisted append-only protection triggers are checksummed schema objects;
missing, extra, or altered objects fail integrity verification.

Each audit event MAC covers its plaintext searchable projection and the exact
stored ciphertext-envelope hashes for its batch, invocation, manifest,
operation event, outcome, artifact, and target-mutation relationships. Queries
verify these projection bindings before returning data. No independently
editable plaintext projection is trusted merely because the final audit head
still matches.

The schema deliberately does not create a row per captured PowerShell stream
event. Complete events remain in the encrypted artifact.

### Existing target invariants

The database adapter must preserve, not reinterpret:

- The exact 14-field target model.
- A maximum of eight saved profiles.
- Ordinal-ignore-case unique target names.
- Unique normalized transport, host, port, subsystem, and runtime identities.
- PowerShell 7 and Windows PowerShell 5.1 profiles for the same endpoint.
- Replace-by-default and explicit `-Add` behavior.
- Sorted reads and all-or-nothing requested-name removal.
- Exact-profile compare-and-swap checks and the existing stable
  `TargetStoreCompareAndSwapFailed` and `TargetStoreCommitStateUnknown`
  outcomes.
- No persisted passwords, passphrases, tokens, or private-key material.

The global generation, internal revision, target-state MAC, and mutation MAC
are new persistence security controls. They do not alter the public target
object or replace the existing exact-profile CAS contract.

The authoritative equality checks run through the existing .NET model rules
inside the write transaction. SQLite's ASCII-oriented `NOCASE` collation must
not replace .NET ordinal-ignore-case behavior. Removing a target hard-deletes
the active plaintext profile; the authenticated mutation receipt keeps only the
encrypted before/after evidence required for accountability. SQLite, WAL, APFS,
NTFS, and SSD media are not claimed to provide physical secure erasure.

## Data Protection and Audit Integrity

### Plaintext structured data

Target profiles remain plaintext within an owner-private database, matching
their current exposure in the mode-private `targets.json` file. Plaintext here
is a confidentiality decision, not permission to bypass integrity checks.
`Get-HHTarget` preserves its existing keyless, read-only inspection behavior:
an absent root returns zero objects without creating state, while an existing,
path-safe database may return the unchanged public target objects with a
non-terminating warning if the master key or anchor is unavailable. Such rows
are explicitly unverified display data and are never accepted as authoritative
mutation or dispatch input. Every mutation and remote-capable resolution
reopens and authenticates the database, target-state MAC, and platform anchor;
missing key or anchor then fails closed with `AuditKeyUnavailable`. A true
`-WhatIf` path remains available without initializing persistence.

Operational identifiers, timestamps, enum states, counts, target aliases, and
artifact sizes may also remain plaintext for bounded indexing and recovery.

The data-root directory and files require owner-only permissions: `0700` and
`0600` on POSIX systems, and an owner-only ACL on Windows. Symlinks and unsafe
existing permissions fail closed.

Before remote activity, the data root, database, WAL/SHM, writer lock, operation
lock, recovery root, and artifact root must resolve to contained, regular local
paths. A
filesystem root, symlink/reparse point, path escape, or unsupported network
filesystem fails closed.

### Encrypted structured data

The existing audit master key derives separately labelled encryption,
integrity, lookup, and anchor keys. AES-GCM protects:

- Complete user command text.
- `Reason` and `CaseId` values.
- Immutable audit target snapshots.
- Exact remote script text and serialized arguments.
- Detailed remote identity and failure information.
- Authenticated audit payloads.

Encryption occurs before SQL parameter binding so plaintext does not enter the
database or WAL and is never placed in SQL text, diagnostics, or debug logs.
Passwords, passphrases, and private keys remain excluded from both encrypted and
plaintext fields.

Every encrypted database value uses a versioned envelope with a fresh CSPRNG
96-bit nonce, 128-bit AES-GCM tag, and exact ciphertext bytes. Associated data
binds the envelope version, database ID, table/domain, immutable row ID,
column/purpose, and schema version. The audit HMAC chain covers the canonical
stored envelope bytes and searchable projection, not a decrypted or
reconstructed approximation. Domain-separated derivation labels and fixed test
vectors are committed with the implementation. Case lookup is HMAC-SHA256 over
the exact UTF-8 `CaseId` with a lookup-only key; the plaintext value is never an
index column.

The target-state MAC covers its domain label, database/schema identity,
generation, prior mutation MAC, and the complete canonically sorted saved set
of exact 14-field target values plus internal revisions, including inactive
profiles because an explicitly named inactive profile remains dispatchable.
Cryptographic buffers are cleared on a best-effort basis after use.

### Output artifact v2

Because no released data exists, the SQLite cutover writes only `.hhout` v2.
The v1 writer is removed with the superseded persistence layer; a v1 reader is
not required.

The v2 authenticated header binds `databaseId`, `ledgerId`, `invocationId`, a
reserved `artifactId`, format version, cipher/compression identifiers, and
chunk size. Output is written as bounded independently compressed AES-GCM
chunks. Every chunk has a fresh 96-bit nonce and associated data containing the
header hash, chunk sequence, previous chunk tag, and declared lengths. An
authenticated final footer commits chunk count, stream-event count, plaintext
and ciphertext totals, and a digest of the canonical event stream. Missing
footer, reorder, truncation, cross-invocation substitution, or an unexpected
extra chunk makes the artifact incomplete or invalid.

Each canonical event frame contains `Sequence`, `RemoteSequence`,
`ObservedAtUtc`, `Phase`, `Stream`, `TypeName`, `SerializedByteCount`,
`IsTerminating`, and a bounded PowerShell-serialized value. The production
capture path streams frames to the prepared writer with backpressure; it does
not first accumulate the complete multi-target batch in memory.

Artifact publication uses a `CreateNew`, no-follow, owner-private temporary
file inside the output directory, durable file flush, no-replace rename, and
the platform's durable parent-directory synchronization equivalent before
terminal metadata is committed. Path containment, opened-file identity,
permissions, length, hash, footer, and AEAD are revalidated before retrieval or
recovery attachment.

### Authenticated chain and external anchor

`audit_events` retains the canonical HMAC chain and rejects updates or deletes.
Command history contains only HostHunter-originated remote operations and their
recovery/terminal evidence. Purely local target mutations do not become remote
command records; instead, each target generation has its own keyed state MAC
and durable mutation receipt.

A second data-root-scoped macOS Keychain item stores a bounded, versioned
canonical binary authenticated head:

```text
magic + envelopeVersion + databaseId + schemaVersion + ledgerId +
auditSequence + auditLastMac + targetGeneration + targetStateMac + anchorMac
```

The envelope is fixed-field, network-byte-order, and at most 256 bytes. Its
service is `com.hosthunter.nextgeneration.database-anchor.v1`; its account is
the same canonical-data-root hash scheme as the master-key item. `anchorMac` is
HMAC-SHA256 with the anchor-only derived key over every preceding byte.

The Keychain anchor is outside the database backup/restore boundary:

- Database behind anchor: fail closed as rollback or truncation.
- Equal sequence with different MAC, database ID, or ledger ID: fail closed.
- Equal target generation with a different target-state MAC, or a regressing
  target generation: fail closed before target resolution or dispatch.
- Database ahead after a crash: verify the complete authenticated extension,
  then advance the anchor.
- Missing or corrupt anchor where database history exists: fail closed.

The macOS native worker gains an atomic compare-and-update operation using
`SecKeychainItemModifyAttributesAndData`, followed by fixed-time exact readback
verification. It never updates by delete/recreate. Under the writer mutex the
caller reads the expected current bytes, verifies monotonicity and the anchor
MAC, performs the compare-and-update, reads back, and only then reports a
committed seal. Initial creation is permitted only for a provably empty new
database at audit sequence and target generation zero. If any database,
artifact, legacy evidence, or anchor exists while the master key is missing,
HostHunter fails without generating a replacement key.

Linux and Windows store the same authenticated anchor envelope in
`audit/anchor.bin`, atomically replaced under the writer mutex beside the
owner-private fallback `audit.key`. This detects database-only edits,
truncation, and target redirection. No equivalent whole-data-root rollback
guarantee is claimed because an attacker can restore the key, anchor, database,
and artifacts together. That residual limitation is explicit in help, release
notes, and the threat model.

## System Flows

### Lazy initialization and schema handling

1. Evaluate command validation and `ShouldProcess` first. A declined `-WhatIf`
    path does not create a root, load SQLite, access Keychain, or take a lock.
2. Resolve the proposed root and validate its existing ancestors without
    creating product state.
3. Detect every legacy persistence signal before database or Keychain creation:
    target/ledger/head files, legacy lock names, temp companions, old
    output/recovery remnants, and legacy `audit.key`. Preserve it and fail
    `LegacyPersistenceMigrationRequired`.
4. For an authorized real action against an absent root, atomically create only
    the exact owner-private data-root directory. A remote-capable action then
    opens the operation lock inside that root before provider or database
    initialization. Revalidate the opened root and rerun legacy detection under
    the lock so concurrent creation cannot bypass either check. A local-only
    mutation uses the writer mutex without claiming remote-operation ownership.
5. Lazily load and verify the packaged provider.
6. For a fresh root, acquire the writer mutex; create remaining owner-private
    directories, obtain the master key, run only `0001_initial_sqlite` in one database
    transaction, create immutable database identity and zero heads, and create
    and read-verify the initial anchor. A crash-left sequence-zero database may
    complete anchor initialization only when schema, identity, empty history,
    empty target set, zero generation, key, and every path verify exactly.
    A crash-left fresh root containing only the current secure lock/init
    remnants is similarly resumable after the same zero-state checks; those
    current lock files are not mistaken for legacy persistence.
7. For an existing database, load the master key and anchor before mutation;
    inspect identity, schema version, migration checksums, allowlisted schema
    objects, `quick_check`, foreign keys, audit chain, target-state MAC, and
    anchor equality. Release 0.1.0 performs no in-place upgrade of an existing
    SQLite schema. Unknown, older, newer, or checksum-mismatched databases fail
    `PersistenceSchemaUnsupported` without mutation.

Future schema upgrades must verify the old schema and anchor before mutation,
quiesce dispatch, create the separately approved authenticated maintenance
snapshot, apply a checksummed transaction under the writer mutex, monotonically
reseal, and run post-migration verification. Migration is never attempted on a
database that has not already authenticated under its old schema.

### Startup before remote-capable work

1. Complete the authorized root-creation ordering above, then acquire the
    bounded operation lock inside the validated root if the fresh-root path did
    not already acquire it. The fresh-root path retains that same handle; it
    never reacquires a second operation lock. The lock proves that no other
    HostHunter process can still be executing or finalizing a remote batch in
    this data root. Revalidate the root and legacy signals under that lock.
2. Run the remaining lazy provider/database initialization or existing-state
    verification above while retaining the operation lock.
3. Perform complete HMAC-chain verification and validate the current target
    snapshot before dispatch. This check has a 60-second hard timeout and fails
    `AuditIntegrityVerificationTimedOut`; the release fixture must verify at
    least 100,000 audit events within 10 seconds on each claimed RID at the
    minimum PowerShell version. History is still retained beyond that fixture,
    but remote work
    fails closed if verification exceeds the bound until a separately approved
    authenticated checkpoint design is introduced. Historical artifacts are
    existence/size checked here and are hash/AEAD checked on retrieval, recovery
    use, and the full integrity lane.
4. Recover only this now-quiescent root's unterminated invocations without
    remote activity.
5. Commit and anchor all recovery outcomes before accepting a new batch.
6. Hold the operation lock through the new batch's terminal and anchor writes.

Read-only queries do not acquire the operation lock, recover work, write audit
events, or advance an anchor. They return authenticated `Pending` records when
an active invocation has no terminal outcome.

### Remote-operation accountability state machine

- Intent creation stores the immutable ordered manifest and reserves each
  operation and artifact identity as `Declared`.
- Immediately before an actual network phase, commit and externally anchor a
  unique `DispatchArmed` event after byte-for-byte comparison with the declared
  script, arguments, runtime, target, and phase. A network adapter may receive
  only that armed value.
- Conditional install, proof, reconcile, cleanup, and rollback phases are not
  armed until their condition is true. A declared conditional phase not used by
  a terminal path receives `Skipped` evidence.
- On adapter return, commit `Completed` evidence with its exact dispatch and
  outcome state. There is no second arm, command substitution, fallback, or
  automatic retry.
- An armed operation without completion after process loss is recovered as
  `DispatchUncertain`; a merely declared operation is provably
  `NotDispatched`.
- A same-barrier fan-out may arm all operations that will be released together
  in one transaction and anchor update, but none is dispatched before that
  barrier completes.

### Target onboarding and testing

1. Commit the complete per-target intent and exact identity-probe operations.
2. Advance the authenticated anchor.
3. Prepare the identity-bound artifact and capacity reservation.
4. Arm each actual host-trust/runtime phase and advance the anchor.
5. Perform host-trust and runtime validation while streaming evidence.
6. Durably publish output artifacts.
7. Commit terminal outcomes and validation evidence, then advance the anchor.
8. For `Set-HHTarget`, apply the complete proposed target set in one generation
    CAS transaction only after all proposed targets validate.
9. `Test-HHTarget` records validation history but does not update the saved
    profile's accepted fields.

### Command invocation

1. Resolve one to eight targets.
2. In one transaction, create the batch, every invocation, complete command
    text, exact manifests, reserved artifact identities, and intent audit
    events.
3. Advance the external anchor.
4. Establish actual artifact capacity reservations.
5. Arm and anchor the operations released by the next fan-out barrier.
6. Only then open sessions and dispatch commands while streaming evidence.
7. Preserve independent per-target outcomes and the existing maximum
    concurrency of eight.
8. Perform no automatic remote retry or runtime fallback.
9. Encrypt, flush, and durably publish each `.hhout` artifact.
10. Commit artifact metadata, terminal outcome, observed identity, and terminal
    audit event, then advance the anchor.

### SSH key bootstrap

- Commit the exact install, proof, reconcile, and rollback manifests before
  network activity, then arm and anchor only each phase that will actually run.
- Preserve the existing password-session, install, separate key-only proof,
  profile CAS, and exact rollback rules.
- Database transactions cannot include the remote mutation. Install, rollback,
  cleanup, or commit ambiguity therefore remains an explicit `Unknown` outcome
  with reconciliation required.
- Never retry uncertain remote work automatically.

### Audit retrieval

Add two exported cmdlets:

- `Get-HHAuditRecord`: newest-first, bounded metadata lookup with these exact
  optional parameters:
  - `-InvocationId <string>` and `-BatchId <string>` accept exactly 32
    hexadecimal GUID characters.
  - `-TargetName <string[]>` uses ordinal-ignore-case matching.
  - `-CaseId <string>` uses exact ordinal matching through a keyed lookup.
  - `-FromUtc <DateTimeOffset>` is inclusive and `-ToUtc <DateTimeOffset>` is
    exclusive; `FromUtc` must be earlier than `ToUtc` when both are present.
  - `-Operation <string[]>` accepts `ValidateTarget`, `TestTarget`,
    `InvokeCommand`, or `EnableSshKeyAuthentication`.
  - `-Status <string[]>` accepts `Succeeded`, `Failed`, `Cancelled`, or
    `Unknown`, plus `Pending` for an authenticated intent without a terminal
    outcome.
  - `-BeforeSequence <long>` is an exclusive cursor for stable older-page
    retrieval and must be greater than zero when supplied.
  - `-First <int>` defaults to 100 and accepts 1 through 1000.
- `Get-HHAuditOutput -InvocationId <string>` requires exactly one 32-character
  hexadecimal invocation ID, verifies the database chain, artifact metadata,
  ciphertext hash, and AEAD tag, then returns that invocation's ordered
  `HostHunter.AuditStreamEvent` objects.

Filters combine with logical AND. Values within the same array filter combine
with logical OR. Ordering is the unique audit `Sequence` descending; a caller
passes the last returned sequence to `-BeforeSequence` to retrieve an older
page. An explicitly requested unknown invocation ID throws
`AuditRecordNotFound`; broader history filters may validly return zero records.

`Get-HHAuditRecord` returns `HostHunter.AuditRecord` objects with these stable
properties: `Sequence`, `BatchId`, `InvocationId`, `Operation`, `IntentAtUtc`,
`Status`, `TargetName`, `Transport`, `HostName`, `Port`, `UserName`,
`Authentication`, `RequestedPowerShellRuntime`, `RequestedExecutionMode`,
`CommandText`, `RemoteOperations`, `Reason`, `CaseId`, `FailureKind`,
`DispatchState`, `OutcomeStatus`, `CompletedAtUtc`, `RemoteIdentity`,
`RemotePowerShellVersion`, `RemotePSEdition`, `ExecutionMode`,
`ValidatedAtUtc`, `ObservedHostKeyFingerprint`, `OutputBytes`,
`StreamEventCount`, `HasCompleteOutput`, `ExceptionType`, `RecoveryState`, and
the five existing bootstrap outcome properties when applicable. Each
`RemoteOperations` entry exposes its ordinal, declared manifest, and verified
`Declared`, `DispatchArmed`, `Completed`, `Skipped`, or `DispatchUncertain`
state. A `Pending` record has null terminal-only properties.

`Get-HHAuditOutput` returns ordered `HostHunter.AuditStreamEvent` projections
with `Sequence`, `RemoteSequence`, `ObservedAtUtc`, `Phase`, `Stream`,
`TypeName`, `SerializedByteCount`, `IsTerminating`, `SerializedValue`, and
deserialized `Value`. These are validated evidence projections, not live remote
objects; deserialized values have no remote methods or sessions.

Stable persistence/query error identifiers are:

- `AuditRecordNotFound`.
- `AuditOutputUnavailable` for an invocation without a complete retrievable
  artifact.
- `AuditIntegrityFailed` for chain, anchor, database, path, hash, or AEAD
  verification failure.
- `AuditKeyUnavailable`.
- `AuditIntegrityVerificationTimedOut`.
- `PersistenceBusy`.
- `OperationBusy`.
- `PersistenceStorageFull`.
- `PersistenceCapacityInsufficient`.
- `PersistencePathUnsafe`.
- `PersistenceRuntimeUnsupported`.
- `PersistenceSchemaUnsupported`.
- `AuditQueryInvalidArgument` for malformed identifiers, ranges, cursors,
  limits, or enum filters.
- `LegacyPersistenceMigrationRequired`.

The record object includes the complete decrypted command text. Normal table
formatting may abbreviate its display, but the object value remains complete.
Bulk output expansion across multiple invocations is intentionally unsupported
because one invocation may contain 100 MiB of plaintext.

Both cmdlets are read-only and fail closed if the platform master key, audit chain,
anchor, or requested artifact cannot be verified.

Audit-chain verification for queries uses the same 60-second hard timeout and
`AuditIntegrityVerificationTimedOut` error as remote-capable startup. A query
never returns a partial unverified page when that bound is exceeded.

Neither query cmdlet creates a new remote-command audit event.

## Failure and Recovery Contract

| Failure or crash point | Required result |
| --- | --- |
| Before intent commit | No durable invocation and no network activity |
| After intent commit but before anchor update, with no armed operation | No dispatch; authenticate and advance the DB-ahead chain, then record `Failed`/`NotDispatched` |
| After anchor update but before any operation is armed | Record `Failed`/`NotDispatched`; never call the endpoint |
| After `DispatchArmed` but before durable completion | Preserve available evidence and recover the operation as `DispatchUncertain` and invocation as `Unknown`; never retry |
| Declared conditional operation never armed | Record `Skipped`/`NotDispatched`; do not turn it into uncertainty |
| During `.hhout` staging | Quarantine the incomplete remnant under the data root; claim no complete output |
| After artifact rename but before terminal commit | Verify the v2 invocation binding and retain it as partial evidence attached to an `Unknown` recovery outcome |
| After terminal DB commit but before anchor update | Verify the committed chain extension and advance the anchor without changing the terminal result |
| Anchor ahead of database | Fail closed as database rollback or truncation |
| Database references a missing or invalid artifact | Fail integrity validation; do not return incomplete output as complete |
| Operation lock exceeds timeout | Return `OperationBusy`; do not recover or dispatch |
| Writer/database lock exceeds timeout | Return `PersistenceBusy`; perform no additional remote attempt |
| Database or artifact storage is full | Fail closed, retain any authenticated partial evidence, and never retry a possibly dispatched command |
| Capacity reservation fails before arming | Return `PersistenceCapacityInsufficient`; no dispatch |
| Initial DB exists without anchor | Complete initialization only for exact sequence-zero empty state; otherwise fail closed |
| Master key missing beside any state | Return `AuditKeyUnavailable`; never generate a replacement key |
| Unknown or checksum-mismatched schema | Return `PersistenceSchemaUnsupported` before network activity |
| Unsupported provider runtime | Return `PersistenceRuntimeUnsupported` with no runtime download or fallback |

Recovery records are auditable and bounded. Recovery runs only while holding
the operation lock and never infers remote success from an artifact, stream
event, or lost controller state. It may preserve a previously committed
terminal result, but it never upgrades partial evidence to success.

## Schema Rollout, Cutover, and Rollback

This is a pre-release expand/deploy/contract migration. There is no deployed
mixed-version fleet and no real data requiring import.

### Expand

- Add the pinned provider packaging, initial-schema runner, database crypto,
  external anchor, operation/writer locks, `.hhout` v2 writer, database
  adapters, and replacement-path tests.
- Keep current JSON/JSONL code only long enough to protect and compare existing
  behavior. It remains inactive during SQLite proof and is never dual-written.
- Add a legacy-state detector that throws `LegacyPersistenceMigrationRequired`
  before mutation if it discovers target/ledger/head JSON, any related lock or
  temp file, legacy output/recovery evidence, or a legacy plaintext key.
  An unmatched SQLite database instead throws `PersistenceSchemaUnsupported`.

### Deploy within the unreleased working tree

- Switch every public cmdlet and recovery path to the SQLite adapters.
- Prove fresh-process target, command, bootstrap, recovery, tamper, and audit
  retrieval journeys through the database.
- Prove that no active flow creates `targets.json`, `ledger.jsonl`, or
  `ledger.head.json`.

### Contract before initial publication

- Remove superseded JSON/JSONL writers, locks, temporary-file handling, and
  production readers.
- Retain only the small fail-closed legacy detector; do not retain an importer.
- Remove stale tests, fixtures, docs, and configuration references only after
  replacement behavior is proven.
- Keep `.hhout`, Keychain, `known_hosts`, SSH keys, and transport behavior.

### Rollback

- Before public release, rollback is a source rollback plus removal of the
  exact clean test data root; no user data exists. Test-only teardown also
  removes both path-scoped Keychain items after revalidating the canonical test
  root and item identities. Production state is never automatically reset.
- Once real SQLite data exists, downgrade to a JSON-writing version is
  unsupported because it would fork target and audit history.
- Operational backup/restore is unsupported in v1. Before any future schema
  migration, approve and prove the authenticated maintenance-snapshot contract
  described above. Never overwrite a newer external anchor with an older
  backup.
- Future database migrations are forward-only and additive first; destructive
  contract work belongs in a later release after compatibility and snapshot
  proof.

## Legacy-Prune Classification

| Existing surface | Classification during expand | Final disposition |
| --- | --- | --- |
| `targets.json` writer/reader | Active baseline, then superseded | Remove active path |
| Target file lock and atomic JSON temp writer | Active baseline, then superseded | Remove |
| Target model, validation, merge, sorting, limits, and exact-record CAS semantics | Active | Retain above SQLite adapter |
| `ledger.jsonl` append/parser | Active baseline, then superseded | Remove active path |
| Canonical event model, lifecycle validation, HMAC chain, and recovery semantics | Active | Retain and adapt to SQLite |
| `ledger.head.json` representation | Superseded | Replace with Keychain anchor |
| Legacy-state recognition | Compatibility safety control | Retain fail-closed detector only |
| `.hhout` v1 writer | Active baseline, identity binding insufficient for orphan recovery | Replace with streaming `.hhout` v2; no v1 compatibility required |
| Audit Keychain provider | Active | Extend with separate head item |
| `known_hosts`, local keys, remote key entries | Active | Retain unchanged |

No path classified `unknown` may be removed until reference, test, runtime, and
documentation sweeps prove it is unused.

## Security Preflight

The database migration adds these trust boundaries:

- Module process to managed SQLite provider and bundled native library.
- Decrypted audit values to parameterized database writes.
- SQLite transaction to external `.hhout` publication.
- SQLite audit head to macOS Keychain anchor.
- SQLite audit head to Linux/Windows owner-private fallback anchor.
- Operation lock ownership to crash recovery.
- Unreleased source and dependency inputs to the local build and release
  package.

Release-blocking abuse paths and controls are:

| Abuse path | Required control |
| --- | --- |
| Replace or roll back the database to hide a command | HMAC chain plus platform anchor; macOS Keychain supplies whole-root rollback detection, while Linux/Windows detect database-relative divergence only |
| Redirect commands by editing plaintext target rows | Keyed target-generation MAC over every saved active and inactive profile, included in the external anchor and verified before dispatch |
| Edit/delete/reorder structured rows | Identity-bound AEAD, HMAC projection bindings, foreign keys, target-state MAC, append-only constraints, and startup/query verification |
| Regress the anchor through concurrent writers | Bounded global writer mutex plus atomic expected-value anchor update and exact readback |
| Recover another process's live invocation | Separate OS-released operation lock held through remote terminal/anchor completion |
| Inject SQL through target or command text | Parameterized statements only; no SQL string interpolation |
| Commit a password or captured secret | Credentials excluded from structured records; audit payload and `.hhout` encrypted; ignored-root and gitleaks gates |
| Swap, truncate, or misattach a `.hhout` file | V2 database/ledger/invocation/artifact AAD, chained chunks, final footer, path, hash, length, and AEAD verification |
| Load a malicious or incompatible native SQLite library | Exact package pins, locked restore, hashes, allowlisted runtime path, version assertion, dependency and artifact scans |
| Execute an undeclared or unaudited remote phase | Declare exact manifest, commit and anchor `DispatchArmed`, then pass only the compared value to transport |
| Restore an old backup over newer evidence | No active restore in v1; a future feature must compare a complete authenticated snapshot with the external anchor and reject rollback |
| Deny service with a held database lock | Short transactions and finite lock timeout; never extend the wait into a remote retry |
| Exhaust disk through indefinite retained output | Pre-dispatch real capacity reservation, protected DB/recovery margin, bounded streaming/backpressure, preserved evidence, and no automatic retry/deletion |
| Roll back the full Linux/Windows data root | Explicitly unresolved by the colocated fallback key/anchor; document the residual and never claim macOS-equivalent protection |

The repository threat model must be updated and structurally checked before the
first implementation push. Critical or high findings block push.

## Acceptance Ledger

| Requirement | Implementation evidence | Status before implementation |
| --- | --- | --- |
| SQLite is the only structured source of truth | Fresh database migration integration and fresh-process E2E showing no JSON/JSONL creation | Pending |
| Existing target behavior is unchanged | Focused model/store unit tests, two-process CAS integration, and target CLI journeys | Pending |
| Every HostHunter remote command is intended and armed before dispatch | Byte-for-byte manifest/event tests proving declared, armed, completed/skipped/uncertain state and anchor ordering | Pending |
| Complete command text and optional reason/case are retained | Database crypto round-trip, audit query units, and fresh-process query E2E | Pending |
| Complete ordered streams remain recoverable | Identity-bound streaming `.hhout` v2, capacity/backpressure proof, and `Get-HHAuditOutput` integration/E2E | Pending |
| One-to-eight target fan-out remains independent | Database-backed fan-out integration and direct/mixed runtime journey evidence | Pending |
| PS7 and Windows PS 5.1 attribution remains exact | Existing deterministic bridge proof plus exact-candidate live Windows qualification | Pending |
| SSH-key transition remains conflict-safe and compensating | Database CAS/bootstrap units, fixture integration, and authorized live journey | Pending |
| Database and artifact crashes fail safely | Deterministic fault injection and kill-process recovery matrix | Pending |
| A live process is never falsely recovered | Cross-process operation-lock contention, kill/release, and eight-target fan-out integration | Pending |
| Whole-root rollback is detected on macOS | Native Keychain anchor lifecycle and rollback-negative proof | Pending |
| Audit history and output can be retrieved safely | All parameter sets and error states covered by fresh-process CLI E2E | Pending |
| Runtime and proof artifacts cannot be committed | Ignore-scope tests, tracked-path guard, final tree/history gitleaks | Pending |
| Provider package is reproducible and supported | Locked restore, version assertion, RID smoke tests, license/SBOM, dependency/image/package scans | Pending |

## Verification Plan

### Completed post-approval action

The user-action coverage review for the two new exported query cmdlets and the
changed persistence behavior of all six existing cmdlets is complete in
`docs/testing/e2e-workflow-inventory.md`. For this non-browser module,
fresh-process CLI E2E is the Playwright-equivalent layer.

### Focused unit proof

- Migration ordering, checksums, empty/newer/corrupt schema handling.
- Provider/runtime selection and incompatible assembly rejection.
- Parameterized query construction and encrypted-column handling.
- Target limit, equality, sorting, add/replace/remove, generation, revision,
  and every CAS outcome.
- Audit canonicalization, encryption, HMAC chain, external-anchor comparison,
  atomic anchor update, operation state machine, and immutable outcome rules.
- Audit query filters, cursor/default/maximum limits, exact output object
  shapes, complete command values, pending records, and single-artifact
  retrieval.
- `.hhout` v2 identity/chunk/footer binding, bounded streaming, capacity
  reservation, and durable publication.
- Crash/recovery state classification and stable error identifiers.
- At least 95% changed-scope statements, branches, functions, and lines.

### Integration proof

- Clean database construction from committed migrations alone.
- Multiple fresh processes contending on target/audit writes and the separate
  remote-operation lock.
- WAL recovery and finite busy/operation-lock timeouts.
- Database transaction and `.hhout` publication boundary failures.
- Concurrent database commits and monotonic Keychain-anchor serialization.
- Database commit before anchor, anchor before dispatch, artifact before
  terminal, and terminal before anchor fault points.
- Row edit/delete/reorder, wrong key, stale anchor, database rollback, missing
  artifact, swapped artifact, and incomplete staging negatives.
- Plaintext target redirection, target-generation regression, `SQLITE_FULL`,
  artifact disk-full, path escape, symlink/reparse point, and network-root
  negatives.
- One-to-eight target direct and deterministic mixed-runtime execution.
- No remote retry caused by a database failure.
- Release package import on every claimed RID and PowerShell 7.4/7.6.5
  boundary, with no integration/E2E import from `src/`.

### Fresh-process CLI E2E

- Every existing public cmdlet using SQLite.
- Both new audit cmdlets, cursor pagination, pending state, exact object shapes,
  and all supported filters/error states.
- Complete command text, reason/case, exact manifests, terminal outcome, and
  stream retrieval across process restarts.
- No creation of `targets.json`, `ledger.jsonl`, or `ledger.head.json`.
- Legacy-state detection with no network or data mutation.
- Runtime-root tracked-file guard and `-WhatIf` no-root/no-database behavior.

### Native and live proof

- macOS Keychain master-key and external-head lifecycle on the exact candidate.
- SQLite provider load, schema creation, CRUD, ACL/path, and integrity smoke on
  each controller runtime claimed in release documentation.
- Existing PowerShell 7, Windows PowerShell 5.1, mixed-runtime, and authorized
  key-bootstrap journeys on the Windows laptop using the exact candidate SHA.
- WinRM remains a negative no-dispatch journey only.

### Final local gate

Before the expensive gate, run `test-readiness-preflight` and close every
acceptance-ledger row with focused evidence. Then run:

- Repository-wide unit coverage of at least 90% in all four metrics.
- All critical integration and CLI E2E journeys.
- Static/governance validation.
- Secret, dependency, filesystem, image, and release-package scanning.
- Production module-package build and clean import.
- Repo-root threat-model review.
- Final gitleaks working-tree and exact-commit/history scans.

All canonical proof runs locally in containers. Native macOS Keychain and live
Windows qualification are explicit local exceptions because containers cannot
prove those platform boundaries. GitHub performs no test execution.

### Planned executable verification interfaces

These paths are part of the foundation slice and must exist before adapter
implementation is accepted. A planned name is not evidence until its bounded
runner and machine-readable receipt are implemented and green.

| Purpose | Exact planned command | Receipt root |
| --- | --- | --- |
| Locked provider restore | `./scripts/dependencies/restore-sqlite.sh` | `.artifacts/dependencies/sqlite/` |
| Changed-scope four-metric proof | `./scripts/lanes/persistence-coverage.sh` | `.artifacts/coverage/persistence/` |
| SQLite concurrency/fault proof | `./scripts/lanes/sqlite-integration.sh` | `.artifacts/integration/sqlite/` |
| Package-based CLI journeys | `HH_TEST_MODULE_PATH=<package> ./scripts/lanes/e2e.sh` | `.artifacts/e2e/` |
| Exact release-package scan | `./scripts/security/scan-release-package.sh <package>` | `.artifacts/security/release-package/` |
| macOS anchor qualification | `./scripts/qualification/macos-anchor.sh <sha> <package>` | `.artifacts/qualification/macos/` |
| Windows controller/runtime qualification | `pwsh -File scripts/qualification/Test-HHWindowsController.ps1 -CandidateSha <sha> -PackagePath <package>` | `.artifacts/qualification/windows/` |
| Clean-checkout candidate proof | `./scripts/release/verify-candidate.sh <sha>` | `.artifacts/release/<sha>/` |

The standalone laptop gate for this repository will live outside the source
tree at `/Users/jameshinton/Developer/hosthunter-next-generation-pr-gate` and
invoke the clean-checkout candidate contract. It does not exist yet; creating,
testing, and documenting it is a release requirement, not an assumed capability.

## Implementation Sequence

1. Completed: approve this Shared Understanding Contract.
2. Completed: run user-action coverage review and update the action/test
    matrices.
3. Completed: perform the post-approval schema/API, security/recovery,
    packaging, pruning, and delivery review and reconcile its decisions.
4. Main/common foundation: freeze `0001_initial_sqlite`, connection/transaction
    interfaces, stable errors, identity-bound encryption/output formats,
    writer/operation locks, anchor interface, fault seams, and focused tests.
5. Add the locked provider acquisition project, restore wrapper, RID package
    layout, lazy loader, package builder, package-import test seam, licences,
    hashes, and scans.
6. Add fresh-database creation, identity/schema verification, zero-head anchor
    initialization, atomic Keychain update, Linux/Windows fallback seal, and
    focused cryptographic/recovery proof.
7. Replace target persistence and prove exact model, hard-delete, limit,
    ordinal equality, exact-record CAS, generation/state-MAC, and concurrency
    parity.
8. Replace audit persistence, `.hhout` v2 streaming, operation arming, capacity
    reservation, and no-network-before-anchor ordering.
9. Add `Get-HHAuditRecord` and `Get-HHAuditOutput` with exact type/filter/cursor
    unit and CLI E2E proof.
10. Add deterministic crash, disk/capacity, operation-lock, writer/anchor, and
    multi-process integration proof.
11. Rewire all eight public cmdlets to the package-backed SQLite interfaces,
    run replacement-path journeys, and confirm no JSON/JSONL writes remain.
12. Remove superseded persistence and `.hhout` v1 layers one coherent layer at
    a time, running focused proof and a deleted-surface sweep after each layer.
13. Implement the clean-checkout candidate runner and separate standalone
    laptop gate; run test-readiness preflight, changed-scope proof, the canonical
    full working-tree gate, working-tree threat review, and gitleaks.
14. Create a local candidate commit only after the working tree is green. Build
    the package from a clean checkout of that SHA and record both candidate SHA
    and package SHA-256.
15. Run the standalone exact-SHA container gate, native macOS anchor proof,
    Windows provider/ACL proof, PS7, bridged 5.1, mixed-runtime, and authorized
    key-bootstrap journeys against that same package hash. Any edit creates a
    new SHA and invalidates every prior candidate receipt.
16. Create an empty public GitHub repository, disable Actions, and verify that
    only `jimtin` has administrative/write authority and that no write app,
    team, collaborator, or deploy key exists before the first source push.
17. Push only the proven SHA, apply the available `main` branch rules, and
    re-read remote SHA, visibility, Actions, rules, collaborators, apps, teams,
    deploy keys, and repository contents.

## Parallel Work

Parallel work begins only after the main/common foundation has frozen the
schema, connection/transaction, lock, crypto/output, anchor, error, and test
interfaces. Shared migrations, module integration, and public cmdlets never
have concurrent owners.

| Stage/lane | Exclusive ownership | Expected focused evidence |
| --- | --- | --- |
| Main/common foundation first | `0001`, shared interfaces, writer/operation locks, encryption/output envelopes, anchor contract, error IDs, module integration | Contract tests and clean schema/provider-seam proof |
| Provider/package after freeze | Dependency project/lock/hashes/licences, RID assets, package builder, lazy loader only | Version/RID/unsupported-runtime/package scan receipts |
| Target persistence after freeze | Target repository and target-only unit/concurrency tests | Target parity, eight-limit, exact CAS, generation/state-MAC, fresh-process CRUD |
| Audit/query after freeze | Audit repository, operation events, `.hhout` v2, query cmdlets, audit-only tests | Exact intent/arm, artifact, retrieval, tamper, and crash evidence |
| Main/integration last | Public-cmdlet rewiring, shared configuration, all E2E files, stale-test reconciliation, threat model, final gates | Acceptance reconciliation and canonical exact-candidate proof |

Before adapter parallelism, main splits the current combined journey file into
main-owned target, audit/query, and recovery journey files or retains sole
ownership of it throughout. Workers use disjoint files, never revert concurrent
changes, and report changed files plus focused container evidence.

## Definition of Done

This migration is complete only when:

- SQLite is the sole active structured persistence path.
- No active product flow creates or reads target/audit JSON or JSONL.
- Every remote operation remains durably declared, uniquely armed, and
  externally anchored before dispatch, with completed/skipped/uncertain phase
  evidence afterward.
- Complete command text, optional reason/case, exact remote manifests, terminal
  evidence, and full encrypted stream output survive process restart.
- `Get-HHAuditRecord` and `Get-HHAuditOutput` provide supported, bounded,
  integrity-checked retrieval.
- All target, concurrency, runtime, bootstrap, output-limit, cancellation,
  cleanup, and no-retry contracts remain intact.
- Database corruption, rollback, lock timeout, artifact mismatch, and crash
  boundaries fail closed without inventing success or retrying remote work.
- A second process cannot recover a live batch, and one process can still fan
  out to eight targets under the single operation lock.
- `.hhout` v2 is invocation-bound, durably published, capacity-reserved, and
  streamed with bounded memory/backpressure.
- The provider package is reproducible, pinned, scanned, licensed, and proven on
  every claimed controller RID and both the minimum and pinned PowerShell
  versions; canonical persistence journeys import that package.
- Changed-scope and repository-wide coverage gates pass with required margins.
- All critical integration and fresh-process CLI journeys pass locally.
- Native macOS and live Windows exact-candidate qualifications pass.
- Runtime and validation roots are wholly ignored and cannot be tracked.
- The exact commit passes the standalone laptop gate, gitleaks, threat review,
  and public-release checks.
- GitHub publication is re-read as public, owner-written, Actions-disabled, and
  free of sensitive runtime data.

## Open Items

- Answered: legacy-data migration, target-profile encryption boundary, audit
  query surface, and first-release retention.
- Deferred with user approval: WinRM, audit pruning/export, centralized audit
  collection, full-file database encryption, public backup/restore, and
  isolated forensic snapshot opening.
- Accepted assumption: no existing HostHunterNextGeneration state must survive
  this unreleased cutover.
- Accepted residual: macOS detects whole-data-root rollback through Keychain;
  Linux/Windows colocated key/anchor fallback does not.
- Unvalidated implementation evidence remains pending by design. The
  architecture, API, recovery states, ownership, test interfaces, and release
  sequence have no unresolved technical planning blocker.

## Approval Prompt

The four product decisions and the subsequent technical refinements for
streaming `.hhout` v2 and the declared/armed/completed recovery protocol were
confirmed on 2026-08-24. Any later material change to storage, encryption,
retention, query, migration, or recovery behavior requires new user approval.
