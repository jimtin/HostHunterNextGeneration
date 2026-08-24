# HostHunterNextGeneration Implementation Ledger

## Status

**AMENDED SQLITE CONTRACT CONFIRMED; IMPLEMENTATION AND REQUALIFICATION IN
PROGRESS 2026-08-24**

The pre-migration working tree passed 431/431 product unit tests, 9/9
integration tests, and 16/16 CLI E2E journeys, with all four coverage metrics
above 90% and the full security/build program green. That receipt is a baseline
for behavior that must survive; it is not evidence for the planned SQLite
replacement, exact-commit qualification, or positive live Windows PowerShell
5.1 execution.

## Public contract

The confirmed first release exports exactly these cmdlets:

1. `Set-HHTarget`
2. `Get-HHTarget`
3. `Test-HHTarget`
4. `Remove-HHTarget`
5. `Invoke-HHCommand`
6. `Enable-HHSshKeyAuthentication`
7. `Get-HHAuditRecord`
8. `Get-HHAuditOutput`

All external operations use injectable adapters. Public cmdlets orchestrate
domain functions; transport, persistence, clock/identifier, key protection,
and audit storage implementations remain behind private interfaces.

The controller requires PowerShell 7.4 or newer. SSH is the only qualified v1
transport. `PowerShell7` is the default requested runtime;
`WindowsPowerShell51` is an explicit Windows-target choice reached through a
PowerShell 7 SSH session and a local `-UseWindowsPowerShell` compatibility
runspace. Runtime mismatch or unavailability fails closed without fallback.
WinRM is deferred by user decision until a controlled lab exists.

The confirmed persistence contract is
`docs/planning/sqlite-persistence-plan.md`. SQLite replaces active target JSON
and audit JSONL storage; complete output remains in encrypted `.hhout`
artifacts. No legacy importer or dual-write path is included.

## SQLite migration acceptance delta

All rows below are required before the pre-migration baseline can be described
as release-ready again.

| Requirement | Intended implementation | Focused evidence | Status | Deferred/non-goal |
| --- | --- | --- | --- | --- |
| Authoritative SQLite state | checksummed `0001_initial_sqlite` and SQLite-only adapters | clean construction and fresh-process no-JSON/JSONL journeys | pending | legacy importer; in-place v1 upgrade |
| Reproducible provider | locked Microsoft.Data.Sqlite/SQLitePCLRaw/native graph, exact RID assets, lazy package-only loader | exact version/RID/PowerShell-boundary smoke, package inventory, licences, SBOM and scans | pending | runtime downloads; unqualified RIDs/musl |
| Preserve target semantics | database adapter with exact model, limit, ordering, generation/revision CAS | target units plus competing-process integration | pending | more than eight targets |
| Preserve keyless target inspection | `Get-HHTarget` returns unchanged plaintext objects with unverified-state warning, but grants no mutation/dispatch authority | fresh-process missing-key read plus mutation/dispatch refusal | pending | trusting unverified rows |
| Authenticate plaintext target rows | keyed target-generation state MAC over every saved active and inactive profile in the external anchor | row-redirection, generation-regression, inactive-profile and rollback negatives | pending | full-file database encryption |
| Serialize database, anchor, and remote ownership | bounded writer mutex plus separate operation lock; atomic expected-value anchor update | live-process contention, commit/seal, kill/release, and crash-boundary integration | pending | concurrent remote batches in separate processes |
| Preserve exact accountability | encrypted intent/manifests, per-operation declared/armed/completed/skipped/uncertain evidence, and HMAC chain | transport-spy ordering, substitution, recovery and conditional-phase tests | pending | commands outside HostHunter |
| Reconcile external output | identity-bound chunked `.hhout` v2 plus capacity reservation and database-bound metadata | stream/backpressure and file/rename/directory-sync/DB/anchor fault matrix | pending | output rows inside SQLite; v1 compatibility |
| Recover without retry | only armed incomplete operations become uncertain; unarmed work is failed/not-dispatched; operation lock proves quiescence | competing-process and kill/fault restart integration with endpoint counts | pending | automatic remote retry |
| Query audit history | bounded/cursor-paged `Get-HHAuditRecord`, pending records, exact object shape, and complete decrypted command | query units and fresh-process CLI journeys | pending | bulk unbounded query |
| Query invocation output | verified single-invocation `Get-HHAuditOutput` | ordered six-stream restart journey and tamper negatives | pending | multi-invocation output expansion |
| Refuse legacy state | stable `LegacyPersistenceMigrationRequired` without mutation/network | unchanged-sentinel hash assertions and fresh-process CLI | pending | automatic import or deletion |
| Keep runtime state untracked | ignored `.hosthunter/` and `.artifacts/` plus tracked-path guard | static/security forced-add canary | pending | tracked receipts |
| Preserve indefinitely | no automatic deletion of database or `.hhout` evidence | reopen/count stability and storage-full failure tests | pending | export/prune policy |
| Bound retention pressure before dispatch | real per-invocation capacity reservation, protected DB/recovery margin, streaming/backpressure | aggregate eight-target and mid-command full-disk proof | pending | automatic deletion |
| Preserve platform-honest rollback claims | Keychain external anchor on macOS; owner-private colocated fallback on Linux/Windows | native mac rollback proof and fallback whole-root residual negative | pending | macOS-equivalent whole-root protection off macOS |

## Pre-migration acceptance baseline

| Requirement | Intended implementation | Focused evidence | Status | Deferred/non-goal |
|---|---|---|---|---|
| Record all HostHunter remote operations | Intent-before-network ledger with terminal per-target records | audit unit tests and dispatch integration | verified | commands outside HostHunter |
| Retain full command and streams | encrypted, compressed per-invocation artifact with independent 100 MiB per-target limit | direct and compatibility output tests | direct and deterministic compatibility verified; live 5.1 pending | authentication secrets |
| Optional reason and case | nullable metadata on batch/intent; no prompt | paired CLI journey | verified | mandatory workflow |
| Set one or many targets | schema-v2 atomic store; replace by default; `-Add` extends; at most eight | target-domain tests and fresh-process journeys | verified in container | more than eight targets |
| Select target runtime | `-PowerShellRuntime`, default `PowerShell7`, explicit `WindowsPowerShell51` | target/schema units, canonical CLI negatives, live Windows positives | container/direct and negative paths verified; live 5.1 pending | HostHunter under Windows PowerShell 5.1 |
| Permit two runtime profiles for one endpoint | runtime participates in normalized endpoint identity | endpoint-key units and no-network dual-profile CLI preview | verified deterministically | duplicate name or identical runtime profile |
| Require exact requested PowerShell | Core 7 direct identity or Desktop 5.1 compatibility identity | real SSH fixture, injected bridge seams, live Windows exact-candidate proof | direct, negative, and deterministic bridge paths verified; live 5.1 pending | native shell endpoints and silent fallback |
| Interactive password SSH | native remoting prompt; no unattended product password path | askpass test-only fixture journey | verified | stored password or `sshpass` |
| Bootstrap SSH key auth | exact-entry install, separate key-only probe, rollback on failure | disposable fixture plus authorized live Windows transition | container fixture verified; live Windows transition pending | server-wide password disable; rotation/revoke |
| Bounded multi-target invocation | one batch, independent target results, global concurrency at most eight | direct and mixed runtime fan-out evidence | direct and deterministic mixed fan-out verified; live mixed batch pending | transactional remote execution |
| Recover interrupted work | durable intents without terminal outcome become `Unknown` | ledger recovery matrix | verified at unit boundary | automatic retry |
| Tamper evidence | authenticated encryption and HMAC-chained canonical ledger | corruption matrix and CLI tamper refusal | verified | protection from local administrator controlling data and keys |
| Protect audit key on macOS | data-root-scoped Keychain item through native Security APIs; legacy files fail closed | 37 AuditKeyStore + 21 Configuration focused units; disposable separate-process live lifecycle | focused, live lifecycle, and aggregate working-tree gate verified | explicit legacy migration and Windows DPAPI |
| Bind remote operations to exact manifests | operation-specific command, argument, runtime, and completion contracts | manifest mismatch and operation-boundary unit/integration cases | verified in container | arbitrary candidate-owned control commands |
| Enforce strict audit correlations | require exact batch, invocation, target, operation, dispatch, and outcome relationships | malformed, replayed, and cross-operation correlation cases | verified in container | automatic inference from incomplete records |
| Make target changes conflict safe | compare-and-swap (CAS) over the expected store generation before atomic replacement | concurrent-writer and stale-update cases | verified in container | silent last-writer-wins mutation |
| Bound remote cleanup | deterministic timeout for compatibility-runspace and SSH cleanup after success, failure, or cancellation | timeout and cancellation cleanup cases | verified in container | unbounded cleanup waits |
| Preserve bootstrap uncertainty and one cumulative cap | conservative dispatch classification and one output budget across all bootstrap phases | uncertain-dispatch and cross-phase limit cases | verified in container | retry after uncertain dispatch |
| Defer WinRM honestly | retain no-dispatch guard and stable deferred failure | unit case, negative fresh-process CLI, documentation sweep | verified negative; positive WinRM deferred | all WinRM auth, trust, certificate, and listener work |
| Publish without sensitive operational data | hardened ignores, public threat model, repo-scoped scans | exact-tree/history gitleaks and identifier sweep | working-tree security lane passed; exact-commit/history proof pending | real endpoints, users, fingerprints, keys, ledgers, outputs |
| Keep GitHub owner-only | no collaborators/teams/write apps; Actions disabled; protected main where available | live permission, settings, workflow, and remote-SHA re-read | pending publication | public read/fork/pull-request capability |
| Review external contributions manually | no automatic GitHub or laptop execution | settings audit and published policy | documented; live settings pending | automatic external contribution testing |

## Pre-migration user-action baseline

The detailed matrix in `docs/testing/e2e-workflow-inventory.md` is authoritative.
The release-blocking delta is summarized here.

| User action | Expected behavior | CLI/live evidence | Status |
|---|---|---|---|
| Save default PowerShell 7 target | direct Core 7 metadata persists | fresh-process Linux SSH journey | verified |
| Save explicit PowerShell 7 target | explicit selection behaves identically to the default | fresh-process Linux SSH journey | verified |
| Define PS7 and 5.1 profiles for one endpoint | both identities accepted; exact duplicate rejected | no-network fresh-process preview plus endpoint units | verified without network; live 5.1 save pending |
| Request 5.1 where unavailable | `RuntimeUnavailable`, no fallback or store mutation | negative Linux SSH journey | verified |
| Save and invoke qualified 5.1 profile | Desktop 5.1 compatibility path and all streams | live Windows exact-candidate journey | pending |
| Invoke mixed PS7/5.1 batch | independent runtime attribution and outcomes | live Windows plus deterministic fan-out seams | deterministic seams verified; live mixed batch pending |
| Attempt WinRM | clear deferred error without session or store mutation | negative fresh-process journey | verified negative; positive WinRM deferred |
| Convert password profile to Ed25519 | key-only proof precedes profile transition | disposable fixture plus authorized live Windows journey | fixture verified; live Windows transition pending |
| Remove either named runtime profile | exact selected record is removed atomically | canonical direct profile plus dual-profile unit seams | verified deterministically |

## Pre-migration test baseline

| Production surface | Unit evidence | Integration evidence | CLI E2E evidence | Status |
|---|---|---|---|---|
| Target domain/store | schema v2, v1 migration, runtime identity, limit, atomicity, corruption, CAS | lock/race, stale-generation, and atomic-write seams | target CRUD, runtime profiles, ninth, WhatIf | verified in container |
| SSH transport/trust | argument construction, host identity, runtime request, exact operation manifests | real PowerShell 7 subsystem, wrong auth, changed key, negative 5.1, manifest rejection | onboarding, runtime selection, changed trust, retest | verified for container/direct and negative paths |
| Windows PowerShell bridge | planning, identity, envelopes, bounded cleanup, limits, no fallback | deterministic compatibility, cancellation, and mixed-fan-out seams plus live Windows | negative fixture plus live positive journeys | deterministic evidence verified; live positive pending |
| WinRM guard | always-deferred v1 failure before session creation | no success fake | fresh-process no-mutation rejection | verified negative; positive WinRM deferred |
| Audit crypto/ledger | AES-GCM round trip/failure, canonical HMAC chain, ordering, truncation, strict correlations | unwritable/partial/corrupt store plus cross-operation correlation rejection | tamper refusal and recovery evidence | verified, including strict correlations |
| Output writer | all stream kinds/order, limit, compression, hashes, runtime metadata | direct and compatibility envelope evidence | direct plus live 5.1 invocation | direct and deterministic compatibility verified; live 5.1 pending |
| Dispatcher | intent ordering, no retry, runtime attribution, per-target state, cancellation, fan-out limit | fake endpoints, real SSH, mixed-runtime seams | selected/reason/case and live mixed runtime | container/direct and deterministic mixed paths verified; live mixed pending |
| Key bootstrap | exact marker, idempotence, rollback, profile transition, uncertainty, cumulative cap | real SSH key-only validation, rollback, and cross-phase limit seams | fixture success plus authorized live Windows invocation | fixture and adversarial seams verified; live Windows pending |
| Module package | exact exports and help metadata | packaged clean import | fresh-process module-contract journey | verified |

## Parallel work

Parallel implementation used disjoint ownership for schema/runtime storage, the
Windows PowerShell bridge, bootstrap hardening, accountability, and CLI
journeys. The main agent owns final reconciliation, exact-commit proof, live
Windows mutation and qualification, publication, and live GitHub settings
verification. Workers must not edit another worker's files or revert concurrent
changes.
