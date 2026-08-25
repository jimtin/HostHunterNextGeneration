# CLI E2E Workflow Inventory

## Status

**SQLITE ACTION IMPLEMENTATION VERIFIED; MACOS DEFAULT-ROOT SSH
REQUALIFICATION IN PROGRESS 2026-08-25**

This is the Playwright-equivalent action matrix for a PowerShell CLI module with
no browser surface. Canonical journeys run in fresh `pwsh -NoProfile` processes
against a disposable, pinned PowerShell 7 SSH fixture. The fixture can prove
direct PowerShell 7 and negative 5.1-unavailable behavior, but it cannot provide
a positive Windows PowerShell 5.1 compatibility runspace. Positive 5.1 and
mixed-runtime rows therefore belong to the separate live Windows
exact-candidate lane. The current package-backed working-tree E2E lane passes
23/23 journeys. Process/fault actions that cannot safely run through a normal
CLI session are covered by the package integration lane and public-boundary
units. Exact-candidate reproduction remains pending.

## Confirmed Forensics Part 1 extension

The confirmed ECS 9.5.0 Process Start work is tracked in
[`forensics-part1-action-matrix.md`](forensics-part1-action-matrix.md). Its
first slice is a package-backed local EVTX-to-ECS/outbox service journey. The
seven planned forensics cmdlets remain unexported until their complete remote
and local workflows are implemented, so the current exact-eleven export
assertion remains correct for the released surface.

## Docker runtime completion extension

Docker is the canonical operator runtime from `0.3.0-preview1` onward. The
package-only CLI matrix below must therefore execute from the production
controller image, with fresh external data, key, anchor, and SSH-key volumes.
The runtime journey is incomplete until every one of the eleven exported
cmdlets has been exercised from that image and the same image has completed
the exact Windows qualification.

The runtime E2E adds these non-negotiable actions:

- initialize an empty external-volume set without macOS Keychain or a Windows
  credential-store dependency;
- stop and restart the controller, preserving authenticated target, audit,
  escalation-preference, and encrypted output state;
- run the complete existing eleven-cmdlet matrix through the packaged module;
- run the internal Sysmon 1 and Security 4688 ECS 9.5 Process Start journey in
  the network-isolated parser service without mounting secrets, databases, or
  SSH keys there;
- reject missing, swapped, unsafe-mode, or wrong-provider key/anchor volumes;
- prove `docker compose down` does not remove external state volumes;
- require an explicit exact-project confirmation before the lifecycle command
  destroys disposable volumes; and
- keep all seven incomplete Forensics acquisition cmdlets absent from the
  export inventory.

The live Windows qualification remains part of the user-action proof, rather
than a mock-only supplement. It covers PowerShell 7, Windows PowerShell 5.1,
mixed-runtime stream attribution, Windows Process Start audit policy including
the optional command-line warning and 4688 observation, privilege restoration,
and the protected Ed25519/password-recovery lifecycle.

## SQLite post-approval action matrix

This matrix is authoritative for the confirmed persistence amendment.
No release row is left unexplained: `verified working tree` means current
package E2E or public-boundary plus package-integration evidence; `pending live`
is limited to the immutable native qualification.

| User action | Route/surface | Role/persona | Data state | Expected behavior | CLI E2E evidence | Unit/integration evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Import module and inspect help | module package | local operator | clean package | exactly eleven cmdlets and resolvable help without loading SQLite or creating state | `HH_TEST_MODULE_PATH` clean packaged import | manifest/export/help/lazy-loader contract | implemented; requalification pending |
| Inspect or save escalation preference | `Get-HHEscalationPreference`, `Set-HHEscalationPreference` | local operator | absent or authenticated state | built-in method reads without creating state; explicit save is authenticated and survives restart | WhatIf/no-root and save/restart/read journeys | schema-v2 migration, MAC, CAS, and anchor tests | implemented; requalification pending |
| Preview Windows process policy | `Set-HHWindowsProcessAuditPolicy -WhatIf` | local operator | absent or populated state | warning is visible when enabling command-line inclusion; no root, intent, native API, registry, or network mutation | package WhatIf journey | public-boundary warning/no-write matrix | implemented; requalification pending |
| Set Windows process audit policy | `Set-HHWindowsProcessAuditPolicy` | local operator | one to eight saved Windows targets | native query/set/requery without auditpol; exact privilege restoration and finite per-target result | non-Windows package negative and exact Windows PS7/5.1 journey | native adapter, compensation, escalation, and audit-correlation units | implemented; exact Windows pending |
| Control 4688 command-line inclusion | `-CommandLineLogging` | local operator | ProcessCreation selected | Unchanged/Enabled/Disabled/NotConfigured; enabling warns but continues; exact prior registry state restored by qualification | package warning/validation plus live 4688 presence/absence | registry snapshot/type/value/compensation matrix | implemented; exact Windows pending |
| Preview target creation | `Set-HHTarget -WhatIf` | local operator | absent data root | no root, database, anchor, prompt, audit event, or network | whole root remains absent | ShouldProcess before persistence initialization | verified working tree |
| Preview two runtime profiles | `Set-HHTarget -InputObject -WhatIf` | local operator | existing database | validate profiles but preserve DB generation/head and avoid network | before/after logical-state comparison | runtime/domain and no-write units | verified working tree |
| Use the macOS default data root | target, command, and key-auth cmdlets | macOS operator; `HH_DATA_ROOT` unset | `~/Library/Application Support/HostHunterNextGeneration` | password save, restart, command, key conversion, and key-auth command all use the exact managed pin without argument splitting | package-backed fresh-process journey rooted under `Library/Application Support`; native Windows controller receipt | unique environment binding, cleanup/concurrency, patched-floor, and OpenSSH capability tests | working-tree package and fixture verified; exact native pending |
| Reject unsafe SSH controller boundaries | every SSH-capable cmdlet | local operator | vulnerable PowerShell patch or OpenSSH without required expansion | stable pre-dispatch refusal; no prompt, intent, target mutation, or network | package negative journey | version-floor and capability units | focused verified; exact candidate pending |
| Reject changed host identity from a spaced root | target and command cmdlets | local operator | managed `known_hosts` under `Library/Application Support` contains the wrong pin | fail closed before command dispatch; never consult a global known-hosts file or update the managed pin | real SSH fixture wrong-pin journey | strict option and fingerprint units | working-tree fixture verified; exact candidate pending |
| Save or add targets | `Set-HHTarget`, `-Add` | local operator | valid SSH endpoint | intent is durable before validation and the complete target mutation is atomic | set/restart/get/add/restart/get with SQLite-only state | schema, generation, eight-limit, concurrency, and CAS integration | verified working tree |
| Reject invalid target mutation | `Set-HHTarget` | local operator | duplicate, ninth, WinRM, trust/auth/runtime failure | stable failure with no target-generation change or unintended network | rewritten negative journeys | validation and transaction rollback | verified working tree |
| Read no targets | `Get-HHTarget` | local operator | valid empty database | return zero objects and create no audit event | empty fresh-process read | empty query/no-mutation units | verified working tree |
| Read or filter targets | `Get-HHTarget -Name` | local operator | populated database | preserve sorted and ordinal-ignore-case behavior | cross-process all/name reads | lookup and sorting units | verified working tree |
| Inspect targets without an available key | `Get-HHTarget` only | local operator | path-safe database exists; key or anchor unavailable | preserve plaintext target objects with a non-terminating unverified-state warning; no mutation, audit event, or network | fresh-process key/anchor read-only journey | projection/path checks and no-authority units | verified working tree |
| Refuse unauthenticated target mutation or dispatch | mutation and remote-capable cmdlets | local operator | key or anchor unavailable | `AuditKeyUnavailable`; do not trust displayed rows, mutate, recover, or use the network | fresh-process key/anchor mutation/dispatch negatives | target-state MAC and anchor units | verified working tree |
| Retest no targets | `Test-HHTarget` | local operator | empty database | return zero objects without intent or network | empty fresh-process retest | empty-selection unit | verified working tree |
| Retest saved targets | `Test-HHTarget` | local operator | populated database | record validation without changing target generation/profile | probe, query history, compare target state | intent/outcome and immutable-profile integration | verified working tree |
| Preview target removal | `Remove-HHTarget -WhatIf` | local operator | populated database | no target, generation, anchor, audit, or filesystem mutation | logical state unchanged | ShouldProcess/no-write unit | verified working tree |
| Remove saved or missing targets | `Remove-HHTarget` | local operator | populated database | atomic removal; missing name fails without mutation | remove/restart/get and missing-name negative | transaction/CAS/receipt integration | verified working tree |
| Reject command before intent | `Invoke-HHCommand` | local operator | invalid syntax or target selection | no invocation, artifact, anchor advance, or dispatch | DB history and network sentinel unchanged | parser/selection/no-intent units | verified working tree |
| Invoke on one to eight targets | `Invoke-HHCommand` | local operator | selected valid targets | every intent and actual operation arm anchored before its network phase; exact command runs once per target | invoke/restart/query record, operation states, and six streams | transaction/arming ordering, fan-out, and artifact integration | verified working tree |
| Invoke with optional context | `Invoke-HHCommand -Reason -CaseId` | local operator | valid target | exact optional values and complete command survive restart | retrieve using `Get-HHAuditRecord` | encrypted lookup/round-trip units | verified working tree |
| Preview SSH-key conversion | `Enable-HHSshKeyAuthentication -WhatIf` | local operator | password profile | no key, target, audit, DB, anchor, or network mutation | before/after logical-state comparison | ShouldProcess and plan units | verified working tree |
| Convert SSH authentication | `Enable-HHSshKeyAuthentication` | local operator | password profile | preserve install/proof/CAS/rollback/unknown contract and queryable outcome | fixture success plus record query; live Windows lane | database CAS and compensation integration | fixture verified; exact Windows pending |
| Query empty audit history | `Get-HHAuditRecord` | local operator | no invocations | return zero records without changing audit/target heads | repeated empty read | read-only/empty-query units | verified working tree |
| Query bounded audit history | `Get-HHAuditRecord -First` | local operator | more than 100 records | newest first; default 100; accepted range 1..1000 | ordering/default/boundary journey | limit and stable ordering units | verified working tree |
| Page older audit history | `Get-HHAuditRecord -BeforeSequence` | local operator | more than one page | exclusive stable cursor has no duplicates/gaps and preserves descending sequence | multi-page restart journey | cursor and concurrent-writer snapshot units | verified working tree |
| Filter audit history | `Get-HHAuditRecord` filters | local operator | mixed records | apply exact ID/target/case/time/operation/status contract | every filter and valid combination | parameterized query and boundary units | verified working tree |
| Inspect active audit work | `Get-HHAuditRecord -Status Pending` | local operator | another process owns a live batch | return authenticated pending record without recovery or anchor mutation | concurrent-process query | stable snapshot and operation-lock integration | verified by public units and process integration |
| Inspect complete command | `Get-HHAuditRecord` | local operator | valid invocation | return complete decrypted command value after restart | exact long-command equality | AEAD and formatter units | verified working tree |
| Retrieve complete output | `Get-HHAuditOutput -InvocationId` | local operator | complete v2 artifact | return exactly one invocation's ordered typed evidence projections | cross-process event equality/order | header/chunk/footer/hash/AEAD/deserialization integration | verified working tree |
| Reject unavailable output | `Get-HHAuditOutput` | local operator | unknown/malformed ID or incomplete/missing/swapped artifact | stable fail-closed error; never label partial evidence complete | fresh-process negative matrix | validation/path/hash/tag branches | verified working tree |
| Query after tampering | both audit cmdlets | local operator | edited/deleted/reordered DB or stale anchor | return no unverified data and fail `AuditIntegrityFailed` | tamper/restore journeys | corruption/chain/anchor matrix | verified by public units and package integration |
| Refuse remote work after tampering | all remote-capable cmdlets | local operator | target or audit state changed | fail before network | untouched network sentinel | startup integrity and target-state MAC | verified by public units and package integration |
| Recover unarmed interrupted invocation | next remote-capable operation | local operator | intent exists but no arm/terminal | record `Failed`/`NotDispatched`, never reconnect, make record queryable | kill/restart/query journey | crash-boundary and idempotent recovery | verified package integration |
| Recover armed interrupted invocation | next remote-capable operation | local operator | armed operation lacks completion | record operation `DispatchUncertain` and invocation `Unknown`; never reconnect | kill/restart/query journey | operation-state recovery and endpoint-count proof | verified package integration |
| Leave a live invocation alone | second remote-capable process | local operator | first process holds operation lock | bounded `OperationBusy`; no recovery or network | concurrent live-owner journey | lock ownership/release integration | verified package integration |
| Recover orphan or partial artifact | next remote-capable operation | local operator | renamed v2 artifact or incomplete staging | attach only identity-bound complete artifact as partial evidence; quarantine incomplete staging | restart/recovery/query negative | v2 classifier and recovery paths | verified working tree |
| Encounter legacy persistence | any persistence cmdlet | local operator | legacy file/lock/temp/key/output state | `LegacyPersistenceMigrationRequired`; no import, deletion, DB creation, anchor change, or network | read plus remote-capable negative journeys | exact sentinel and ordering units | verified working tree |
| Encounter unsupported SQLite state | any persistence cmdlet | local operator | unmatched/old/new/checksum-mismatched DB | `PersistenceSchemaUnsupported`; no migration or network | fresh-process schema negatives | pre-mutation identity/schema verification | verified working tree |
| Refuse insufficient capacity | remote-capable cmdlet | local operator | reservation cannot cover all selected targets plus protected margin | `PersistenceCapacityInsufficient`; no arm or network | deterministic full-volume journey | reservation and aggregate eight-target integration | verified package integration |
| Encounter busy or mid-command full storage | mutation/query/remote cmdlets | local operator | lock timeout, `SQLITE_FULL`, or external fill after dispatch | stable local error before dispatch or honest `Unknown` after arm; no retry | deterministic negative journey | busy, full, streaming and artifact fault integration | verified package integration |
| Repeat read-only audit queries | both audit query cmdlets | local operator | valid history | no new batch, invocation, audit event, artifact, or anchor update | authenticated heads/counts unchanged | read-only transaction units | verified working tree |
| Verify SQLite-only persistence | all eleven cmdlets | local operator | complete journey set | no active flow creates or reads target/audit JSON or JSONL | filesystem sweep and legacy negatives | deleted-surface/reference guard | implemented; requalification pending |

The temporary no-space override root used while diagnosing the macOS failure is
an independent authenticated store. It is not migrated, merged, or deleted by
these journeys; cleanup requires a separate explicit operator decision after
the default-root proof succeeds.

Positive Windows PowerShell 5.1 and mixed-runtime success remain pending until
the live Windows exact-candidate lane passes. SQLite does not turn mock
runtime evidence into release qualification.

## Pre-migration behavioral baseline

| User action | Surface | Persona and state | Expected behavior | CLI E2E evidence | Unit/integration evidence | Status |
|---|---|---|---|---|---|---|
| Import module, inspect exports, resolve help | module package | local operator; clean process | exactly six public commands and resolvable help | `TargetAndCommandJourneys.Tests.ps1` module contract | `ModuleContract.Tests.ps1` | covered |
| Preview default target creation | `Set-HHTarget -WhatIf` | local operator; empty store | no state or network mutation; default resolves to `PowerShell7` | clean-process preview | ShouldProcess and target-input unit cases | covered |
| Save and reload a default PowerShell 7 target | `Set-HHTarget`, `Get-HHTarget` | local operator; valid password SSH target | direct Core 7 runtime validated and schema-v2 metadata persists | native prompt plus fresh-process reload | real SSH transport and schema unit cases | covered |
| Save an explicit PowerShell 7 target | `Set-HHTarget -PowerShellRuntime PowerShell7` | local operator; valid password SSH target | same direct runtime contract without fallback | explicit-runtime fresh-process set/get | runtime validation plus real SSH integration | covered |
| Preview two runtime profiles for one endpoint | `Set-HHTarget -InputObject -WhatIf` | local operator; PS7 and 5.1 profiles share SSH identity | distinct requested runtimes are accepted; exact duplicates are rejected; store stays byte-identical | no-network two-profile preview | runtime-aware endpoint-key unit matrix | covered without network; live 5.1 save pending |
| Reject unavailable Windows PowerShell 5.1 | `Set-HHTarget -PowerShellRuntime WindowsPowerShell51` | local operator; Linux PowerShell 7 fixture | `RuntimeUnavailable`, no fallback, no target-store mutation | negative fresh-process fixture journey | bridge planning and failure integration seams | covered |
| Save a qualified Windows PowerShell 5.1 target | `Set-HHTarget -PowerShellRuntime WindowsPowerShell51` | local operator; Windows target with Desktop 5.1 | compatibility identity validated and persisted | live Windows exact-candidate journey is required | bridge unit/integration matrix | blocked |
| Add a second PowerShell 7 endpoint | `Set-HHTarget -Add` | local operator; one saved target | both profiles persist and retest is non-mutating | alternate fixture alias plus byte-identical retest | batch/store unit cases | covered |
| Reject a ninth target | `Set-HHTarget` | local operator; proposed set has nine records | reject before network with byte-identical store | fresh-process negative journey | target-domain limit cases | covered |
| Preview key conversion | `Enable-HHSshKeyAuthentication -WhatIf` | local operator; password profile | no remote or profile mutation | password profile remains unchanged | key-plan unit cases | covered |
| Reject changed host identity | `Set-HHTarget` | local operator; pinned SSH profile | reject before save with byte-identical store | changed fingerprint journey | SSH trust unit cases | covered |
| Reject password authentication failure | `Set-HHTarget` | local operator; wrong username | prompt fails promptly and saves nothing | wrong-user fresh-process journey | native failure and audit serialization integration | covered |
| Audit failure before command dispatch | `Invoke-HHCommand` | local operator; transport fails before identity proof | terminal failure has no observed fingerprint, identity, runtime, or validation timestamp | strict fresh-process audit verifier | intent/terminal correlation unit cases | covered |
| Invoke complete streams on direct targets | `Invoke-HHCommand -Target` | local operator; two active PS7 profiles | exact command runs once per target and preserves all six streams | exact runtime, fingerprint, manifest, terminal correlation, and decrypted six-stream evidence | direct stream and RunspaceId integration | covered |
| Invoke one Windows PowerShell 5.1 command | `Invoke-HHCommand` | local operator; validated 5.1 profile | compatibility execution preserves ordered streams and runtime attribution | live Windows exact-candidate journey is required | bridge envelope integration matrix | blocked |
| Invoke a mixed PowerShell 7 and 5.1 batch | `Invoke-HHCommand` | local operator; one profile per runtime | independent outcomes and attribution under global throttle at most eight | live Windows exact-candidate journey is required | deterministic mixed-fan-out seams | blocked |
| Supply optional operational context | `Invoke-HHCommand -Reason -CaseId` | local operator; valid selected target | no mandatory metadata prompt; complete text and optional values audited | exact command/context, manifest, terminal, ciphertext-redaction, and decrypted-artifact assertions | audit metadata unit cases | covered |
| Refuse dispatch after audit tampering | `Invoke-HHCommand` | local operator; modified ledger | no network dispatch; exact restoration resumes | append-and-restore journey | corruption matrix | covered |
| Convert a password target to Ed25519 | `Enable-HHSshKeyAuthentication` | local operator; valid password profile | exact key entry installed, key-only proof succeeds, then profile changes | disposable fixture journey passed; live Windows exact-candidate journey required | generation, idempotence, rollback, dispatch uncertainty, and cumulative-cap integration | covered locally; live qualification pending |
| Load the proven protected key into a run-scoped agent | native Windows qualification controller | local operator; committed public-key profile | exact identity is loaded without passphrase in arguments, environment, files, logs, or receipts | exact-package Windows receipt required | focused qualification contract verifies agent start, exact-key add/list/remove, environment restoration, and stop | implemented; live qualification pending |
| Invoke through the run-scoped agent | `Invoke-HHCommand` | local operator; exact protected identity loaded | subsequent key-only command succeeds without runtime fallback | exact-package Windows receipt required | transport and qualification contract tests | implemented; live qualification pending |
| Preserve password recovery after key transition | native Windows qualification controller | endpoint has HostHunter public key and password login remains enabled | password-only SSH succeeds independently; this is recovery authentication, not runtime fallback | exact-package Windows receipt required | qualification contract preserves public-key-disabled password probe | implemented; live qualification pending |
| Remove the exact qualification identity and agent | native Windows qualification controller | live key journey completed | exact remote authorized-key line and local agent identity are removed, agent stops, prior agent environment is restored | exact-package Windows receipt requires all cleanup booleans | bootstrap rollback and qualification cleanup tests | implemented; live qualification pending |
| Destroy exact Docker qualification state | Docker Windows qualification controller | six fresh labelled qualification volumes exist | controller, remote key, agent, process policy, and all six volumes are cleaned; partial survivors block success | exact Windows receipt requires controllerVolumeCleanupComplete and six destroyed volumes | focused lifecycle and Windows qualification cleanup tests | implemented; exact live qualification pending |
| Remove exact optional native Keychain items | optional macOS qualification controller | disposable data-root-scoped audit key and anchor exist | both production-derived items exist before deletion, deletion succeeds, and both are absent afterward | optional macOS receipt requires cleanupComplete | focused macOS qualification cleanup tests | compatibility-only; not a Docker release gate |
| Remove saved or missing profiles | `Remove-HHTarget` | local operator; named runtime profiles | selected names removed atomically; missing name fails without temporary state | direct fresh-process remove and missing-profile journeys | atomic and CAS removal unit cases | covered |
| Attempt a WinRM target mutation | `Set-HHTarget -Transport WinRM` | local operator; any endpoint | clear deferred error, no session, no saved mutation | negative fresh-process journey | fail-closed WinRM unit cases | covered negative; positive WinRM deferred |
| Exceed per-target output limit | remote invocation | local operator; output crosses 100 MiB | shared pipeline stops and offender is classified | intentionally not duplicated through CLI | real streaming integration | covered |
| Fail key-only proof and roll back | key bootstrap | local operator; proof fails | exact installed entry removed; password profile retained | intentionally not repeated after successful CLI transition | real fixture rollback integration | covered |
| Recover interrupted intent | module startup | local operator; durable intent lacks terminal event | append terminal `Unknown` without retry | deliberate crash omitted from CLI | ledger recovery unit matrix | covered |

Rows marked `blocked` or `live qualification pending` require the separate live
Windows release lane. A mock-only Windows PowerShell 5.1 success is insufficient.

Exact remote-operation manifests, strict audit correlations, target-store CAS,
and bounded cleanup are internal enforcement work rather than additional public
actions. Their adversarial container evidence passed in the canonical
working-tree gate and is tracked in the implementation ledger and critical-path
inventory.

## Deferred actions

Positive WinRM operation is deferred by user decision until a controlled lab
exists. Audit export/pruning and SSH key revoke/rotation require separately
approved public cmdlet names and lifecycle semantics. No automatic audit
deletion ships in this release. Key-bootstrap rollback removes only the exact
entry it installed.
