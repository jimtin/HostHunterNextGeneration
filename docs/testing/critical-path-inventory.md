# Critical Path Inventory

## Status

**SQLITE CRITICAL PATHS IMPLEMENTED; EXACT-CANDIDATE NATIVE PROOF PENDING
2026-08-25**

The SQLite v2 working tree has 647/647 passing product tests, all four coverage
metrics above 90%, 23/23 package CLI journeys, and nine passing process/fault
scenarios. The supported security floors are PowerShell 7.4.19, 7.5.10, and
7.6.5 within their servicing lines, plus later supported releases; SSH also
requires OpenSSH 8.4+ environment expansion. Exact-candidate reproduction,
native Windows, and post-publication
GitHub verification remain pending.

## Confirmed SQLite critical paths

| ID | Critical path | Entry point | Required failure evidence | Focused proof | Status |
| --- | --- | --- | --- | --- | --- |
| CP-DB-01 | Lazily initialize pinned packaged provider and fresh schema | first real persistence action | help/WhatIf loads nothing; unsupported RID/version/native asset or nonempty unknown schema fails before network | provider/schema units, clean-DB integration, PS7.4/7.6.5 claimed-RID package smoke | verified working tree |
| CP-DB-02 | Enforce SQLite-only cutover | every persistence cmdlet | complete legacy evidence fails `LegacyPersistenceMigrationRequired`; unmatched DB fails `PersistenceSchemaUnsupported`; no mutation/network | legacy/schema detector units and fresh-process journeys | verified working tree |
| CP-TGT-DB-01 | Preserve target model and CAS | target CRUD and bootstrap | name/endpoint collision, ninth target, stale generation/revision, competing process, unknown commit | target units plus multi-process DB integration | verified working tree |
| CP-AUD-DB-01 | Declare, commit, arm, and anchor before network | every remote-capable phase | DB, encryption, comparison, mutex, or anchor failure permits no phase dispatch; conditional phases reflect actual use | manifest/operation-state units plus transport/network sentinel integration | verified working tree |
| CP-AUD-DB-02 | Stream and durably publish identity-bound output and terminal evidence | command/probe/bootstrap completion | capacity, chunk, flush, rename, directory-sync, DB terminal, or final-anchor failure never invents complete output/success | v2 stream/artifact/transaction/anchor fault matrix | Linux and macOS verified; exact Windows pending |
| CP-AUD-DB-03 | Recover without remote retry or live-owner interference | next remote-capable operation | unarmed work fails/not-dispatched; armed incomplete work becomes uncertain/unknown; live owner yields `OperationBusy` | competing-process kill/fault restart with endpoint invocation count | verified working tree |
| CP-AUD-DB-04 | Detect tamper and rollback | startup and query | row edit/delete/reorder, wrong key, stale/missing anchor, DB rollback, or target redirection refuses dispatch/query | corruption matrix and native Keychain rollback proof | container verified; exact macOS pending |
| CP-QRY-01 | Retrieve bounded and cursor-paged audit records | `Get-HHAuditRecord` | invalid bounds/cursor, unknown exact ID, unavailable key, race, or corrupt history returns stable errors/no unverified data | query units plus filters/paging/pending fresh-process journeys | verified working tree |
| CP-QRY-02 | Retrieve one complete output | `Get-HHAuditOutput` | malformed/unknown ID, missing/swapped/corrupt/partial artifact fails closed | artifact/query units plus ordered six-stream restart journey | verified working tree |
| CP-DB-03 | Serialize durable writes and remote ownership | all SQLite mutations and remote batches | finite writer/operation timeout, reader snapshot race, anchor regression, WAL crash, `SQLITE_FULL`; no retry | multi-process, live-owner, reader/writer, and fault integration | verified working tree |
| CP-DB-04 | Refuse unsafe backup/restore in v1 | operator filesystem action | raw copied or stale database cannot become active against current anchor | documented no-public-restore contract plus stale-copy negative | verified working tree |
| CP-SEC-DB-01 | Protect local runtime paths | data-root initialization | unsafe mode/ACL, symlink/reparse, escape, root, network path, or tracked runtime state fails closed | platform path units and static/security canary | Unix verified; Windows implementation focused green and native pending |
| CP-SEC-DB-02 | Bound retained-output resource pressure | before and during remote dispatch | capacity reservation/margin failure refuses dispatch; external mid-command fill records only honest evidence | eight-target reservation, bounded streaming/backpressure, and full-volume faults | verified working tree |
| CP-PKG-DB-01 | Package reproducible native provider | package build/import | missing/incorrect managed/native asset, lock/licence/hash/SBOM drift, source-imported E2E, or unsupported RID blocks release | locked build, exact-package scan, clean package import and provider CRUD smoke | verified working tree; exact archive pending |

## Pre-migration behavioral baseline

| Critical path | Entry point | Required failure evidence | Focused proof | Status |
|---|---|---|---|---|
| Save a default PowerShell 7 SSH target | `Set-HHTarget` | trust, authentication, timeout, non-PowerShell endpoint, no partial write | real SSH fixture plus fresh-process default-runtime save/reload | verified |
| Save an explicit PowerShell 7 SSH target | `Set-HHTarget -PowerShellRuntime PowerShell7` | Core/major-version mismatch without fallback | identity unit matrix, real SSH fixture, fresh-process CLI | verified |
| Use the macOS default or another space-containing data root | `Set-HHTarget`, `Invoke-HHCommand`, `Enable-HHSshKeyAuthentication` | raw path must never become multiple SSH arguments; environment reference must be unique and restored; wrong pin remains fail-closed | native SSH fixture rooted under `Library/Application Support`, restart and key-auth journey, exact Windows qualification receipt | working-tree fixture and 7.4.19 floor verified; exact native pending |
| Refuse a vulnerable controller or unsupported OpenSSH expansion boundary | every SSH-capable cmdlet | stable pre-dispatch error; no intent, authentication prompt, or target mutation | runtime-floor and functional OpenSSH-capability units/integration | focused verified; exact candidate pending |
| Save an explicit Windows PowerShell 5.1 SSH target | `Set-HHTarget -PowerShellRuntime WindowsPowerShell51` | non-Windows outer target, missing compatibility session, non-Desktop or non-5.1 identity, no partial write | injected bridge seams, Linux negative fixture, live Windows exact-candidate proof | deterministic and negative paths verified; live positive pending |
| Save two runtime profiles for one SSH endpoint | `Set-HHTarget -Add` | exact duplicate runtime profile and duplicate name rejected | endpoint-key unit matrix plus no-network fresh-process preview | verified without network; live 5.1 save pending |
| Refuse legacy target/audit stores | persistence startup | any legacy JSON/JSONL or unmatched database is preserved and fails before network | replacement SQLite detector and fresh-process negative journey | verified |
| Save one to eight targets atomically | `Set-HHTarget`, `-Add` | duplicate identity, ninth target, stale CAS generation, concurrent writer, failed commit | target/store unit matrix plus competing-writer, two-endpoint, and ninth-target CLI seams | verified, including CAS |
| Persist and select active targets | target CRUD cmdlets | corruption, unsupported schema, replace/add/remove invariants | SQLite store unit matrix and fresh-process reload | verified |
| Protect macOS audit key and database head | audit startup | unavailable/locked/corrupt Keychain, failed create, cross-process read, legacy plaintext key, rollback/regression | existing key cases plus second-item anchor and whole-DB rollback proof | implementation and disposable lifecycle verified; exact candidate pending |
| Audit before network | every outbound operation | unavailable database/key, failed transaction/anchor, unterminated intent, invalid correlation | SQLite accountability units and network-sentinel integration | verified |
| Bind exact remote-operation manifests | all network-capable private operations | missing, substituted, or mismatched operation manifest | operation-specific manifest rejection unit/integration matrix | verified |
| Invoke direct PowerShell 7 commands | `Invoke-HHCommand` | runtime mismatch, terminating/non-terminating errors, timeout, no retry | real SSH streams, RunspaceId fan-out, fresh-process CLI | verified with runtime attribution |
| Invoke bridged Windows PowerShell 5.1 commands | `Invoke-HHCommand` | bridge open/identity/cleanup timeout or cancellation, terminating error, lost completion, no fallback | injected bridge and bounded-cleanup seams plus live Windows exact-candidate streams | deterministic bridge and cleanup verified; live positive pending |
| Invoke a mixed-runtime batch | `Invoke-HHCommand` | independent attribution, one-target failure, global throttle, uncertain peer outcome | fan-out unit/integration seams plus live Windows exact-candidate batch | deterministic fan-out verified; live mixed batch pending |
| Capture complete streams | dispatcher/output writer | all six streams, serialization safety, 100 MiB per-target cap | direct and compatibility envelopes, finite serialization, streaming limit tests | direct and deterministic compatibility paths verified; live 5.1 pending |
| Recover interrupted audit | module startup | missing terminal, invalid recovery set, failed terminal/anchor commit | kill/fault restart without endpoint retry | verified in process-kill integration |
| Detect evidence tampering | audit verification | row edit/delete/reorder, wrong key, DB rollback, target redirection, artifact mismatch | SQLite corruption matrix and CLI refusal before dispatch/query | verified in container; native Keychain rollback pending |
| Convert password SSH to key | `Enable-HHSshKeyAuthentication` | generation/read/install/proof failures, uncertain dispatch, cumulative cap, cleanup, idempotence | disposable fixture, adversarial bootstrap seams, and authorized live Windows exact-candidate transition | fixture, uncertainty, and cumulative cap verified; live transition pending |
| Use and clean a passphrase-protected qualification key | exact Windows package qualification | interactive key creation/proof, exact agent identity, agent stop, password recovery, or remote rollback fails | focused qualification contract plus redacted native receipt fields | focused contract verified; exact live Windows proof pending |
| Prove exact native Keychain cleanup | macOS and Windows qualification completion | wrong service, item-not-found false success, partial lifecycle, or missing absence check | focused qualification tests plus exact-package native receipts | focused contract verified; exact native receipts pending |
| Preserve unrelated keys on rollback | bootstrap internals | exact marker conflict, failed key-only proof, rollback failure | real fixture and remote-script unit matrix | verified |
| Reject endpoint identity change | target and command gateways | changed fingerprint or managed host record | trust unit matrix and CLI changed-identity refusal | verified |
| Reject WinRM in v1 | target and command cmdlets | no session creation, no target mutation, clear deferred error | fail-closed unit case plus fresh-process negative CLI | verified negative; positive WinRM deferred |

Positive Windows PowerShell 5.1 execution and mixed-runtime fan-out require the
explicit live Windows exact-candidate lane; a Linux mock cannot make those rows
verified. WinRM is deferred by user decision until a controlled lab exists. It
is an expected negative path, not an unqualified first-release feature.

SSH key revoke/rotation and audit export/pruning remain deferred because their
public APIs are outside the confirmed first-release cmdlet set.
