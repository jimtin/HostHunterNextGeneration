# HostHunter Cmdlet Action Matrix

## Scope

This is the complete user-action inventory. HostHunter is a PowerShell CLI, so
the package-backed service journey is the Playwright-equivalent layer. Exactly
seventeen ordered steps run against one fresh authenticated SQLite store and one
SSH target. The local journey uses Linux; the same manifest is completed by a
separate live Windows PS7/OpenSSH qualification for Windows-positive behavior.

Direct SQL connections are read-only (`PRAGMA query_only=ON`). Product cmdlets
perform every write. Each step records duration, public result, expected
outcome and before/after database snapshot.

The native macOS client adds one user-facing entry path without adding product
managed-host behavior: profile import starts/reuses the container, generated proxies mirror
the packaged exports, and each framework invocation crosses one framed standard-input
bridge. The client also owns the two local visualization lifecycle commands.
The native-client SSH qualification calls all seventeen unique framework cmdlets,
including persistence/audit readback and the password-to-key transition.

| Step | User action | Role/state | Expected public behavior | Required database evidence | Status |
| ---: | --- | --- | --- | --- | --- |
| 1 | `Get-HHTarget` / `Get-HHTargets` alias | operator; empty store | displays `No currently set`, returns no targets and creates no state | no DB or row/generation delta | verified |
| 2 | `Set-HHTarget` | operator; first-use SSH fixture; visualization paused | discovers, pins and validates the host, saves authentication state, then records host details in its audit result without visualizer scheduling | profile=1; target generation/mutation +1; validation plus host-details audit; observation=0 | implemented; focused proof pending |
| 3 | `Get-TargetHostDetails` | operator; saved profile; visualization paused | returns one fresh complete or partial host result without visualizer scheduling | one audited invocation/outcome; encrypted observation=0 | implemented; focused proof pending |
| 4 | `Get-TargetProcessStartEvents` | operator; saved profile; mission paused or active | performs one bounded 4688 read, returns complete/partial/unavailable evidence, and advances only its process cursor | normalized schema-valid events encrypted atomically with cursor; pending when paused | implemented; focused proof pending |
| 5 | `Get-TargetProcessEndEvents` | operator; saved profile; mission paused or active | performs one bounded 4689 read, returns canonical termination evidence without inferred outcome or identity, and advances only its end cursor | normalized schema-valid events encrypted atomically with cursor; pending when paused | implemented; focused proof pending |
| 6 | `Get-TargetAuthenticationEvents` | operator; saved profile; mission paused or active | performs one bounded Security-log read for 4624/4625/4634/4647/4648/4672 without deliberately causing a failure | normalized schema-valid events encrypted atomically with independent cursor; pending when paused | implemented; focused proof pending |
| 7 | `Get-TargetProcessAccessToken` | operator; saved profile; exact PID or process basename | returns the selected process token or a truthful unavailable result without wildcard selection | immutable encrypted event stored before delivery; no cursor mutation | implemented; focused proof pending |
| 8 | `Get-TargetUserEffectiveRights` | operator; saved profile; optional identity | defaults to target username and returns complete/partial/failed rights evidence | immutable encrypted event stored before delivery; no cursor mutation | implemented; focused proof pending |
| 9 | `Test-HHTarget` | operator; saved profile | real identity probe succeeds without a credential prompt or profile mutation | one audited invocation/outcome; target generation unchanged | verified |
| 10 | `Invoke-HHCommand` | operator; saved profile | exact remote value and streams return once without a credential prompt | batch/invocation/operation/event/outcome/output/audit deltas; authenticated artifact | verified |
| 11 | `Get-HHAuditRecord` | operator; completed command | fresh process decrypts exact command/reason/case | read-only; counts and chain unchanged | verified |
| 12 | `Get-HHAuditOutput` | operator; completed artifact | fresh process returns exact ordered output/streams | read-only; artifact and chain unchanged | verified |
| 13 | `Enable-HHSshKeyAuthentication` | operator; encrypted-password profile | uses the stored credential without prompting, installs/proves key, then atomically deletes the password envelope | authentication Password to PublicKey; credential removed; generation/mutation +1; successful audited phases | verified |
| 14 | `Set-HHWindowsProcessAuditPolicy` | operator; managed target | Linux: finite audited unsupported failure. Windows: creation and termination policy mutate/verify/restore succeeds | one intent and terminal outcome; no retry; Windows receipt proves restoration | Linux verified; current Windows release proof pending |
| 15 | `Set-HHEscalationPreference` | operator; initialized store | persists `WindowsTokenPrivilege` | configuration generation/mutation +1 | verified |
| 16 | `Get-HHEscalationPreference` | operator; persisted preference | fresh process returns persisted method | read-only; configuration state unchanged | verified |
| 17 | `Remove-HHTarget` | operator; saved profile | atomically removes target and any stored credential while retaining audit history | profiles=0; credentials=0; target generation/mutation +1; audit remains queryable | verified |

## Boundary and negative coverage

- The eleven host-facing cmdlets are `Set-HHTarget`, `Test-HHTarget`,
  `Invoke-HHCommand`, `Enable-HHSshKeyAuthentication`,
  `Set-HHWindowsProcessAuditPolicy`, `Get-TargetHostDetails`,
  `Get-TargetProcessStartEvents`, `Get-TargetProcessEndEvents`, `Get-TargetAuthenticationEvents`,
  `Get-TargetProcessAccessToken`, and `Get-TargetUserEffectiveRights`. Each delegates exactly once to
  `Invoke-HHManagedHostOperation` with its semantic operation label.
- The other six framework cmdlets contain no managed-host network call.
- Invalid input fails before intent/network. Armed uncertain work becomes
  `Unknown` and is never automatically retried.
- Existing WinRM or WindowsPowerShell51 rows may be inspected and removed but
  dispatch fails with a stable unsupported error.
- `-WhatIf`, broad parameter combinations, capacity stress, scans, coverage,
  builds and compatibility matrices are not separate user journeys. Focused
  unit/integration tests cover material branches; the exact-SHA release gate
  owns coverage, integration, build, and security checks.
- The macOS client may execute Docker and open the loopback browser URL only. It contains no SSH,
  audit, persistence, or managed-host cmdlet implementation. Generated declarations are
  validated as parameter metadata before loading.
- Secure prompts originate locally. Password bytes use redirected stdin and a
  token-bound controller-loopback broker, are cached only for one command's
  fixed SSH phases, and are cleared/discarded afterward.
- First-use trust uses a distinct bounded yes/no protocol frame. Decline writes
  no known-host entry, requests no password, and creates no target profile.
  Matching pinned keys do not prompt; changed keys fail before authentication.

## Receipt contract

The local result is terminal pass/fail and includes exact expected and
observed seventeen names, per-step outcome/duration/DB deltas, SQLite
`integrity_check`, schema version, package/source/image identity, and Windows
qualification state. There are no retries, shards, nested schedulers, or
promotion of stale `latest` evidence.
