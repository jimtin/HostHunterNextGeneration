# HostHunter Cmdlet Action Matrix

## Scope

This is the complete user-action inventory. HostHunter is a PowerShell CLI, so
the package-backed service journey is the Playwright-equivalent layer. Exactly
eleven ordered steps run against one fresh authenticated SQLite store and one
SSH target. The local journey uses Linux; the same manifest is completed by a
separate live Windows PS7/OpenSSH qualification for Windows-positive behavior.

Direct SQL connections are read-only (`PRAGMA query_only=ON`). Product cmdlets
perform every write. Each step records duration, public result, expected
outcome and before/after database snapshot.

| Step | User action | Role/state | Expected public behavior | Required database evidence | Status |
| ---: | --- | --- | --- | --- | --- |
| 1 | `Get-HHTarget` | operator; empty store | returns no targets without creating state | no DB or row/generation delta | pending |
| 2 | `Set-HHTarget` | operator; password SSH fixture | validates identity and persists one PS7/SSH profile | DB created; profile=1; target generation/mutation +1; successful validation audit | pending |
| 3 | `Test-HHTarget` | operator; saved profile | real identity probe succeeds without profile mutation | one audited invocation/outcome; target generation unchanged | pending |
| 4 | `Invoke-HHCommand` | operator; saved profile | exact remote value and streams return once | batch/invocation/operation/event/outcome/output/audit deltas; authenticated artifact | pending |
| 5 | `Get-HHAuditRecord` | operator; completed command | fresh process decrypts exact command/reason/case | read-only; counts and chain unchanged | pending |
| 6 | `Get-HHAuditOutput` | operator; completed artifact | fresh process returns exact ordered output/streams | read-only; artifact and chain unchanged | pending |
| 7 | `Enable-HHSshKeyAuthentication` | operator; password profile | installs key, proves key-only access, then commits profile | authentication Password to PublicKey; generation/mutation +1; successful audited phases | pending |
| 8 | `Set-HHWindowsProcessAuditPolicy` | operator; managed target | Linux: finite audited unsupported failure. Windows: policy mutate/verify/restore succeeds | one intent and terminal outcome; no retry; Windows receipt proves restoration | pending |
| 9 | `Set-HHEscalationPreference` | operator; initialized store | persists `WindowsTokenPrivilege` | configuration generation/mutation +1 | pending |
| 10 | `Get-HHEscalationPreference` | operator; persisted preference | fresh process returns persisted method | read-only; configuration state unchanged | pending |
| 11 | `Remove-HHTarget` | operator; key profile | atomically removes target and retains audit history | profiles=0; target generation/mutation +1; audit remains queryable | pending |

## Boundary and negative coverage

- The five host-facing cmdlets are `Set-HHTarget`, `Test-HHTarget`,
  `Invoke-HHCommand`, `Enable-HHSshKeyAuthentication`, and
  `Set-HHWindowsProcessAuditPolicy`. Each delegates exactly once to
  `Invoke-HHManagedHostOperation` with its semantic operation label.
- The other six cmdlets contain no managed-host network call.
- Invalid input fails before intent/network. Armed uncertain work becomes
  `Unknown` and is never automatically retried.
- Existing WinRM or WindowsPowerShell51 rows may be inspected and removed but
  dispatch fails with a stable unsupported error.
- `-WhatIf`, broad parameter combinations, capacity stress, scans, coverage,
  builds and compatibility matrices are not separate user journeys. Focused
  unit/integration tests cover material branches; the exact-SHA release gate
  owns coverage, integration, build, and security checks.

## Receipt contract

The local result is terminal pass/fail and includes exact expected and
observed eleven names, per-step outcome/duration/DB deltas, SQLite
`integrity_check`, schema version, package/source/image identity, and Windows
qualification state. There are no retries, shards, nested schedulers, or
promotion of stale `latest` evidence.
