# HostHunterNextGeneration

HostHunter is a container-first PowerShell module for operating managed Linux
and Windows hosts through PowerShell 7 over OpenSSH. It exposes eleven cmdlets
and records every managed-host operation in authenticated SQLite with encrypted,
tamper-evident output artifacts.

## Supported boundary

- Controller: Linux container running PowerShell 7.
- Managed hosts: Linux or Windows with a PowerShell 7 SSH endpoint.
- Transport: SSH only.
- Persistence: SQLite plus separate secret, anchor, SSH-key, and evidence roots.
- External gateway: the private `Invoke-HHManagedHostOperation` engine.

WinRM, Windows PowerShell 5.1, native desktop controllers, generic runtime
shells, and the former Forensics/parser/API subsystem are intentionally absent.

## Public cmdlets

```text
Get-HHTarget
Set-HHTarget
Test-HHTarget
Remove-HHTarget
Invoke-HHCommand
Enable-HHSshKeyAuthentication
Get-HHAuditRecord
Get-HHAuditOutput
Set-HHWindowsProcessAuditPolicy
Set-HHEscalationPreference
Get-HHEscalationPreference
```

`Get-HHTargets` is an alias for `Get-HHTarget`. When no matching targets are
saved, either name displays `No currently set` and returns no pipeline objects.

Five cmdlets contact managed hosts: `Set-HHTarget`, `Test-HHTarget`,
`Invoke-HHCommand`, `Enable-HHSshKeyAuthentication`, and
`Set-HHWindowsProcessAuditPolicy`. They all delegate once to the same private
engine, which owns intent persistence, dispatch arming, SSH phases, stream
capture, encrypted evidence, terminal audit, cleanup, and uncertain-outcome
handling. The other six cmdlets operate only on local authenticated state.

`Invoke-HHCommand` accepts arbitrary remote PowerShell. HostHunter audits the
originating request and result; it cannot constrain network activity performed
by that user-supplied command after it begins on the managed host.

## Use HostHunter from macOS PowerShell

Install the current-user client once from the repository:

```powershell
pwsh -NoProfile -File ./scripts/client/Install-HHClient.ps1
```

Open PowerShell normally. The profile import launches Docker Desktop once when
its engine is stopped, starts the controller when needed, reuses an unchanged
controller, and synchronizes the eleven exported commands from the packaged
module:

```powershell
Set-HHTarget -Name server01 -HostName 192.0.2.10 -UserName analyst
Test-HHTarget -Name server01
Invoke-HHCommand -Target server01 -Command 'Get-Process'
Get-HHAuditRecord -TargetName server01
```

These are normal PowerShell functions: parameter discovery, pipelines, objects,
warnings, errors, verbose/debug/information messages, and progress cross one
generic versioned bridge. New exported cmdlets synchronize automatically; the
macOS client contains no per-cmdlet business logic. Passwords are prompted with
`Read-Host -AsSecureString` and travel only through the command's standard-input
session and an in-memory controller-local broker. They are never command-line
arguments, environment values, persistent files, or logs.

HostHunter never pulls Git changes automatically. When build-relevant checked-out
source changes, the next import rebuilds the controller once.

## Runtime administration

The native client owns normal startup. The lower-level runtime commands remain
available for diagnosis and explicit state management:

```sh
./scripts/runtime/hosthunter.sh doctor
./scripts/runtime/hosthunter.sh stop
```

Runtime state remains separated across five trust-domain volumes: data, secrets,
anchors, SSH keys, and evidence. Destroying runtime state is explicit:

```sh
./scripts/runtime/hosthunter.sh destroy
```

## Focused cmdlet verification

Run the only development acceptance journey:

```sh
./scripts/verify-cmdlets.sh
```

It builds a production-derived verifier and a disposable SSH fixture, calls all
eleven cmdlets in one ordered stateful journey, and validates read-only SQLite
snapshots and deltas. It has one timeout owner, no shards, and no retries.
Results are written below `.artifacts/cmdlets/<source-sha>/`.

The Linux fixture can prove only a finite, audited unsupported outcome for
`Set-HHWindowsProcessAuditPolicy`. A release that claims positive Windows
support must also run the single live-Windows PowerShell 7 qualification against
the exact controller image and restore the process-audit setting.

## Release proof

Coverage, critical integration, security scans, image scanning, and production
build checks are intentionally excluded from the cmdlet verdict. They run once
for an exact committed SHA:

```sh
./scripts/release/verify-candidate.sh <40-character-sha>
```

The gate atomically consumes the SHA before work begins. It writes independent
cmdlet and heavy-proof receipts plus one immutable terminal receipt. A failed,
blocked, interrupted, or passed SHA is never executed again; fixes require a new
commit SHA. The read-only aggregator is:

```sh
./scripts/release/aggregate-candidate.sh <40-character-sha>
```

See `docs/planning/hosthunter-simplification-plan.md` and
`docs/testing/e2e-workflow-inventory.md` for the accepted behavior contract.
