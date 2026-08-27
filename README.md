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
module. In an interactive terminal it finishes with a short radar-style
welcome animation. Set `HH_CLIENT_NO_ANIMATION=1` to suppress it; scripts,
redirected sessions, tests, and CI never animate or wait:

```powershell
Set-HHTarget -HostName BestLaptopEver -UserName RemoteAdmin
Get-HHTarget
Invoke-HHCommand -Target BESTLAPTOPEVER -Command 'Get-Process'
Get-HHAuditRecord -TargetName BESTLAPTOPEVER
```

You do not need to obtain a host key first. Windows OpenSSH creates the host
identity when its SSH service starts. On first contact HostHunter retrieves the
public key, deterministically selects a supported algorithm, pins it, and prints
`Accepting public key <algorithm> <SHA256 fingerprint>`. Choosing SSH authorizes
this first-use trust without a second prompt. A later key change stops before
credentials are sent. On an untrusted network, supply an independently verified
`-HostKeyFingerprint` so discovery must match it before authentication.

HostHunter next recommends installing a dedicated Ed25519 key. Press Enter to
accept the recommended choice. It uses the password once, independently proves
the key, then saves only the public-key profile. A definite key failure may
offer password fallback; an uncertain remote or commit outcome stops without a
retry or saved password.

If you explicitly choose `-Authentication Password`, or accept a definite
fallback, HostHunter displays the storage risks and requires a separate Yes
confirmation. It encrypts the password in SQLite using a key held in the
separate secrets volume. Later target tests, commands, Windows policy changes,
and key conversion authenticate invisibly. Proven key conversion and target
removal atomically delete the saved credential.

The saved target name defaults to the computer name returned by the
authenticated PowerShell identity probe. `-Name` remains an optional override,
and `-HostKeyFingerprint` remains available for independently verified or
noninteractive first contact. New targets are additive and never silently
deactivate existing targets.

These are normal PowerShell functions: parameter discovery, pipelines, objects,
warnings, errors, verbose/debug/information messages, and progress cross one
generic versioned bridge. New exported cmdlets synchronize automatically; the
macOS client contains no per-cmdlet business logic. Trust decisions use a
separate bounded yes/no frame. Passwords are prompted with
`Read-Host -AsSecureString` and travel only through the command's standard-input
session and an in-memory controller-local broker. They are never command-line
arguments, environment values, logs, or client output frames. Password mode
persists only an authenticated encrypted SQLite envelope; its decryption key
remains in the separate secrets volume.

HostHunter never pulls Git changes automatically. When build-relevant checked-out
source changes, the next import rebuilds the controller once. The profile loads
the client bridge directly from the configured repository on every new PowerShell
session, so it cannot keep using an older copied bridge after the source changes.

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
./scripts/runtime/hosthunter.sh destroy \
  --confirm-project hosthunter-next-generation-runtime --destroy-volumes
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
