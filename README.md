# HostHunterNextGeneration

HostHunterNextGeneration is a container-first PowerShell 7 module for
accountable remote PowerShell execution. It saves one to eight endpoint
profiles, verifies the requested PowerShell runtime before use, records intent
before network dispatch, and retains the complete command and all PowerShell
streams as protected audit evidence. Its private Part 1 pipeline also
normalizes Windows Process Start evidence to ECS 9.5 without exporting an
incomplete acquisition interface.

## First-release runtime contract

The controller requires a security-patched PowerShell release: 7.4.19 or
newer in the 7.4 servicing line, 7.5.10 or newer in the 7.5 servicing line,
7.6.5 or newer in the 7.6 servicing line, or a later supported release. SSH
operations also require OpenSSH 8.4 or newer so the managed known-hosts path
can be passed without argument ambiguity. SSH is the only qualified
first-release transport.

| Requested runtime | SSH execution path | Availability |
|---|---|---|
| `PowerShell7` | Directly in the authenticated PowerShell 7 SSH runspace | Default; container/direct path qualified |
| `WindowsPowerShell51` | PowerShell 7 SSH runspace to a local `-UseWindowsPowerShell` compatibility session | Explicit Windows-target choice; implemented; release qualification pending |
| Any runtime over WinRM | No dispatch | Deferred; rejected fail-closed |

HostHunter does not silently change runtime, transport, authentication, trust,
or command text. A missing or mismatched requested runtime fails that target,
and an uncertain dispatched command is never retried automatically.

- [Confirmed dual-runtime release plan](docs/planning/dual-runtime-winrm-release-plan.md)
- [Confirmed shared understanding](docs/planning/shared-understanding-contract.md)
- [Confirmed repository testing design](docs/testing/repo-testing-design.md)
- [Confirmed amended SQLite persistence plan](docs/planning/sqlite-persistence-plan.md)
- [Implementation and evidence ledger](docs/planning/implementation-ledger.md)
- [Threat model](HostHunterNextGeneration-threat-model.md)

## Public commands

The module exports exactly eleven commands:

- `Set-HHTarget`
- `Get-HHTarget`
- `Test-HHTarget`
- `Remove-HHTarget`
- `Invoke-HHCommand`
- `Enable-HHSshKeyAuthentication`
- `Get-HHAuditRecord`
- `Get-HHAuditOutput`
- `Get-HHEscalationPreference`
- `Set-HHEscalationPreference`
- `Set-HHWindowsProcessAuditPolicy`

## Docker quick start

Docker Compose is the canonical runtime from `0.3.0-preview1` onward:

```bash
export HH_RUNTIME_PROJECT=hosthunter-local
./scripts/runtime/hosthunter.sh start
./scripts/runtime/hosthunter.sh doctor
./scripts/runtime/hosthunter.sh shell
```

The runtime creates six external, project-labelled volumes: data, secrets,
anchors, SSH state, evidence, and the private parser socket. It never migrates
or deletes native macOS state automatically. The controller runs as UID/GID
`10001:10001` with a read-only root filesystem, no Linux capabilities, no
Docker socket, no Docker logging, and explicit CPU, memory, PID, and temporary
storage bounds. The EVTX parser is a separate networkless container with no
database, key, anchor, or SSH mounts.

The unattended `DockerVolume` provider keeps core and Forensics keys separate
from their external anchors. Files are owner-only and bound to the provider,
domain, version, and canonical data root. It replaces any macOS Keychain or
Windows credential-store requirement inside Docker. It does not protect
against a trusted Docker administrator who can read every mounted volume or
coordinate a whole-environment rollback.

Stopping preserves state. Permanent deletion is deliberately separate:

```bash
./scripts/runtime/hosthunter.sh stop
./scripts/runtime/hosthunter.sh destroy \
  --confirm-project "$HH_RUNTIME_PROJECT" \
  --destroy-volumes
```

Docker has no atomic multi-volume deletion API. HostHunter preflights all six
volumes and reports exact survivors if deletion is only partly completed. Back
up the six volumes as one consistency set. Losing the secret volume makes the
encrypted databases unreadable; restoring data without its matching key and
anchor volumes fails closed.

## SSH quick start

Import the module and explicitly pin the endpoint's complete OpenSSH SHA-256
host-key fingerprint. Password authentication uses the native interactive SSH
prompt; HostHunter never accepts or stores a password parameter.

```powershell
# The canonical container shell loads the packaged module.
# For optional native use:
# Import-Module ./src/HostHunterNextGeneration/HostHunterNextGeneration.psd1

Set-HHTarget `
    -Name server01-pwsh `
    -HostName server01.example.test `
    -UserName operator `
    -HostKeyFingerprint 'SHA256:replace-with-the-complete-fingerprint'

Invoke-HHCommand `
    -Target server01-pwsh `
    -Command 'Get-Process | Select-Object -First 5' `
    -Reason 'Investigate service load' `
    -CaseId 'INC-1234'
```

Native macOS use remains an optional compatibility mode. Its default data root is
`~/Library/Application Support/HostHunterNextGeneration`. HostHunter binds its
managed `known_hosts` path to each native SSH session without embedding that
space-containing path in the SSH option argument. Custom data roots containing
spaces are supported as well. Distinct data roots have independent databases,
Keychain identities, and audit histories; HostHunter never merges or deletes
them automatically.

Omitting `-PowerShellRuntime` selects `PowerShell7`. `Reason` is optional human
context. `CaseId` is an optional correlation value, such as an incident, change,
or ticket ID. HostHunter generates its own batch, invocation, and event IDs.

### Explicit Windows PowerShell 5.1 profile

A Windows endpoint can have separate named profiles for both runtimes. Both use
the same pinned SSH endpoint, but runtime is part of profile identity.

```powershell
Set-HHTarget `
    -Name server01-windows-powershell `
    -HostName server01.example.test `
    -UserName operator `
    -HostKeyFingerprint 'SHA256:replace-with-the-complete-fingerprint' `
    -PowerShellRuntime WindowsPowerShell51 `
    -Add

Invoke-HHCommand `
    -Target server01-windows-powershell `
    -Command '$PSVersionTable | Format-List'
```

The 5.1 profile is saved only after the outer SSH session proves PowerShell 7
and the compatibility runspace proves `Desktop` edition version 5.1. There is
no fallback to direct PowerShell 7 if that proof fails.

Use `Get-HHTarget` to inspect the requested runtime and last validated edition,
version, and execution mode. `Test-HHTarget` repeats runtime validation without
changing the saved profile.

## Windows process auditing and privilege activation

Saved active targets are reused automatically, so `-Target` is needed only to
select a subset. The following enables successful Process Creation auditing
through the native Windows audit-policy APIs, without invoking `auditpol`:

```powershell
Set-HHWindowsProcessAuditPolicy `
    -State Enabled `
    -Escalate
```

`-Subcategory ProcessTermination` is optional. `-Escalate` uses the explicit or
saved escalation method; the initial `WindowsTokenPrivilege` method activates
`SeSecurityPrivilege` only when it already exists in the remote process token.
It does not bypass UAC or add missing administrative rights, and HostHunter
restores the previous privilege state after the operation.

Command-line inclusion is an independent option:

```powershell
Set-HHWindowsProcessAuditPolicy `
    -State Enabled `
    -CommandLineLogging Enabled `
    -Escalate
```

HostHunter warns and continues because event 4688 will contain process
arguments in plaintext, which may expose passwords, tokens, or private data.
Use `Disabled`, `NotConfigured`, or the default `Unchanged` explicitly. Direct
policy changes describe the effective state at verification time; Group Policy
or MDM may subsequently replace it.

## Passwordless SSH transition

After a successful interactive password connection, install and independently
prove a dedicated Ed25519 key with:

```powershell
Enable-HHSshKeyAuthentication -Name server01-pwsh
```

The dedicated key is created interactively so the operator can set a non-empty
passphrase. Load it into a user-controlled `ssh-agent` for repeated commands;
HostHunter never stores the passphrase or accepts it through command arguments,
environment variables, or plaintext files.

The profile changes to public-key authentication only after a separate key-only
PowerShell identity probe succeeds. A failed proof removes only the exact
authorized-key entry installed by that attempt. Server-wide password login is
left enabled as a recovery path.

## Accountability boundary

Only remote operations invoked through HostHunter are logged. Before network
dispatch, the current implementation durably records an intent containing the
complete command text, requested runtime, and optional context. The reviewed
SQLite design additionally commits and anchors an exact operation arm before
each actual remote phase. Terminal records are HMAC chained, and complete
Output, Warning, Error, Verbose, Debug, and Information stream evidence is
compressed and encrypted with AES-256-GCM.

Each target invocation has an independent 100 MiB plaintext output limit.
Exceeding it stops the pipeline and records an explicit failure. If connectivity
is lost after dispatch and completion cannot be proven, the terminal audit
outcome is `Unknown`.

The optional native macOS contract stores the audit master key in the user's
login Keychain under a data-root-specific account. A bounded child process uses native Security
framework byte APIs; the raw 32-byte key is passed only through anonymous pipes,
never command arguments, environment variables, or a plaintext key file. A
legacy plaintext `audit.key` blocks remote activity until it is deliberately
migrated. The canonical Docker runtime instead uses independently mounted
secret and anchor volumes. The ledger is tamper-evident; it is not tamper-proof
against an administrator who controls the evidence, keys, and anchors together.

## Public repository policy

When publication is complete, anyone may read or fork the repository, but only
`jimtin` may push, merge, administer it, or install repository-scoped
integrations. External pull requests do not grant write access, and their code
must never be automatically executed on the maintainer laptop. GitHub Actions
must remain disabled; every external change requires manual source review
before any trusted local command is run. These GitHub settings remain subject
to a live post-publication re-read before release completion is claimed.

Do not commit real endpoint names, usernames, IP addresses, fingerprints,
credentials, private keys, target stores, ledgers, or `.hhout` evidence.

## Local validation

All canonical proof runs in local containers. The full command builds the
production controller and isolated parser, runs every one of the eleven public
cmdlets through the package-backed user journey, verifies real Sysmon 1 and
Security 4688 Process Start fixtures, checks restart persistence, and scans the
resulting production images:

```bash
./scripts/verify-local.sh
```

Focused implementation evidence is not release evidence. The exact-candidate
gate reruns static, security, filesystem/image, unit coverage, integration,
SQLite fault, runtime, package, and user-journey proof from one clean checkout.
Its compact successful proof bundle and coverage working set are each capped at
20 MiB; scanner caches, raw branch-hit events, copied checkouts, and superseded
candidate trees are never retained as proof.

The release is complete only after the same exact runtime image is qualified
against the Windows target for PowerShell 7, Windows PowerShell 5.1, all six
streams, process-audit policy and command-line behavior, privilege restoration,
SSH-key transition, password recovery, and exact cleanup.

GitHub does not rerun the suite. The repository uses a gate-owned model: commit
and push hooks run their declared local lanes. The HostHunter-specific
standalone laptop gate and clean-checkout candidate runner own full exact-SHA
proof before every push to `main`.
