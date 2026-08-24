# HostHunterNextGeneration

HostHunterNextGeneration is a PowerShell 7 module for accountable remote
PowerShell execution. It saves one to eight endpoint profiles, verifies the
requested PowerShell runtime before use, records intent before network dispatch,
and retains the complete command and all PowerShell streams as protected audit
evidence.

## First-release runtime contract

The controller requires PowerShell 7.4 or newer. SSH is the only qualified
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

The current pre-migration module exports exactly:

- `Set-HHTarget`
- `Get-HHTarget`
- `Test-HHTarget`
- `Remove-HHTarget`
- `Invoke-HHCommand`
- `Enable-HHSshKeyAuthentication`

The confirmed SQLite persistence plan adds `Get-HHAuditRecord` and
`Get-HHAuditOutput`. The cmdlets remain planned and test-mapped until their
implementation and package-backed requalification pass.

## SSH quick start

Import the module and explicitly pin the endpoint's complete OpenSSH SHA-256
host-key fingerprint. Password authentication uses the native interactive SSH
prompt; HostHunter never accepts or stores a password parameter.

```powershell
Import-Module ./src/HostHunterNextGeneration/HostHunterNextGeneration.psd1

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

The v1 macOS contract stores the audit master key in the user's login Keychain
under a data-root-specific account. A bounded child process uses native Security
framework byte APIs; the raw 32-byte key is passed only through anonymous pipes,
never command arguments, environment variables, or a plaintext key file. A
legacy plaintext `audit.key` blocks remote activity until it is deliberately
migrated. Other controller platforms use a restrictive per-user file fallback
until a platform credential-store design is qualified. The ledger is
tamper-evident; it is not tamper-proof against an administrator who controls
both the evidence and credential material.

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

All canonical proof runs in local containers:

```bash
./scripts/verify-local.sh
```

The current working-tree product proof passed on 2026-08-24: 544/544 unit
tests and 18/18 CLI E2E journeys passed, together with the nine-scenario SQLite
fault/recovery lane. Product coverage was 96.8122% statements (6894/7121),
90.048% branches (2253/2502), 96.1039% functions (222/231), and 96.8729%
lines (5700/5884). The exact-candidate gate will rerun static, security,
filesystem/image, integration, package, and build proof from a clean checkout.

That receipt proves the current working tree. It is not an exact-commit or live
Windows PowerShell 5.1 qualification receipt. Those checks, public repository
creation, and the live GitHub owner-only settings re-read remain pending.

GitHub does not rerun the suite. The repository uses a gate-owned model: commit
and push hooks run their declared local lanes. The HostHunter-specific
standalone laptop gate and clean-checkout candidate runner are implemented;
they own full exact-SHA proof before the first publication.
