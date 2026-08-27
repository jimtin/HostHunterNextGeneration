# First-contact target implementation ledger

## Confirmed behavior

`Set-HHTarget -HostName <host> -UserName <user>` discovers the SSH server's
public host key, automatically pins and announces the selected fingerprint
before requesting a password, authenticates through the managed-host engine,
derives the saved target name from the remote PowerShell identity, and adds the
validated target without removing existing targets.

An explicit `-Name` overrides the discovered computer name. An explicit
`-HostKeyFingerprint` is the noninteractive/out-of-band trust path. Passwords
remain command-scoped secure prompts and are never accepted as parameters.

## Acceptance and test ledger

| Requirement | Production change | Focused evidence | Status |
| --- | --- | --- | --- |
| Host name and user name are the only normal inputs | scalar `Set-HHTarget` property parameter set | public cmdlet metadata/unit tests | verified |
| First-use key is discovered, pinned and announced before credentials | deterministic trust discovery and host-visible information frame | SSH trust and native protocol tests | verified |
| A saved key is reused; a changed key fails before credentials | pinned known-host comparison | SSH trust and native-client tests | verified |
| Name defaults to authenticated remote computer name | identity-result projection before persistence | engine and native-client tests | verified |
| Existing targets remain active | repository commit is always additive | public cmdlet and SQLite journey tests | verified |
| Explicit name and fingerprint remain available | optional scalar overrides | unit and 11-cmdlet journey | verified |
| Managed-host engine remains the sole host gateway | no new client-side SSH path | static boundary test | verified |
| SQLite, audit, encryption, anchors and recovery remain intact | existing persistence path and schema | focused cmdlet journey | verified |
| Connection failures are actionable | host/port/service/firewall guidance; protocol unwraps internal `EndInvoke` failures | SSH trust and protocol tests | verified |
| Mac bridge follows checked-out source | profile imports the repository client rather than a stale copied implementation | fresh installed-profile 11-cmdlet macOS journey | verified |

## User-action coverage

| User action | Surface | State | Expected behavior | Service-journey evidence | Unit/integration evidence | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Add with host and user | native PowerShell | no saved key | trust, credential, identity, additive save | native client and 11-cmdlet journey | public/engine tests | covered |
| Onboard first SSH identity | native PowerShell | discovered new key | pin exact key, announce its fingerprint, then permit authentication | native client journey | trust/protocol tests | covered |
| Connect again | native PowerShell | matching pinned key | no trust prompt | SSH fixture journey | trust tests | covered |
| Connect after key changes | native PowerShell | mismatched pinned key | fail before credential request | native fixture key-rotation journey | trust/transport tests | covered |
| Supply explicit name/fingerprint | native PowerShell | automation/out-of-band verification | require the discovered key to match and preserve the override | 11-cmdlet journey | public/engine tests | covered |

## Parallel work

No parallel workers are used. The public parameter contract, native interaction
protocol, managed-host transaction and audit ordering are one tightly coupled
security boundary with overlapping files.
