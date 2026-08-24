# Security Policy

## Supported version

HostHunterNextGeneration is currently a `0.1.0-preview1` project. Security fixes
are applied to the latest revision only until a stable release policy exists.

## Reporting a vulnerability

Until publication and repository settings are verified, contact the repository
owner through an existing private channel. After GitHub private vulnerability
reporting is enabled and confirmed, use that flow. Do not open a public issue
containing credentials, target details, commands, audit evidence, host-key
material, or exploit instructions that would expose a real environment.

When reporting, include the affected revision, operating system, PowerShell
version, transport, expected result, and a minimal redacted reproduction. Never
attach a real `audit.key`, private key, `targets.json`, `known_hosts`, ledger,
`.hhout` artifact, password, token, or unredacted production output.

## Public-repository execution policy

The publication policy prohibits repository code from running in GitHub
Actions. The public repository must grant push, merge, administration, and
repository-scoped integration authority only to `jimtin`; no collaborators or
teams receive write authority for the first release. Publication and the live
settings re-read remain pending.

Public visibility permits reading, forks, and pull requests; none of those grant
write access or trusted execution. External contributions must receive a manual
source review before the owner runs any script, hook, build, test, or validation
lane. Publishing a pull request is not authorization to run untrusted code with
host, Docker, Keychain, SSH-agent, or remote-endpoint authority.

## First-release remoting boundary

SSH is the only qualified transport. PowerShell 7 is the default requested
runtime. Windows PowerShell 5.1 is an explicit Windows-target choice reached
through a PowerShell 7 SSH session and a local compatibility runspace. Runtime
mismatch or unavailability fails closed without falling back to another
runtime. The compatibility path is implemented, but positive live
Windows PowerShell 5.1 qualification against an exact commit remains pending.

Dedicated SSH keys are passphrase-protected and may be loaded into an
operator-controlled `ssh-agent`. HostHunter does not persist or noninteractively
inject endpoint passwords or private-key passphrases. Native release
qualification removes its exact agent identity, stops its run-scoped agent,
and verifies its disposable Keychain items are absent before claiming cleanup.

WinRM is intentionally deferred until a controlled lab can qualify its
authentication, certificate, trust, and controller boundaries. A WinRM target
must be rejected without dispatch in the first release. Do not weaken that
guard or infer WinRM support from mocks.

## Security boundary

HostHunter logs only operations it originates. Remote output can itself contain
secrets and must be handled as sensitive. The local ledger is tamper-evident,
not tamper-proof against an administrator who controls both the evidence and
the controller's credential material. On macOS, the audit master key belongs in
the user's login Keychain; a legacy plaintext `audit.key` blocks remote activity
until a deliberate migration. See the repository threat model for the complete
boundary and current mitigations.
