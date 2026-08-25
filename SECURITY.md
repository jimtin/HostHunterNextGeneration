# Security Policy

## Supported version

HostHunterNextGeneration is currently a `0.3.0-preview1` project. Security fixes
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

SSH authority requires a security-patched controller release: PowerShell
7.4.19+, 7.5.10+, 7.6.5+, or a later supported branch. OpenSSH must support
environment expansion for `UserKnownHostsFile` (OpenSSH 8.4 or newer).
HostHunter passes only a unique per-session environment reference through the
SSH option boundary, restores that process environment in `finally`, disables
global known-hosts fallback and host-key updates, and continues to validate the
canonical managed file and exact pinned fingerprint before connection. This is
required for macOS's space-containing default data root as well as adversarial
custom path names.

Dedicated SSH keys are passphrase-protected and may be loaded into an
operator-controlled `ssh-agent`. HostHunter does not persist or noninteractively
inject endpoint passwords or private-key passphrases. Release qualification
removes its exact agent identity, stops its run-scoped agent, and proves exact
remote and runtime-volume cleanup.

WinRM is intentionally deferred until a controlled lab can qualify its
authentication, certificate, trust, and controller boundaries. A WinRM target
must be rejected without dispatch in the first release. Do not weaken that
guard or infer WinRM support from mocks.

## Security boundary

HostHunter logs only operations it originates. Remote output can itself contain
secrets and must be handled as sensitive. Docker is the canonical runtime from
`0.3.0-preview1`: its non-root controller uses distinct external data, secret,
anchor, SSH, evidence, and parser-socket volumes, while the networkless parser
has no key, database, anchor, or SSH mount. Docker logging is disabled, no
service receives the Docker socket, and the parser never writes plaintext
JSONL evidence.

The unattended Docker-volume provider removes any Keychain or Windows
credential-store requirement but trusts the Docker administrator. An
administrator controlling the data, key, and anchor volumes together can read
keys or coordinate a whole-environment rollback. Backups and destruction must
therefore cover all exact project volumes as one lifecycle. Native macOS
Keychain support remains optional compatibility; a legacy plaintext `audit.key`
still blocks remote activity until deliberate migration. See the repository
threat models for the complete boundaries and mitigations.
