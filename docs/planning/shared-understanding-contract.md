# Shared Understanding Contract

## Status

AMENDED SQLITE CONTRACT CONFIRMED 2026-08-24; IMPLEMENTATION IN PROGRESS

## Goal

Build a publicly released, MIT-licensed PowerShell 7 module named
`HostHunterNextGeneration` that manages remote PowerShell targets and executes
accountable commands against them.

## Functional scope

- Provide `Set-HHTarget`, `Get-HHTarget`, `Test-HHTarget`, and
  `Remove-HHTarget` for one or many saved and active targets.
- Provide `Get-HHAuditRecord` for bounded authenticated history lookup and
  `Get-HHAuditOutput` for verified single-invocation stream retrieval.
- Require a working PowerShell endpoint rather than accepting ping or an open
  port as proof of accessibility.
- Use PowerShell-over-SSH on the explicitly qualified `osx-arm64`,
  `linux-arm64`, `linux-x64`, and `win-x64` PowerShell 7 controllers. Other
  controller RIDs fail closed until separately qualified.
- Reject WinRM in the first release; implementation and qualification are
  deferred until a separate controlled Windows lab exists.
- Default targets to PowerShell 7 and allow an explicit
  `WindowsPowerShell51` runtime on Windows SSH targets through a local
  `New-PSSession -UseWindowsPowerShell` bridge.
- Begin with interactive SSH password authentication.
- Provide an explicit, audited password-to-public-key bootstrap flow.
- Route all HostHunter-originated remote execution through
  `Invoke-HHCommand`.
- Support up to eight concurrent target executions initially.
- Keep `Reason` and `CaseId` optional; generate operation, batch, and
  per-target invocation identifiers automatically.

## Accountability boundary

HostHunter records every remote operation it originates, including target
validation, identity probes, and key-enrolment commands. It does not claim to
capture direct `ssh`, `Invoke-Command`, or other activity outside HostHunter.

Before network activity, HostHunter durably records an immutable intent. Before
each actual remote phase it also commits and anchors a unique dispatch-arm event
for the exact declared script and arguments. If either barrier fails, nothing
is sent. Each target has an independent outcome connected to a shared batch
identifier. Uncertain commands are marked `Unknown` and are never retried
automatically.

## Audit and output

- Retain complete command text and all non-secret arguments.
- Never persist authentication secrets in target profiles, command records, or
  plaintext files.
- Capture complete PowerShell output, error, warning, verbose, debug, and
  information streams, preserving order and timing where observable.
- Store output in invocation-bound, chunked, encrypted, compressed
  per-invocation `.hhout` v2 artifacts whose hashes are committed to an
  HMAC-chained, tamper-evident ledger.
- Limit output to 100 MiB per target invocation by default. Stop the remote
  pipeline and record `OutputLimitExceeded` rather than executing without
  complete capture.
- Perform no automatic deletion in the first release. Export and pruning are
  deferred; if later added, they must be explicit and audited.
- Treat output as sensitive because a remote command can print a secret even
  when authentication credentials are correctly excluded.

## Local persistence

The confirmed detailed persistence contract is
`docs/planning/sqlite-persistence-plan.md`.

- SQLite is the sole authoritative structured store after the unreleased
  cutover. JSON and JSONL are neither imported nor dual-written.
- Target profiles remain plaintext inside owner-private storage; command text,
  reason/case values, exact remote operations, detailed identities, and audit
  payloads are encrypted before database binding.
- Complete ordered stream output remains in encrypted `.hhout` artifacts whose
  metadata is authenticated by the database audit chain.
- The macOS Keychain holds the audit master key and a separate monotonic anchor
  covering the audit head and authenticated target-state generation.
- Linux and Windows use owner-private key/anchor files in the data root. They
  detect database-only divergence but do not claim macOS-equivalent whole-root
  rollback detection.
- `Get-HHTarget` preserves keyless, read-only plaintext inspection with an
  unverified-state warning. The returned objects are never trusted for a
  mutation or dispatch; all authoritative mutation and remote-capable work
  requires the key and verified anchor.
- A separate cross-process operation lock prevents one HostHunter process from
  recovering another process's live remote batch; one owner may still fan out
  to eight targets.
- Legacy target or ledger files fail closed with no network activity and are
  never overwritten or deleted automatically.
- Product state belongs under the normal OS data root or `.hosthunter/` when a
  repository-local root is explicitly selected. Crash and recovery remnants
  stay inside that ignored root; validation receipts remain under
  `.artifacts/`.

## Target and transport rules

- Persist endpoint metadata and credential references only.
- Validate authenticated server identity with strict SSH host-key validation.
- Never use `TrustedHosts=*`, certificate-validation bypasses, or silent
  fallback after authentication or trust failure.
- Save a proposed multi-target set atomically: if one target fails validation,
  save none of the proposed changes.
- Replace the active target set by default; an explicit `-Add` extends it.
- Treat multi-target command execution as independent per-target operations,
  not a transaction.

## SSH key bootstrap

An explicit `Enable-HHSshKeyAuthentication` operation uses an authenticated
password session to install a public key, opens a separate key-only session,
and changes the target profile only after the new session passes the normal
identity probe. On failure it removes only the newly added HostHunter key entry
and retains password mode.

The default is one dedicated, passphrase-protected HostHunter key per local
operator and controller, loaded through `ssh-agent`. Existing keys can be
selected explicitly. HostHunter does not disable server-wide password
authentication. Key removal and rotation operate by exact fingerprint and do
not rewrite unrelated authorized keys.

## Security boundary

The local ledger is tamper-evident, not tamper-proof against an administrator
who controls both the ledger and its keys. The storage interface must allow a
future independently controlled append-only collector, but that collector is
not part of the first release.

## Verification and release constraints

- All canonical validation executes locally in containers.
- Unit coverage is at least 90% for statements, branches, functions, and lines;
  materially changed logic targets at least 95%.
- Critical paths have integration coverage.
- Every public CLI action has black-box service-journey coverage as the
  Playwright-equivalent layer for this non-browser module.
- Database proof includes clean construction from committed migrations,
  multi-process CAS and writer/operation-lock serialization,
  corruption/rollback and crash recovery, native-provider packaging, and both
  audit-query journeys.
- GitHub never reruns tests. Developer hooks are slim; the standalone laptop
  gate owns full exact-candidate-SHA proof before merge or release.
- Every push requires the repo secret-scan lane and an explicit threat-model
  review of the changed scope.
- WinRM is not claimed as qualified until a controlled Windows controller has
  proved it against a real Windows target.
- WinRM implementation and qualification are deferred until the user has a
  separate controlled Windows lab. First-release WinRM paths remain fail closed.
- When published, the public GitHub repository must grant write and
  administrative authority only to `jimtin`; external contributions are
  manual-review-only and never execute automatically on the maintainer laptop.
  Publication and the live settings re-read remain separate release work.

## Non-goals for the first release

- Endpoint-wide capture of commands executed outside HostHunter.
- Native Bash, Zsh, CMD, or other non-PowerShell remote command modes.
- Server-wide disabling of SSH password authentication.
- Unattended password injection through `sshpass`, `expect`, environment
  variables, command arguments, or plaintext temporary files.
- A graphical interface or web application.
- A centrally operated audit collector.
