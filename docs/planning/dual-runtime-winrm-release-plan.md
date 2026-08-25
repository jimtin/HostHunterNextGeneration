# Dual-Runtime SSH and Public Release Plan

## Status

**CONFIRMED 2026-08-24**

This remains the confirmed transport/runtime baseline. Its six-cmdlet and
file-persistence release statements are superseded by the subsequently
confirmed `docs/planning/sqlite-persistence-plan.md`. The SQLite plan expands
the target release contract to eleven cmdlets and must be implemented and
requalified before exact-commit, live Windows, or publication work resumes.

The user confirmed this contract after a live capability check of PowerShell 7
and Windows PowerShell 5.1. That diagnostic is not exact-candidate release
qualification. WinRM implementation and release claims are explicitly deferred
until a separate controlled Windows lab exists.

## Feature readiness

**IMPLEMENTED; WORKING-TREE CONTAINER GATE PASSED; LIVE RELEASE QUALIFICATION PENDING**

The implementation can use the existing native PowerShell-over-SSH path for
both runtimes without adding an unsupported macOS WSMan library or a Python
runtime dependency. A pre-candidate capability check proved the direct
PowerShell 7 path, the Windows PowerShell compatibility bridge, strict SSH host
identity, and ordered capture of Output, Warning, Verbose, Debug, Information,
and Error records. Exact-candidate release qualification remains pending.
The first macOS Keychain probe proved that the CLI's safe `-w` prompt cannot
consume redirected standard input. The replacement bounded child worker now
uses native Security-framework byte APIs, and its separate-process disposable
create/read/delete lifecycle passed without placing the key in arguments,
environment variables, or a plaintext key file.

The current 2026-08-25 readiness unit receipt is 647/647 with 95.3557%
statements (7761/8139), 90.0669% branches (2557/2839), 96.3504% functions
(264/274), and 95.3931% lines (6419/6729). The exact-candidate gate must still
reproduce the full static, security, integration, E2E, package, and image
program. This receipt is not an exact-commit or positive live Windows 5.1
proof.

## Summary

- Goal: publish `jimtin/HostHunterNextGeneration` as a public, MIT-licensed
  PowerShell module with accountable command execution against one to eight
  PowerShell targets.
- Controller: HostHunter requires PowerShell 7.4 or newer.
- Target runtimes: `PowerShell7` is the default; `WindowsPowerShell51` is an
  explicit per-target choice for Windows targets reached through SSH.
- Transport: SSH is the only qualified first-release transport. WinRM remains
  schema-compatible only where needed to fail closed and is not claimed as
  implemented or release-ready.
- Safety: there is no silent runtime, transport, authentication, trust, or
  command retry fallback.
- Publication: create a public GitHub repository where only `jimtin` has write
  or administrative authority. External contributions must never be executed
  automatically on the maintainer laptop. Live settings verification remains
  pending until publication.

## Confirmed decisions

- The designated Windows qualification environment retains PowerShell 7 and
  Windows PowerShell 5.1 side by side.
- SSH opens a PowerShell 7 session first. `PowerShell7` commands execute in
  that runspace.
- `WindowsPowerShell51` opens a local `New-PSSession -UseWindowsPowerShell`
  runspace inside the authenticated PowerShell 7 SSH session. The command is
  executed only after that runspace reports `Desktop` edition and version 5.1.
- HostHunter never rewrites candidate commands for runtime compatibility.
- A missing or mismatched requested runtime is a terminal failure for that
  target; HostHunter does not fall back to the other runtime.
- Complete command text and all six PowerShell streams remain retained.
  `Reason` and `CaseId` remain optional.
- The existing 100 MiB plaintext output limit applies independently to every
  target invocation, including bridged 5.1 invocations.
- macOS stores the audit master key in Keychain. Windows DPAPI storage is
  deferred with WinRM/controller qualification.
- An exact-candidate live password-to-Ed25519 transition is authorized.
  Password login remains enabled as a recovery path.
- The release publishes the complete public threat model. No real endpoint,
  hostname, username, fingerprint, credential, key, target store, ledger, or
  output artifact is committed.
- GitHub Actions must be disabled at publication. Only the owner may push,
  merge, administer, or install repository-scoped integrations. No
  collaborators or teams are added for the first release.

## Non-goals and deferred work

- Direct WinRM execution or a WinRM release-readiness claim.
- Domain Kerberos, workgroup NTLM policy, HTTPS WinRM certificate lifecycle,
  `TrustedHosts`, CredSSP, Basic, Digest, or client-certificate authentication.
- Running HostHunter itself under Windows PowerShell 5.1.
- Automatically disabling server-wide SSH password authentication.
- Storing endpoint passwords or injecting them through command arguments,
  environment variables, `sshpass`, `expect`, or plaintext temporary files.
- Running unreviewed fork or pull-request code on the laptop gate.
- A GUI, centrally controlled audit sink, audit pruning, or key rotation API.

## Current state

- Target CRUD, SSH transport, strict host-key validation, Ed25519 bootstrap,
  audit crypto/ledger, full-stream capture, output limiting, fan-out, hooks,
  container validation, security scans, and CLI journeys exist.
- The macOS Keychain slice passes 37 focused AuditKeyStore tests and 21 focused
  Configuration tests. Its live native lifecycle proved separate-process
  creation/read equality, exact deletion, and a missing post-delete read without
  retaining a test key or plaintext file.
- A pre-candidate read-only capability check reached PowerShell 7 over SSH and
  Windows PowerShell 5.1 through `-UseWindowsPowerShell`; a diagnostic envelope
  preserved all six streams in order. This does not replace exact-candidate
  qualification.
- The target store writes schema v2, migrates schema-v1 SSH profiles
  deterministically, and the public target and command paths carry requested
  and observed runtime metadata.
- Exact remote-operation manifests, strict audit correlations,
  compare-and-swap (CAS) target-store mutation, bounded cleanup, and bootstrap
  dispatch uncertainty plus a cumulative output cap passed adversarial
  container evidence in the canonical working-tree gate.
- WinRM remains a fail-closed stub and public dispatch rejects it. Its negative
  unit and fresh-process paths passed; positive WinRM remains deferred.

## Target schema and public API

The target store expands to schema v2 with:

- `PowerShellRuntime`: `PowerShell7` or `WindowsPowerShell51`.
- `LastValidatedPSEdition`: `Core` or `Desktop`.
- `LastValidatedPowerShellVersion`: the observed full version string.
- `LastValidatedExecutionMode`: `Direct` or
  `WindowsPowerShellCompatibility`.

Any illustrative Windows PowerShell 5.1 build strings in public planning prose
are synthetic test values. Exact live build identifiers belong only in the
redacted local qualification receipt.

`Set-HHTarget` gains `-PowerShellRuntime`, defaulting to `PowerShell7`.
Schema-v1 SSH records migrate deterministically to `PowerShell7`; no network
behavior changes during migration. Existing WinRM records remain rejected and
must not be guessed into a supported runtime.

Endpoint uniqueness includes transport, host, port, subsystem, and requested
runtime. This permits two named profiles for the same Windows SSH endpoint—one
direct PowerShell 7 and one bridged Windows PowerShell 5.1—while rejecting an
exact duplicate profile.

The exported cmdlet set remains exactly:

- `Set-HHTarget`
- `Get-HHTarget`
- `Test-HHTarget`
- `Remove-HHTarget`
- `Invoke-HHCommand`
- `Enable-HHSshKeyAuthentication`

## Execution and accountability design

1. Write and seal the audit intent before opening any network session.
2. Open the normal strictly pinned SSH PowerShell 7 session and run the existing
    identity probe.
3. For `PowerShell7`, require `Core` edition and major version 7, then execute
    through the existing remote stream envelope.
4. For `WindowsPowerShell51`, require a Windows PowerShell 7 outer target,
    create one local compatibility PSSession, and require `Desktop` edition and
    version 5.1 before dispatch.
5. The compatibility wrapper merges and classifies all six streams inside the
    5.1 runspace before PSRP serialization, then emits finite tagged envelopes
    through the outer SSH session.
6. Preserve per-target sequence, target/runspace attribution, the 100 MiB cap,
    global throttle of eight, immediate stop behavior, and no automatic retry.
7. Close the compatibility runspace and SSH session in bounded cleanup paths.
8. Record requested runtime, observed runtime/edition/version, execution mode,
    identity, host-key fingerprint, dispatch state, outcome, command text,
    optional context, stream evidence, sizes, hashes, and timing.

If a connection is lost after dispatch and completion cannot be proven, the
terminal audit outcome is `Unknown`. A non-terminating remote Error record is
captured and does not by itself abort later records. A terminating error is a
recorded remote command failure.

## Failure and recovery contract

- Missing PowerShell SSH subsystem: fail before target persistence.
- Outer target not PowerShell 7: `RuntimeMismatch`; no fallback.
- Requested 5.1 on a non-Windows target: `RuntimeUnavailable`; no dispatch.
- Compatibility session cannot open or reports anything except Desktop 5.1:
  fail before candidate dispatch.
- Output limit exceeded: stop the shared pipeline immediately, classify the
  offender as `OutputLimitExceeded`, and mark unprovable peer outcomes
  conservatively.
- Audit intent or evidence write failure: no network activity or fail closed at
  the appropriate terminal stage.
- Key bootstrap failure: remove only the exact HostHunter marker installed by
  that attempt and retain the password profile.
- GitHub permission/settings mismatch: do not report the repository as locked
  down or publication complete.

## User-action coverage matrix

| User action | Public surface | Expected behavior | E2E evidence required | Unit/integration evidence | Current status |
|---|---|---|---|---|---|
| Save default PS7 SSH target | `Set-HHTarget` | direct runtime validated and persisted | fresh-process set/get | schema and real SSH probe | verified |
| Save explicit 5.1 target | `Set-HHTarget -PowerShellRuntime WindowsPowerShell51` | compatibility runtime validated and persisted | fresh-process set/get on qualified Windows target | validation plus live bridge | deterministic/negative evidence verified; live positive pending |
| Save PS7 and 5.1 profiles for one endpoint | `Set-HHTarget -Add` | both coexist without false duplicate rejection | two-profile fresh-process journey | endpoint identity unit matrix | no-network preview and unit evidence verified; live 5.1 save pending |
| Reject unavailable/mismatched runtime | `Set-HHTarget`, `Test-HHTarget` | no save or mutation; stable failure | negative CLI journey | runtime probe/failure unit cases | verified |
| Invoke one 5.1 command | `Invoke-HHCommand` | exact command and ordered streams retained | live Windows CLI journey | bridge unit and integration tests | deterministic bridge verified; live positive pending |
| Invoke mixed PS7/5.1 targets | `Invoke-HHCommand` | independent outcomes under throttle <=8 | mixed-runtime CLI journey | fan-out attribution and cap tests | deterministic fan-out verified; live mixed batch pending |
| Preview key conversion | `Enable-HHSshKeyAuthentication -WhatIf` | no remote or profile mutation | existing CLI journey | existing plan tests | covered |
| Convert live password target to key | `Enable-HHSshKeyAuthentication` | separate key-only proof then profile transition | authorized live Windows journey | fixture rollback/idempotence tests | disposable fixture verified; live Windows transition pending |
| Attempt WinRM target | target/command cmdlets | clear deferred/fail-closed error | negative fresh-process journey | WinRM stub tests | verified negative; positive WinRM deferred |
| Remove either runtime profile | `Remove-HHTarget` | exact selected profile removed atomically | fresh-process remove journey | store mutation tests | verified deterministically |

Rows that require positive Windows 5.1 execution remain live qualification
tasks. This CLI service-journey layer is the browser/Playwright equivalent for
this non-graphical module.

## Verification plan

- Unit: schema v2/migration, runtime validation, endpoint uniqueness, identity
  matching, compatibility planning, envelope classification, output limits,
  dispatch uncertainty, audit metadata, and redaction.
- Container integration: existing real SSH fixture for direct PS7; injected
  compatibility-session seams for deterministic success/failure/cleanup;
  existing real key-bootstrap rollback and key-only proof.
- Live Windows qualification: exact candidate archive/hash, PS7 direct command,
  5.1 compatibility command, mixed runtime batch, six ordered streams,
  runtime mismatch/no fallback, and the authorized Ed25519 transition.
- CLI E2E: every matrix row above in fresh PowerShell processes; live-only
  rows remain a separate explicit qualification lane.
- Coverage: at least 95% changed-scope engineering target and at least 90% for
  statements, true branch outcomes, functions, and executable lines
  repository-wide.
- Release: test-readiness preflight, exact-SHA standalone container gate,
  refreshed threat model, repo-scoped gitleaks, dependency and image scans,
  hook verification, slim pre-push gate, and remote GitHub settings audit.

## Security and privacy

- Trust boundaries: local operator to HostHunter; HostHunter to macOS Keychain
  and ssh-agent; controller to SSH server; PowerShell 7 outer runspace to the
  local 5.1 compatibility process; runtime to audit store; reviewed source to
  the laptop gate; owner to public GitHub.
- Sensitive assets: SSH private keys/passphrases, endpoint passwords, audit
  master key, complete command text/output, target metadata, ledger integrity,
  and repository administration.
- Candidate output may contain secrets and remains encrypted at rest.
- The publication candidate must contain no real operational identifiers or
  artifacts.
- External contributors may read and fork the public source, but cannot push,
  merge, administer, install apps, or trigger trusted local execution.
- The repository threat model remains public and is refreshed against the
  final candidate before push.

## GitHub lockdown and publication

1. Create public `jimtin/HostHunterNextGeneration` with `main` as default.
2. Add no collaborators, teams, deploy keys with write access, or
    repository-scoped GitHub Apps beyond the authenticated owner.
3. Disable GitHub Actions for the repository and confirm there are no workflow
    files or workflow runs.
4. Enable private vulnerability reporting and the supported read-only security
    analysis features that do not execute repository code.
5. Protect `main` from deletion and force pushes where the account/plan permits,
    without creating a rule that locks out the sole owner.
6. Push only the exact locally proven candidate through the installed slim
    pre-push hook.
7. Re-read repository visibility, owner/permissions, collaborators, rules,
    Actions policy, default branch, and remote SHA before claiming completion.

Public visibility necessarily allows forks and pull requests. Those do not
grant write access. No external contribution is merged or executed until the
user explicitly changes this policy.

## Rollout and rollback

- Schema v2 is an expand/deploy migration. Version-1 SSH records are read and
  upgraded deterministically; writes use v2. No destructive schema contraction
  occurs in this release.
- Runtime code lands only with its focused tests and updated inventories.
- The live key transition retains password authentication. If key-only proof
  fails, the exact installed entry is rolled back. If it succeeds, the managed
  key remains until the user explicitly requests removal.
- WinRM remains the existing fail-closed stub; no Windows listener or trust
  configuration is changed.
- GitHub publication can be rolled back by making the repository private or
  archiving it, but neither action is taken without new user authorization.

## Parallel work

- Runtime/schema lane: target schema, runtime validation, compatibility bridge,
  and their focused unit tests.
- Journey/documentation lane: CLI E2E updates, action inventories, README/help,
  and deferred-WinRM wording without editing production runtime files.
- Security/release lane: threat-model delta, sensitivity review, and GitHub
  settings checklist without publishing early.
- Main agent: final behavior integration, live Windows mutation, acceptance
  ledger, exact-SHA gates, commit/push, and GitHub settings mutation.

Workers use disjoint file ownership, do not revert concurrent changes, and
report changed files plus focused evidence. The main agent owns cross-lane
integration and the canonical gate.

## Acceptance ledger

| Requirement | Implementation | Evidence | Status |
|---|---|---|---|
| Secure audit-key lifecycle | native macOS Keychain plus safe non-mac fallback | container tests, live disposable create/read/delete, four-metric receipt | focused, live lifecycle, and aggregate working-tree gate passed |
| Select PS7 or Windows PowerShell 5.1 | schema v2 and runtime-aware target API | focused unit, CLI, and live Windows proof | container/direct and negative paths verified; exact-commit live 5.1 pending |
| Preserve complete accountable execution | direct/compatibility envelopes plus audit metadata | all-stream, cap, failure, tamper, and mixed-batch proof | direct and deterministic compatibility evidence verified; live 5.1 pending |
| Bind every remote operation to an exact manifest | operation-specific command, argument, runtime, and completion contracts | manifest rejection and operation-boundary tests | verified in container |
| Enforce strict audit correlations | exact batch, invocation, target, operation, dispatch, and outcome relationships | malformed and cross-operation correlation tests | verified in container |
| Protect target mutations with CAS | compare the expected store generation before atomic replacement | competing-writer and stale-update tests | verified in container |
| Bound compatibility cleanup | deterministic timeout for compatibility-runspace and SSH cleanup, including cancellation | cleanup timeout and cancellation tests | verified in container |
| Preserve bootstrap uncertainty and cumulative limits | conservative dispatch state plus one cumulative cap across bootstrap phases | uncertain-dispatch and cross-phase cap tests | verified in container |
| Convert password SSH target to Ed25519 | existing bootstrap plus authorized live journey | key-only reconnect and exact rollback evidence | fixture verified; exact-commit live Windows transition pending |
| Defer WinRM honestly | retain fail-closed stub and remove release claims | negative CLI tests and documentation sweep | verified negative; positive WinRM deferred |
| Publish without sensitive data | hardened ignores, public threat model, scans | exact tree/history gitleaks and sensitivity audit | working-tree security lane passed; exact-commit/history proof pending |
| Only owner can modify GitHub repository | no collaborators/teams/write apps; protected main; Actions disabled | live GitHub permission/settings re-read | pending |

## Open items

- Answered: dual-runtime architecture, live key bootstrap authorization, public
  threat-model disclosure, and owner-only GitHub authority.
- Deferred with user approval: all WinRM implementation and qualification until
  a controlled lab exists.
- Accepted assumptions: public readers may fork or open pull requests, but
  neither action grants write authority or trusted execution.
- Pending release evidence: exact-commit canonical proof, positive live Windows
  5.1 and key-transition qualification, and live GitHub publication/settings
  verification.

## Implementation sequence

1. Completed for the working tree: freeze this confirmed contract and action
    matrix.
2. Completed for the working tree: implement schema v2 and runtime-aware target
    validation with focused tests.
3. Completed for the working tree: implement the bounded Windows PowerShell 5.1
    compatibility bridge and audit metadata with focused tests.
4. Completed for the working tree: update CLI journeys, inventories, help,
    README, and threat model.
5. Completed for the working tree: run focused evidence and the canonical local
    container gate.
6. Pending: create an exact candidate commit and re-run the full local container
    gate for that exact commit.
7. Pending: qualify that exact archive in the designated live Windows
    environment, including the authorized key transition, without changing
    WinRM configuration.
8. Pending: reconcile evidence, run security/push lanes, create the public
    locked-down GitHub repository, push, and verify remote state.
