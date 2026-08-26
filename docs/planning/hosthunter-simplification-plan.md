# HostHunter Simplification and Testing Plan

Status: CONFIRMED 2026-08-26

Implementation status: Not started.

Authoritative pre-cleanup location:
`/Users/jameshinton/Developer/HostHunterNextGeneration-Simplification-Plan.md`

Required repository destination after cleanup:
`docs/planning/hosthunter-simplification-plan.md`

This copy is intentionally stored outside the HostHunter repository because the
current repository worktree is scheduled for destructive cleanup. After the
clean implementation branch is created, this document must be copied into the
repository as its first documentation change.

## 1. Goal

Reduce HostHunter to one clear product:

- Exactly 11 public cmdlets.
- Linux Docker controller.
- PowerShell 7 over OpenSSH.
- Windows and Linux managed hosts.
- Authenticated SQLite persistence.
- Encrypted audit output and tamper/rollback protection.
- One managed-host communication engine.
- One fast 11-cmdlet user journey.
- One separate live-Windows qualification.
- Coverage, security scans, and production builds run once per exact candidate
  SHA as isolated release stages.
- No shards, recursive runners, automatic retries, or same-SHA test loops.

## 2. Current evidence and diagnosis

- The retained E2E artifact passed the six existing stories in 10.778 seconds.
  Those stories collectively invoke all 11 public cmdlets.
- The recurring failures came from orchestration rather than the cmdlets:
  - controller-floor tests passed 9/9 before their wrapper falsely reported no
    emitted tests;
  - the production-runtime shard stopped before testing because of a readonly
    variable collision;
  - coverage workers and combined receipt processing created additional false
    failures and rerun pressure.
- Historical live-Windows evidence exists for exact SHA
  `38e295e63c8d2453df3eee0eb2655fae4d087d92`.
- The current dirty tree and current HEAD are not accepted implementation
  inputs.

## 3. Clean baseline and destructive cleanup

Implementation begins by removing the current dirty Git state.

Current observed state:

- Repository: `/Users/jameshinton/Developer/HostHunterNextGeneration`
- Current branch: `main`
- Current HEAD: `58e8ac4f53ab9651feb558b289ccf8a812f3371d`
- Modified tracked paths: 48
- Untracked paths: 17
- Total dirty paths: 65

Authorized cleanup:

1. Confirm the exact repository root.
2. Confirm no gate, process, editor task, or container is using the source tree.
3. Resolve the exact 65 Git-reported targets again immediately before cleanup.
4. Restore all tracked files to committed content.
5. Delete all Git-reported untracked files and directories.
6. Do not delete ignored artifacts, credentials, databases, evidence, or Docker
    volumes.
7. Create and switch to a dedicated implementation branch rooted exactly at
    `b7e53b86f49d497f661953c921e2c31e5b9c5fe2`.
8. Require an empty `git status --short` before implementation starts.
9. Copy this plan to
    `docs/planning/hosthunter-simplification-plan.md` in that clean branch.

No backup or reconciliation of the 65 dirty paths is required. The cleanup is
destructive and was explicitly authorized by the user.

## 4. Confirmed product boundary

### 4.1 Retain exactly these 11 cmdlets

1. `Set-HHTarget`
2. `Get-HHTarget`
3. `Test-HHTarget`
4. `Remove-HHTarget`
5. `Invoke-HHCommand`
6. `Enable-HHSshKeyAuthentication`
7. `Get-HHAuditRecord`
8. `Get-HHAuditOutput`
9. `Set-HHWindowsProcessAuditPolicy`
10. `Set-HHEscalationPreference`
11. `Get-HHEscalationPreference`

### 4.2 Retain these guarantees

- Authenticated SQLite state.
- Encrypted audit records and `.hhout` output.
- External anchors and rollback detection.
- Tamper detection.
- Crash recovery.
- Intent recorded before host contact.
- Dispatch armed immediately before every remote phase.
- No automatic retry after uncertain dispatch.
- Exact semantic operation labels.
- SSH host-key verification.
- Password-to-key transition safety.
- Windows audit-policy restoration.
- Separate data, secrets, anchors, SSH-key, and evidence volumes.

### 4.3 Remove these surfaces

- Forensics, EVTX, ECS, parser, API, and outbox paths.
- Parser service and parser socket.
- WinRM.
- Windows PowerShell 5.1.
- Native macOS and native Windows controller modes.
- macOS Keychain controller providers.
- Raw SSH/SCP qualification paths.
- Generic production `shell` and unrestricted `run` launcher modes.
- Redundant controller-floor, capacity, parser, journey, and shard runners.
- Duplicate E2E paths and combined-budget machinery.
- Tests, fixtures, documentation, and dependencies belonging only to removed
  functionality.

Existing operator data and Docker volumes are not deleted automatically.

## 5. Exclusive managed-host engine

Create one private, non-exported entrypoint:

`Invoke-HHManagedHostOperation`

This is the only production application path from the controller to a
user-configured managed host.

### 5.1 Host-facing cmdlets

These five cmdlets must call the engine exactly once:

- `Set-HHTarget`
- `Test-HHTarget`
- `Invoke-HHCommand`
- `Enable-HHSshKeyAuthentication`
- `Set-HHWindowsProcessAuditPolicy`

The other six cmdlets must have negative contract proof that they do not open a
managed-host connection.

### 5.2 Engine responsibilities

The engine owns:

- authenticated persistence opening and operation locking;
- target snapshot and concurrency checks;
- interrupted-operation recovery;
- semantic operation registration;
- capacity reservation;
- deterministic remote-operation manifests;
- audit artifact creation;
- dispatch arming;
- host-trust discovery;
- SSH session creation and identity verification;
- command, key-bootstrap, and policy dispatch;
- stream capture and encrypted output publication;
- terminal success, failure, cancelled, or uncertain classification;
- session cleanup;
- no-retry enforcement.

The semantic labels remain distinct:

- `ValidateTarget`
- `TestTarget`
- `InvokeCommand`
- `EnableSshKeyAuthentication`
- `SetWindowsProcessAuditPolicy`

Public callers pass closed, structured requests. They may not supply arbitrary
transport callbacks, manifest factories, or result augmenters.

`Invoke-HHCommand` remains the intentional arbitrary-command user surface, but
it becomes a thin adapter to the engine.

### 5.3 Boundary scope

The engine restriction covers controller-to-managed-host traffic. It does not
cover:

- SQLite;
- local files and volumes;
- Docker health checks;
- Docker-internal component traffic;
- local `ssh-keygen` or `ssh-agent`;
- build, scanner, package, or GitHub tooling.

If a Docker SSH fixture is configured as a HostHunter target, cmdlet traffic to
it still uses the engine.

A command deliberately sent through `Invoke-HHCommand` may contact another
system from the remote host. HostHunter audits the originating command and
outcome but does not claim to govern every downstream network action performed
by that command.

### 5.4 Mechanical enforcement

Lock the boundary through:

- a private nested engine module;
- one engine-owned SSH adapter containing managed-host transport primitives;
- an engine-created dispatch context proving durable intent and phase arming;
- a fast PowerShell AST/call-graph guard.

The guard fails if it finds:

- `New-PSSession`, session `Invoke-Command`, `Remove-PSSession`,
  `ssh-keyscan`, raw `ssh`, `scp`, `sftp`, sockets, or target HTTP
  clients outside the allowlisted engine adapter;
- direct transport or audit orchestration in public cmdlets;
- more or fewer than one engine call from a host-facing cmdlet;
- an engine call from a local-only cmdlet;
- raw managed-host access inside qualification scripts;
- dynamic invocation intended to bypass the facade.

The official container launcher accepts only the 11 exported cmdlets. A
privileged Docker administrator's manual break-glass access is outside the
application guarantee.

## 6. Persistence and database contract

Retain:

- existing core migrations;
- SQLite provider and repositories;
- encryption and authentication;
- audit-chain records;
- external anchor handling;
- `.hhout` files;
- capacity controls;
- atomic file publication;
- locking and crash recovery.

No core schema migration is currently planned.

Existing migration files remain byte-for-byte unchanged. Historical WinRM or
PowerShell 5.1 target records may remain readable and removable, but dispatch
must fail before host contact with a stable unsupported-profile error. They are
never silently converted.

The production controller retains five trust-domain volumes:

1. Data/database.
2. Secrets.
3. Anchors.
4. SSH material.
5. Evidence and `.hhout`.

Old Forensics/parser volumes remain untouched through the rollback window.

Simplification of the active authenticated-persistence implementation is
deferred to a separately approved project.

## 7. Canonical 11-cmdlet journey

The fast user test runs in exactly two containers:

- production-derived Linux PowerShell verifier;
- disposable PowerShell-over-SSH fixture.

It uses one fresh authenticated SQLite state and one ordered journey.

| Step | User action | Required result | Persistence evidence |
|---:|---|---|---|
| 1 | `Set-HHEscalationPreference` | Preference committed | Configuration generation and mutation increase |
| 2 | `Set-HHTarget` | Pinned PS7 SSH target validates and saves | Target profile, generation, mutation, and `ValidateTarget` audit |
| - | Restart verifier process | State reopens successfully | Same DB, keys, anchor, and generations |
| 3 | `Get-HHEscalationPreference` | Persisted preference returned | No mutation |
| 4 | `Get-HHTarget` | Exact saved target returned | No mutation |
| 5 | `Test-HHTarget` | Identity probe succeeds | One terminal `TestTarget` invocation |
| 6 | `Invoke-HHCommand` | Marker command and all streams return | Invocation, outcome, audit, encrypted `.hhout`, artifact rows |
| 7 | `Set-HHWindowsProcessAuditPolicy` | Linux: finite audited platform failure; Windows: positive result | Terminal policy audit with no retry |
| 8 | `Enable-HHSshKeyAuthentication` | Key-only proof succeeds before profile change | Target generation/mutation increase and terminal bootstrap audit |
| 9 | `Get-HHAuditRecord` | Exact authenticated records returned | Read-only |
| 10 | `Get-HHAuditOutput` | Ordered output decrypts | Read-only |
| 11 | `Remove-HHTarget` | Target removed | Target generation/mutation increase; audit retained |

### 7.1 SQLite checks

After each step, a read-only connection uses `PRAGMA query_only=ON` and
records deltas for:

- `PRAGMA integrity_check`;
- migration state;
- target profiles, state, and mutations;
- configuration state and mutations;
- operation batches;
- invocations and declared remote phases;
- dispatch-armed events;
- outcomes;
- output artifact metadata;
- audit events.

Direct SQL never writes test state. All mutations must occur through public
cmdlets.

Final assertions prove:

- the target is removed;
- configuration remains persisted;
- all five semantic host operations have terminal audit evidence;
- no remote operation remains pending;
- getter cmdlets caused no writes;
- audit and output evidence survived target removal;
- known plaintext markers are absent from SQLite envelopes and `.hhout`;
- no legacy JSON/JSONL persistence path was used.

### 7.2 Runner shape

Canonical command:

`./scripts/verify-cmdlets.sh`

Use one ordered spec, one PowerShell/Pester process, one result file, one
timeout owner, and one teardown.

There are:

- no shards;
- no worker fan-out;
- no retries;
- no parser;
- no nested bounded runners;
- no coverage collection;
- no security scans;
- no production build;
- no mutable latest-passed evidence.

Target local bound:

- hard timeout: 180 seconds;
- stall limit: 60 seconds;
- heartbeat: 15 seconds;
- normal duration target: near the existing approximately 11-second result.

## 8. Live Windows qualification

The Linux fixture cannot prove positive Windows process-audit behavior. Release
requires one exact-SHA Windows journey using the production controller image.

The same 11-stage manifest is reused with Windows-specific expectations.

It must prove:

- pinned Windows PS7/OpenSSH target validation;
- real Windows identity probe;
- six-stream command capture;
- audit and output readback;
- real process-audit policy change;
- benign process and expected 4688 evidence;
- exact restoration of prior audit and command-line settings;
- SSH key installation and key-only proof;
- password recovery;
- removal of only the qualification key;
- target removal from the fresh qualification database.

All host contact, including restoration and cleanup, uses public cmdlets and the
shared engine. Raw qualification `ssh` and `scp` are removed.

Windows credentials enter through a run-scoped Docker secret/askpass boundary.
They may not appear in environment variables, process arguments, retained
files, logs, or receipts.

If secure credential injection cannot be qualified, the stage is blocked
rather than falling back to an unaudited path.

If cleanup becomes uncertain:

- status becomes `RECOVERY_REQUIRED`;
- qualification assertions are not rerun;
- recovery-only work may restore policy or remove the qualification key;
- recovery does not turn the SHA into a pass;
- a new SHA is required for another qualification attempt.

## 9. Focused release-only safety proof

The ordinary user journey stays simple. Retain focused release-only proof for:

| Contract | Minimum proof |
|---|---|
| Exclusive host boundary | AST/call-graph guard and runtime contact sentinel |
| Audit before contact | Inject audit/anchor failure; host invocation count stays zero |
| No uncertain retry | Interrupt after arm; recovery records `Unknown`; contact count stays one |
| Authenticated SQLite | Migration, tamper, key/anchor swap, rollback, corruption |
| Encrypted output | Stream round-trip; plaintext absent; corrupt/swapped output rejected |
| Key transition | Failed key proof leaves password profile unchanged |
| Locking/capacity | Failure occurs before host contact |
| `ShouldProcess` | `-WhatIf` causes no database, audit, file, or network mutation |
| Windows compensation | Exact policy and key cleanup in live receipt |

The retained active unit suite must meet at least 90 percent for statements,
branches, functions, and lines. Materially changed engine and persistence code
targets 95 percent.

Coverage never invokes the 11-cmdlet E2E journey.

PowerShell CLI/service-journey coverage is the browser/E2E equivalent.
Playwright and visual testing are not applicable.

## 10. Once-per-exact-SHA release contract

Heavy coverage, security scans, and production builds are release-only. They do
not run inside the fast cmdlet journey.

Each exact candidate commit receives an atomic claim. A stage runs at most once
for that full SHA and writes an immutable receipt.

State model:

`ABSENT -> RUNNING -> PASSED | FAILED | BLOCKED | TIMEOUT | INTERRUPTED | RECOVERY_REQUIRED`

Rules:

- every stage has `attempt: 1` and `retryCount: 0`;
- receipts use no-overwrite creation;
- terminal receipts are returned without executing work;
- active locks return `already_running` without waiting;
- stale running claims become terminal `INTERRUPTED`;
- failure or timeout is terminal for that SHA;
- a code fix creates a new SHA;
- heartbeats report progress only;
- cleanup traps always write a terminal receipt;
- the aggregator reads and hashes receipts only;
- no mutable latest-passed file exists.

### 10.1 Release stages

| Stage | Work | Maximum |
|---|---|---:|
| Preflight | Detached checkout, Docker, credentials, disk, state checks | No test attempt consumed |
| Package | Assemble exact package once | Bounded |
| Cmdlets | Two-container 11-cmdlet journey | 180s |
| Safety/coverage | Focused safety suite and four-metric coverage | 300s |
| Production build | Build supported Linux images once | 600s |
| Security | Gitleaks, dependency, filesystem, package, SBOM/licence, image scans | 900s |
| Windows | One live Windows journey | 900s |
| Aggregator | Validate receipts and derive final verdict | 10s |

Later failures never replace or hide the cmdlet verdict. A final report may say
`cmdlets passed 11/11; release failed during image scanning`.

### 10.2 Hooks

- Pre-commit: syntax, module-export contract, and engine-boundary guard only.
- Pre-push: validates that required exact-HEAD receipts already exist; it
  executes no test suite.
- The exact-SHA gate creates the Gitleaks receipt once before the first push of
  that SHA.
- GitHub runs no tests.

## 11. Container simplification

### 11.1 Production

Reduce production to:

- one Linux controller image;
- PowerShell 7;
- OpenSSH client;
- SQLite provider;
- five external trust-domain volumes;
- non-root user;
- read-only root filesystem;
- no Docker socket;
- no parser or idle sidecar.

The official launcher permits only the 11 public cmdlets.

### 11.2 Testing

Retain only:

- production-derived verifier image;
- disposable SSH fixture image;
- one internal test network;
- ephemeral run-scoped volumes or tmpfs;
- one uniquely named Compose project;
- one cleanup owner.

Cleanup removes only resources bearing the exact run's project labels.
Operator volumes are never touched.

### 11.3 Architectures and runtime version

- Normal development testing uses the laptop's native Linux architecture.
- Release builds retain `linux/arm64` and `linux/amd64`, each built and
  scanned once.
- Each architecture receives an import/start smoke.
- Live Windows qualification uses the host-native production image.
- No broad PowerShell-version matrix remains.
- The controller uses one pinned, currently qualified PowerShell 7 servicing
  version.
- Dependency upgrades are separate deliberate changes.

## 12. Progressive implementation sequence

### Phase 0 - Clean baseline

- Execute the authorized dirty-tree cleanup in Section 3.
- Create the implementation branch at exact baseline
  `b7e53b86f49d497f661953c921e2c31e5b9c5fe2`.
- Verify a clean status.
- Copy this plan into the repository.

### Phase 1 - Freeze contracts

- Run the user-action coverage review first.
- Create acceptance and test ledgers.
- Replace broad testing requirements with the exact 11-cmdlet inventory.
- Record the gate-owned once-per-SHA model.
- Complete managed-host-engine and gate threat models.
- Update testing documentation before deleting code.

### Phase 2 - Add the slim journey

- Reduce the existing six stories into one ordered journey.
- Add per-step public and read-only SQLite assertions.
- Establish the independent cmdlet receipt.
- Keep the old flow until the replacement is proven.

### Phase 3 - Add immutable receipts

- Add atomic per-SHA claims.
- Always write terminal receipts.
- Remove pass-only and overwrite-capable evidence.
- Make aggregation incapable of invoking stages.
- Prove a repeat invocation performs zero work.

### Phase 4 - Extract the engine

1. Move the current coordinator into the private engine.
2. Route `Invoke-HHCommand` and Windows policy through it unchanged.
3. Migrate `Test-HHTarget`.
4. Migrate `Set-HHTarget`, including trust discovery and target commit.
5. Migrate SSH key bootstrap and profile transition.
6. Enable the bypass guard.
7. Delete old direct orchestration.

After each slice, run only the cheapest focused contract test. Do not run the
full gate between slices.

### Phase 5 - Simplify runtime

- Remove parser service, socket, Python assets, and related health checks.
- Reduce production to one controller service.
- Preserve the five core volumes.
- Replace generic shell/run with the constrained launcher.
- Consolidate duplicate Docker stages.
- Keep old images and volumes for rollback.

### Phase 6 - Remove product surfaces

Remove in separate reversible layers:

1. Forensics/API/outbox/ECS.
2. Parser runtime.
3. WinRM.
4. PowerShell 5.1 bridge and mixed-runtime paths.
5. Native macOS/Windows controller providers.
6. Raw Windows qualification SSH/SCP.
7. Obsolete runtime/package assets.
8. Unused dependencies.

### Phase 7 - Remove obsolete validation

Delete or replace:

- five-minute scheduler;
- test-manifest shards;
- controller-floor shard;
- capacity shard;
- runtime/parser journey;
- branch-worker fan-out;
- duplicate E2E/runtime-E2E paths;
- combined-budget and shard-binding scripts;
- pass-only receipt promotion;
- tests and fixtures for removed functionality.

Retain focused security and recovery contracts required by active code.

### Phase 8 - Documentation and deleted-surface sweep

Search production, tests, scripts, Docker, environment examples, and
documentation for:

- `Forensics`
- `ECS`
- `evtx`
- `parser`
- `WinRM`
- `WindowsPowerShell51`
- `Keychain`
- `MacOS`
- `osx-`
- native Windows controller paths
- parser socket
- raw qualification `ssh` or `scp`

Every remaining reference must be classified as:

- immutable migration history;
- historical compatibility read/remove support;
- required negative assertion;
- active Windows-target behavior;
- defect to remove.

### Phase 9 - Final proof

Run once for the exact candidate SHA:

1. Cmdlet journey.
2. Safety and coverage.
3. Production build.
4. Security scans.
5. Windows journey.
6. Read-only aggregation.

No stage is repeated for the same SHA.

## 13. Security design

The implementation threat model must cover:

- bypassing the managed-host engine;
- suppressing or falsifying audit evidence;
- command or argument leakage;
- password/private-key leakage;
- plaintext leakage into SQLite, `.hhout`, logs, or receipts;
- database or anchor rollback;
- duplicate execution after uncertain dispatch;
- unauthorized generic runtime shell use;
- orphaned Windows policy changes;
- orphaned SSH qualification keys;
- malicious gate-receipt changes.

Critical or high findings block release.

The privileged Docker administrator remains outside the application enforcement
boundary and retains documented break-glass capability.

## 14. Rollout and rollback

### 14.1 Data

- No core schema rewrite.
- Existing migrations remain unchanged.
- Existing databases, keys, anchors, output, and volumes are preserved.
- Unsupported historical profiles remain readable/removable.
- New tests use fresh isolated state.

### 14.2 Runtime rollout

- Stop old Compose without deleting volumes.
- Start the one-container controller against the same five core volumes.
- Verify database and anchor opening before host action.
- Run read-only target/audit queries.
- Retain the prior image and old parser/Forensics volumes through rollback.

### 14.3 Rollback

- Stop the new controller.
- Restart the prior exact image and Compose definition.
- Reuse untouched volumes.
- Verify database and anchor consistency before remote dispatch.
- Never retry an uncertain remote command automatically.

Each prune layer remains independently revertible. Commits and pushes occur
only with explicit authorization.

## 15. Parallel work

After implementation begins:

| Lane | Ownership | Expected evidence |
|---|---|---|
| Main agent | Cleanup, contracts, integration, threat model, final gate | Final ledgers and exact-SHA receipts |
| Engine worker | Private engine, five adapters, engine contract tests | Focused unit/integration evidence |
| Test worker | One 11-step journey and SQLite verifier | 11-row JSON/JUnit receipt |
| Gate/runtime worker | Immutable receipts, Docker simplification, aggregation | No-rerun and lifecycle evidence |

Workers receive disjoint file ownership and may not revert existing changes.
Only the main agent integrates and initiates final exact-SHA proof. Windows
qualification remains serialized because it mutates one controlled host.

## 16. Acceptance ledger

| Requirement | Implementation evidence | Final proof |
|---|---|---|
| Exactly 11 cmdlets | Export/manifest contract | 11 unique receipt rows |
| Exclusive host engine | Private module and AST guard | Zero bypasses; five exact delegations |
| Uniform logging | Engine-owned lifecycle | Five semantic operation correlations |
| Preserve SQLite guarantees | Existing formats and focused tests | Integrity/tamper/rollback/recovery pass |
| Fast container test | Two-service Compose | Normal duration near current baseline |
| Read/write verification | Public mutations and read-only SQL | Expected generation/count changes |
| Windows works | Production image to real Windows PS7 host | Policy, streams, key transition, cleanup |
| No test loops | Immutable terminal receipts | Repeat invocation performs zero work |
| Heavy proof isolated | Independent release stages | Cmdlet receipt unchanged by later failure |
| Obsolete code removed | Deleted-surface sweep | No unexplained legacy references |
| Safe rollback | No schema rewrite; volumes preserved | Prior image can reopen state |

## 17. Definition of done

The work is complete only when:

- exactly 11 cmdlets export;
- all 11 have an explicit user-flow verdict;
- all five host-facing cmdlets use the single engine;
- the other six prove no managed-host communication;
- no production or qualification bypass exists;
- the local journey runs in two containers with one fresh SQLite state;
- real Windows PS7/OpenSSH proof passes;
- Windows policy and key state are restored;
- authenticated persistence, encryption, anchors, tamper detection, and
  recovery pass;
- production uses one Linux controller and five core volumes;
- Forensics, parser, WinRM, PS5.1, native controllers, and redundant runners
  are removed;
- same-SHA stage reruns are mechanically impossible;
- coverage, build, and security stages run once and cannot obscure the cmdlet
  result;
- the discarded dirty state is gone and the implementation branch started
  clean from `b7e53b8`;
- existing operator data remains preserved;
- documentation and repository contracts match reality;
- the final release verdict binds the exact package, images, tree, and SHA.

## 18. Confirmation record

The user approved:

- testing exactly the 11 cmdlets;
- direct read/write database verification;
- preserving authenticated SQLite, encryption, anchors, output, and recovery;
- removing Forensics, parser, WinRM, native controllers, and PowerShell 5.1;
- Linux Docker plus PowerShell 7/OpenSSH;
- one shared managed-host engine;
- internal Docker traffic excluded from that engine;
- release-only coverage, scans, and production builds;
- immutable once-per-SHA receipts;
- starting from clean commit `b7e53b8`;
- destructively discarding the 65-path dirty Git state;
- saving this plan before cleanup.

Implementation remains unauthorized until the user explicitly asks it to begin.
