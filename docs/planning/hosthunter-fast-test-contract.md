# HostHunter Fast Test Contract

Status: Implemented — focused proof complete; exact-SHA release proof deferred

## 1. Objective

Replace HostHunter's overlapping and expanding test orchestration with a small,
bounded validation system that answers the questions operators and maintainers
actually need answered:

1. Do all exported HostHunter cmdlets work?
2. Do their required SQLite reads and writes work safely?
3. Does the native macOS PowerShell experience work when it changes?
4. Do managed-host operations work against a real Windows host before release?
5. Does the exact release candidate meet the retained security, build,
    persistence, and coverage requirements?

The design must prevent automatic retries, repeated exact-SHA proof attempts,
nested broad suites, duplicated builds, and coverage work from obscuring the
cmdlet verdict.

## 2. Confirmed decisions

1. Native release coverage retains a minimum of 90 percent for statements,
    lines, and invoked functions.
2. The numerical PowerShell branch-percentage gate is replaced by explicit,
    meaningful behavioral tests for public cmdlets, authentication choices,
    managed-host dispatch outcomes, SQLite mutations, and critical recovery
    states.
3. The unfinished custom AST branch-coverage redesign will be removed rather
    than completed.
4. The dirty experimental testing work will be discarded after an external
    reference patch is preserved. The implementation will restart from clean
    commit `31d6baa` and selectively reapply only approved, verified fixes.
5. Live Windows qualification runs once against the exact release SHA and
    exact production image. It does not run during normal development,
    pre-commit, or pre-push.
6. Coverage, production builds, full security scans, image scans, and critical
    persistence fault checks remain release-only.
7. Every broad lane runs once, produces a terminal receipt, and never retries.

## 3. Testing layers

### 3.1 Focused development tests

Run only the test files directly related to the implementation slice.

- One container invocation.
- No coverage calculation.
- No network unless the changed behavior requires the SSH fixture.
- Normal target: under 5 seconds per focused file or group.
- Hard timeout: 30 seconds.
- No retries.
- A failure becomes the next focused implementation task; it must not trigger a
  broader suite.

### 3.2 Fast unit smoke

Run the ordinary unit suite once without coverage.

- One container.
- One PowerShell process.
- One Pester invocation.
- Current baseline: approximately 690 tests in 18 seconds.
- Normal target: 25 seconds.
- Hard timeout: 45 seconds.
- No shards, source rewriting, profiler, branch instrumentation, worker fanout,
  or nested PowerShell processes.

This is the maximum routine unit-test scope.

### 3.3 Authoritative cmdlet and SQLite acceptance

Maintain one stateful, metadata-driven journey covering every exported user
cmdlet. The current expected count is 12; the expected list must be read from
the packaged module contract so additions cannot silently escape testing.

The journey will:

1. Use one production-derived controller/verifier container and one disposable
    SSH fixture.
2. Exercise every exported cmdlet through its supported user flow.
3. Cover target creation, authentication, target testing, command execution,
    audit and output reads, preferences, host details, and target removal.
4. Route every managed-host operation through the single audited managed-host
    engine.
5. Perform all business writes through public HostHunter behavior.
6. Use only read-only SQL snapshots for physical persistence assertions.
7. Assert relevant row, generation, mutation, outcome, artifact, and audit
    deltas rather than brittle absolute database counts.
8. Prove fresh-process public readback for encrypted persisted values.
9. Check SQLite integrity and verify that credentials are not stored as
    plaintext.
10. Produce one terminal receipt containing one unique result row per expected
    cmdlet.

It will not run coverage, builds, scans, parser services, unrelated integration
tests, or release checks.

- Normal target: 30 seconds.
- Hard timeout: 90 seconds.
- One invocation and no retries.
- Its result is independent and always reported separately from later release
  checks.

Adding a cmdlet extends this journey and its metadata. It must not create a new
test lane.

### 3.4 Native macOS client journey

Run this only when the native client, PowerShell profile, onboarding prompts,
authentication interaction, startup animation, automatic synchronization, or
container lifecycle changes.

It covers:

1. Loading a fresh packaged HostHunter client from macOS PowerShell.
2. Automatic controller startup.
3. Key and stored-password onboarding.
4. Host-key trust and confirmation-frame handling.
5. Automatic authentication reuse without repeated operator prompts.
6. One representative managed-host command.
7. Fresh-version synchronization after shell reload.

- Hard timeout: 90 seconds.
- One invocation and no retries.
- It is not repeated at release when the exact packaged client receipt already
  proves the unchanged client artifact.

### 3.5 Live Windows qualification

Run only after local cmdlet acceptance passes for the exact release candidate.

It will:

1. Use the existing managed Windows host and the saved SSH key.
2. Use the exact production image and exact candidate SHA.
3. Exercise all Windows-facing public operations through the single managed-host
    engine.
4. Positively prove Windows process-audit-policy mutation and restoration.
5. Prove command, audit, and output readback.
6. Record expected phase counts so unexpected additional remote calls fail the
    qualification.
7. Restore every Windows setting or key material changed by qualification.
8. Produce one terminal passed, failed, blocked, or aborted receipt.

- Hard timeout: 180 seconds.
- No automatic retry, including after uncertain remote dispatch.
- A missing host or credential is a terminal blocked result for that SHA.

### 3.6 Exact-SHA release proof

The standalone laptop release gate owns the expensive proof. It runs only after
an exact candidate SHA is committed and clean.

Order:

1. Atomically claim the exact SHA once.
2. Build each required image once and record its digest.
3. Run the cmdlet and SQLite journey using those exact images.
4. Run live Windows qualification.
5. Run release-only native coverage.
6. Run the small critical authenticated-SQLite fault and recovery suite.
7. Run dependency, secret, filesystem, and image security scans.
8. Validate all component receipts.
9. Aggregate receipts read-only.
10. Seal the candidate as passed, failed, blocked, or aborted.

Rules:

- One attempt per exact SHA.
- No automatic retries.
- An interrupted run is sealed aborted.
- A consumed SHA can never be rerun; a repair requires a new SHA.
- A failed broad check leads only to focused diagnosis and focused repair tests.
- A second release attempt requires a new committed candidate.
- Coverage, security, Windows, or build failures cannot change, remove, or hide
  the independent cmdlet verdict.
- The aggregator cannot execute tests or mutate component results.

## 4. Coverage contract

Coverage is release-only and uses standard PowerShell/Pester-supported evidence
for the shipped production and native-client source.

- Minimum statements: 90 percent.
- Minimum lines: 90 percent.
- Minimum invoked functions: 90 percent.
- Engineering target for each metric: 92 percent or higher.
- Exactly one bounded coverage invocation unless the selected standard
  profiler requires one ordinary verdict pass and one coverage pass; in that
  case the two fixed invocations run within one container and one root timeout.
- No custom AST branch collector.
- No source-copy instrumentation.
- No per-hit files, JSON shards, mutexes, checksums, worker fanout, or nested
  coverage processes.
- No integration, live-host, or network tests in the coverage numerator.

Branch confidence is provided by named behavioral tests rather than a synthetic
percentage. Required branch families include:

- Every public cmdlet success, validation, cancellation, and supported failure
  outcome.
- Key authentication, stored-password authentication, and warned password
  fallback.
- Managed-host pre-dispatch failure, completed failure, uncertain dispatch,
  cleanup failure, and no-retry recovery.
- SQLite empty state, save, replacement, deletion, tamper detection, rollback
  detection, atomic failure, and crash recovery.
- Credential redaction and absence of plaintext from SQLite, logs, artifacts,
  arguments, environment, and client frames.

## 5. Hook contract

### Pre-commit

Runs:

1. Gitleaks.
2. Static and governance checks.
3. Changed/focused unit tests.

- Target: under 30 seconds.
- Hard timeout: 45 seconds.
- No coverage, production builds, image scans, Windows qualification, or broad
  integration suites.

### Pre-push

Runs:

1. Gitleaks.
2. Dependency audit.
3. Static and governance checks.
4. Fast unit smoke.
5. The single cmdlet and SQLite journey.
6. Native macOS journey only when its owned files changed.

- Target: under two minutes.
- No full coverage, production build, image scan, live Windows qualification,
  broad persistence fault matrix, or duplicated release work.

The standalone exact-SHA release gate, not pre-push, owns full proof.

## 6. Mechanical anti-loop controls

Every runner must enforce the following:

1. One root timeout owner.
2. One declared scope and command before execution.
3. One invocation per lane.
4. One terminal receipt on success, failure, timeout, signal, or prerequisite
    block.
5. No automatic retries.
6. No broad runner may invoke itself or another broad runner.
7. Missing or incoherent receipts fail closed.
8. Interruptions cannot return success.
9. A failed broad run may only be followed by focused diagnosis.
10. Broad verification cannot rerun on the same exact SHA.
11. Cleanup always targets the exact run-scoped Compose project and disposable
    volumes.
12. Cmdlet results remain independent of release component results.

Any proposed new lane requires explicit approval and must state:

- the user or release question it answers;
- its owner and exact scope;
- its normal and hard runtime budgets;
- its terminal artifact;
- the existing lane it replaces or why an existing lane cannot absorb it.

No new lane is allowed merely because a test failed or a new cmdlet was added.

## 7. Test-pruning inventory

Before deletion, existing test machinery will be classified as active,
compatibility, superseded, dead, or unknown. Expected removals or replacements
include:

- The unfinished custom AST coverage collector and its experimental tests.
- Coverage shards, per-hit persistence, mutex/checksum collectors, instrumented
  source copies, and duplicate coverage processes.
- Stale coverage-spike and threshold-self-test entrypoints.
- Duplicate unit-suite execution across pre-commit, pre-push, and release.
- Duplicate module, toolchain, and image builds already owned by the exact-SHA
  gate.
- Old broad schedulers, obsolete shard receipts, and stale top-level evidence
  promotion.
- Default 900, 1200, and 1800 second wrappers where focused critical cases can
  use smaller explicit bounds.

Removal is not complete until a deleted-surface sweep classifies every remaining
reference in scripts, tests, documentation, hook configuration, and receipt
validators.

## 8. Dirty-worktree recovery

Implementation begins with controlled recovery, not additional edits on the
experimental tree.

1. Record the current branch, HEAD, status, and diff inventory.
2. Export the complete dirty diff and untracked-file inventory to a timestamped
    patch bundle outside the repository.
3. Verify that the external bundle is readable and contains the expected files.
4. Restore the repository to clean commit `31d6baa` without deleting operator
    data, Docker volumes, credentials, or unrelated repositories.
5. Verify a clean worktree.
6. Selectively reapply only:
    - the proven Windows protected-volume least-privilege copy fix;
    - the corrected SQLite asset-manifest validation;
    - fail-closed terminal-receipt handling;
    - the simplified runners, documentation, and tests in this contract.

The experimental coverage implementation is preserved only as external
reference material and is not reintroduced.

## 9. Implementation sequence

### Phase 1 — Recover a clean baseline

- Preserve the external patch bundle.
- Restore and verify clean `31d6baa`.
- Record the baseline unit-smoke and cmdlet-journey timings once.

### Phase 2 — Make receipts fail closed

- Ensure every runner seals terminal status on normal exit, timeout, and signal.
- Reject missing, duplicate, mismatched, or incoherent receipts.
- Prevent interrupted PowerShell from printing a passing lane result.
- Add small receipt-state contract tests.

### Phase 3 — Simplify focused and unit lanes

- Reduce routine unit validation to one ordinary Pester invocation.
- Remove shards, workers, instrumentation, and duplicate unit execution.
- Enforce 30-second focused and 45-second unit hard limits.

### Phase 4 — Consolidate cmdlet acceptance

- Make the exported-command manifest authoritative.
- Keep one ordered cmdlet/SQLite journey.
- Add automatic failure when expected and observed unique cmdlet names differ.
- Enforce the 90-second hard limit and one terminal receipt.

### Phase 5 — Slim the hooks

- Implement the pre-commit and pre-push contracts above.
- Add contract tests proving prohibited release-only commands are absent.
- Verify hooks are installed and fail closed.

### Phase 6 — Simplify release coverage

- Delete the custom AST branch collector.
- Configure native statement, line, and invoked-function thresholds.
- Retain meaningful behavioral tests for the required branch families.
- Enforce one container, one timeout, standard reports, and no network.

### Phase 7 — Reapply bounded release fixes

- Reapply the proven protected-volume setup/copy design.
- Reapply exact SQLite asset-manifest validation.
- Prove each through its focused container contract without running the release
  gate.

### Phase 8 — Rebuild the exact-SHA release gate

- Build images once.
- Reuse their digests across cmdlets, Windows, coverage, persistence, and scans.
- Enforce once-per-SHA claims and independent component receipts.
- Make aggregation read-only.

### Phase 9 — Validate without looping

Run in this order, once each:

1. Focused contract files.
2. Fast unit smoke.
3. Cmdlet and SQLite journey.
4. Native macOS journey if affected.
5. Pre-commit contract.
6. Pre-push contract.

Only after all focused evidence is green may one new exact candidate be committed
for a single release proof. A release failure ends the attempt and returns to
focused repair; it never triggers an automatic rerun.

## 10. Security boundaries retained

The simplification does not remove HostHunter's active authenticated persistence
or managed-host security guarantees.

Retained boundaries include:

- Encrypted persisted credentials and output.
- Separate SQLite data, secret, anchor, SSH-key, and evidence roots.
- Authenticated audit artifacts.
- Tamper and rollback detection.
- Atomic mutations and crash recovery.
- Durable intent and dispatch arming before managed-host contact.
- No automatic retry of uncertain remote mutations.
- One managed-host communication engine.
- Redaction of secrets from receipts, logs, frames, arguments, and environment.

The security review for implementation will concentrate on accidental bypass of
the managed-host engine, forged passing receipts, credential disclosure,
same-SHA replay, unsafe volume ownership changes, and cleanup targeting the
wrong Compose project or volume.

## 11. Parallel work

Parallel agents are useful during implementation only where ownership is
disjoint:

1. Main agent: clean-baseline recovery, integration decisions, hooks, final
    validation, threat model, gitleaks, and release candidate.
2. Runner worker: focused/unit/cmdlet runners and timeout/receipt behavior.
3. Release worker: exact-SHA state machine, Windows qualification orchestration,
    and read-only aggregation.
4. Pruning/docs worker: obsolete-surface inventory, deletions, and contract
    reconciliation.

Workers must not edit overlapping files, revert other changes, or run the broad
release gate. The main agent owns integration and the only exact-SHA proof.

## 12. Acceptance criteria

The redesign is complete only when:

1. The discarded experimental diff is preserved outside the repository, and
    the implementation diff is ready to be committed as one deliberate
    candidate when publication is requested.
2. Focused tests complete within their 30-second hard bound.
3. The ordinary unit suite runs once and completes within 45 seconds.
4. One journey proves every exported cmdlet and required SQLite behavior within
    90 seconds.
5. Pre-commit completes within 45 seconds.
6. Pre-push completes within two minutes under normal cached conditions.
7. Live Windows runs only at exact-SHA release and completes within 180 seconds.
8. Coverage uses no custom AST branch instrumentation and meets the confirmed
    90 percent statement, line, and invoked-function thresholds.
9. Required behavioral branch families have meaningful named tests.
10. Every broad lane writes a terminal receipt on pass, failure, timeout, or
    interruption.
11. No automatic retry or same-SHA rerun path exists.
12. Builds and full scans occur once per exact release SHA.
13. A failed coverage, build, scan, persistence, or Windows check cannot obscure
    or rewrite the cmdlet verdict.
14. Deleted-surface searches find no active references to the removed coverage
    and orchestration machinery.
15. The final exact-SHA proof runs once, locally in containers, after the
    implementation is committed as a clean candidate.

## 13. Explicit non-goals

- Rewriting HostHunter's authenticated SQLite, encryption, audit, anchor, or
  recovery implementation as part of test simplification.
- Adding another broad test framework.
- Reintroducing parser, Forensics, WinRM, PowerShell 5.1, or native macOS
  controller compatibility.
- Using GitHub-hosted validation.
- Automatically retrying flaky, timed-out, interrupted, or uncertain work.
- Treating a Linux SSH fixture as positive proof of Windows-only behavior.
- Expanding test scope merely to improve a synthetic coverage percentage.
