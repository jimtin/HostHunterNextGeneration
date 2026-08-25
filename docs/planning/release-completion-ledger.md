# HostHunterNextGeneration Release Completion Ledger

## Status

**CONFIRMED BY USER 2026-08-24; IMPLEMENTATION IN PROGRESS**

This ledger is the execution source of truth for completing the first public
release after the SQLite persistence cutover. Focused evidence is required
before the exact-candidate gate. The standalone gate owns the only full product
proof for a candidate SHA.

## Shared Understanding Contract

- Goal: finish, qualify, and publicly release the SQLite-backed
  HostHunterNextGeneration module without weakening its audit, transport,
  coverage, or owner-only publication contracts.
- Primary operator: one local repository and endpoint owner.
- Structured persistence: SQLite only. Complete ordered streams remain in
  authenticated encrypted `.hhout` v2 artifacts.
- Durable publication amendment: a dependency-free first-party .NET 8 helper
  performs the platform-specific no-replace rename and namespace durability
  barrier. It has its own changed-scope coverage and package provenance gate.
- Recovery amendment: unarmed interrupted work is `Failed` and
  `NotDispatched`; armed interrupted work is `Unknown` and
  `DispatchUncertain`; neither is retried. A complete identity-verified orphan
  may be attached to the unknown recovery outcome. Incomplete staging is
  quarantined and is never complete output.
- Public repository: `jimtin/HostHunterNextGeneration`, public read/fork/PR,
  owner-only direct write/merge/admin/integration authority, GitHub Actions
  disabled.
- Non-goals: positive WinRM, legacy JSON/JSONL import, shared/cloud database,
  automatic evidence retention/pruning, hosted GitHub validation, or automatic
  execution of external contributions.

## Acceptance Ledger

| ID | Requirement | Intended change | Focused evidence | Status | Deferred/non-goal |
| --- | --- | --- | --- | --- | --- |
| RC-01 | Trustworthy four-metric coverage | repair loop/try correlation and concurrent branch-event capture; add meaningful high-risk branch tests | golden coverage fixtures, focused instrumented tests, raw product coverage with all metrics >=90 | verified working tree; 544 tests green and all four metrics pass after final ACL amendment | no threshold reduction or runtime exclusion; 92% is preferred buffer, not the hard contract |
| RC-02 | Durable `.hhout` publication | first-party durability helper, PowerShell wrapper, stable pre/post-rename states, wrapped-I/O normalization | .NET helper units; artifact units; Linux container plus native macOS/Windows publication proof | implemented; Linux/macOS green, exact Windows pending | no runtime compilation or new third-party dependency |
| RC-03 | Evidence-honest recovery | correct unarmed/armed terminal states and verified orphan attachment | recovery unit matrix and process-kill integration | verified working tree | no remote retry |
| RC-04 | Concurrency and storage faults | bounded operation/writer contention, WAL crash, reservation and external mid-command full-volume faults, DB/anchor fault matrix | package-import multi-process SQLite integration receipt | verified working tree, 9/9 scenarios | no network filesystem support |
| RC-05 | Complete public action coverage | reconcile package journeys and add empty, preview, refusal, query, paging, tamper, recovery, capacity, and spaced-root actions | fresh-process package E2E plus integration mapping | focused working tree verified, 23/23 plus fault matrix; exact rerun pending | positive 5.1 belongs to live Windows lane; positive WinRM deferred |
| RC-06 | Deterministic secret proof | candidate-file snapshot scan, force-tracked ignored detection, bounded tree/history scans | scanner contract fixtures plus working-tree and exact-history Gitleaks JSON | implemented and working-tree contract green; exact history pending commit | ignored untracked runtime evidence is not scanned as source |
| RC-07 | Candidate-independent gate | clean detached exact-SHA runner plus separate local manual controller | exact tree/package hash and full product receipt | implemented; candidate execution pending | no automatic PR execution |
| RC-08 | Native qualification | same package archive on macOS and Windows; Keychain/anchor, RID/ACL, PS7, Windows PowerShell 5.1, mixed runtime, protected-key transition, run-scoped agent proof, and exact cleanup | redacted native receipts bound to candidate and package SHA-256 | focused qualification contract tests green; exact candidate execution pending | WinRM deferred |
| RC-09 | Owner-only publication | private-first repository hardening, exact push, public-last visibility, settings re-read | remote SHA, visibility, Actions, permissions, rules, hooks, keys and integration receipt | pending | public users may fork or propose pull requests |
| RC-10 | Accurate public documentation and threat model | reconcile implemented state, current receipts, action/critical matrices, residual risks and release policy | static documentation gate and threat-model report checker | documentation reconciled; static and final threat review pending | historical receipts remain labelled historical |

## User-Action Coverage Groups

The detailed matrix remains
`docs/testing/e2e-workflow-inventory.md`. Implementation must close these
groups before the candidate gate:

1. Package import/help and all eleven exported commands.
2. Target preview, empty read/test, add/replace/remove, filtering, limits,
  unavailable-key display, and mutation/dispatch refusal.
3. Command selection, one-to-eight dispatch, optional context, exact command,
  complete stream retrieval, failure-before-intent and no-retry states.
4. Audit empty/default/bounded/cursor/filter/pending/complete-command/output
  queries with read-only head stability.
5. Tamper, legacy state, unsupported schema, rollback, operation busy,
  insufficient capacity, external disk full, and crash recovery.
6. Positive direct PowerShell 7 in the container fixture and positive
  WindowsPowerShell51/mixed-runtime/key-transition qualification on the exact
  live Windows package. The live key journey separately proves initial key-only
  transition, an agent-backed follow-up command, preserved password recovery,
  exact agent/key removal, and stopped-agent cleanup.
7. Negative WinRM with no network or persistence mutation.

## Test Ledger

| Slice | Production/test ownership | Cheapest proof before integration | Candidate proof |
| --- | --- | --- | --- |
| Coverage collector | `scripts/coverage/**`, `tests/coverage/**` | fixture spike, semantic equivalence, concurrent-writer negative | product unit four-metric lane |
| Durability | `eng/durability/**`, artifact wrapper/writer and focused tests | helper units and artifact fault units | package scan plus native OS receipts |
| Recovery/fault | recovery source, SQLite fault workers/integration | recovery units and individual process cases | full SQLite integration lane |
| CLI actions | public E2E and action inventory | filtered fresh-process journey groups | complete package E2E lane |
| Security/release | secret scanner fixtures, candidate runner and controller | scanner contract and clean-worktree negatives | exact tree/history/package/full-gate receipt |
| Native qualification | macOS/Windows qualification scripts and focused contract tests | non-inquiring six-stream command, exact Keychain deletion/post-check, protected-key and run-scoped-agent lifecycle | exact package receipts on both native platforms |

## Parallel Work

- Coverage worker: exclusive ownership of `scripts/coverage/**` and
  `tests/coverage/**`.
- Durability worker: exclusive ownership of `eng/durability/**`, the durability
  PowerShell wrapper, `AuditArtifactV2.ps1`, its focused tests, and explicitly
  assigned package wiring.
- Recovery worker: exclusive ownership of `AuditRecovery.ps1`, recovery tests,
  and new SQLite process/fault fixtures and lane.
- Main agent: shared module/package integration, public E2E, security/release
  scripts, documentation, final threat model, exact candidate, native
  qualification, and publication.

Workers do not revert concurrent changes or edit another lane's files. Shared
build, Compose, module-loader, documentation, and release files remain main
integration surfaces unless explicitly reassigned.

## Gate Order

1. Each slice passes ordinary and instrumented focused tests.
2. The action and critical-path matrices contain no unexplained `missing`,
  `stale`, or `partial` release row.
3. Test-readiness preflight clears predictable blockers.
4. The fast commit hook creates the candidate commit.
5. The standalone gate runs the full product proof once on that exact SHA.
6. Native macOS and Windows proof use the exact package hash.
7. Publication and post-mutation settings verification occur last.

Any source edit after step 4 creates a new candidate and invalidates steps 5
through 7.
