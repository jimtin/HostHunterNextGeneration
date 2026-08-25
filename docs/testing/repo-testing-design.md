# Repository Testing Design

## 1. Status

**ADOPTED DOCKER RUNTIME; EXACT-CANDIDATE AND LIVE WINDOWS
QUALIFICATION PENDING 2026-08-26**

The user explicitly confirmed this design on 2026-08-23. The testing foundation
and dual-runtime product slice are implemented. The canonical working-tree gate
passed on 2026-08-24 as the pre-migration baseline. The user confirmed the
SQLite product direction and the material `.hhout` v2 and recovery amendments
on 2026-08-24. The canonical runtime is now the hardened Docker controller and
networkless parser sidecar. Focused runtime/provider/lifecycle validation is
green; one exact-candidate proof remains pending. Exact-commit proof and positive live Windows
PowerShell 5.1 qualification remain separate release lanes. WinRM is explicitly
deferred and rejected in v1.

## 2. Inputs Consumed

- Shared Understanding Contract:
  `docs/planning/shared-understanding-contract.md` (confirmed 2026-08-23).
- Dual-Runtime SSH and Public Release Plan:
  `docs/planning/dual-runtime-winrm-release-plan.md` (confirmed 2026-08-24).
- SQLite Persistence Shared Understanding Contract:
  `docs/planning/sqlite-persistence-plan.md` (amended contract confirmed
  2026-08-24).
- Feature readiness: ready for SSH. Direct PowerShell 7 is the default and
  Windows PowerShell 5.1 is an explicit Windows-target compatibility path.
  WinRM is a deferred non-goal until the user creates a controlled lab.
- Repo truth: PowerShell 7 module with eleven implemented public cmdlets,
  containerized validation, installed local
  hooks, and no hosted test workflow or deployment. Publication remains pending.
- Controller evidence: Docker/Linux uses supported PowerShell-over-SSH. The
  Windows PowerShell 5.1 compatibility session runs on the remote Windows host,
  not on the controller. Native macOS remains optional compatibility evidence.

## 3. Gap Map

| Area | Current state | Target |
|---|---|---|
| Production runtime | focused implementation green | Non-root Docker controller plus networkless parser, six external volumes, no host credential-store dependency |
| Unit lane | adopted | Containerized Pester plus a proven four-metric coverage gate |
| Integration lane | adopted | Real Compose PowerShell-over-SSH target plus deterministic seams |
| Space-containing SSH data root | working-tree focused proof complete; exact runtime pending | Real password, command, wrong-pin, restart, and key-auth paths under `Library/Application Support`; no space-free substitute |
| Browser/E2E lane | not-applicable | Black-box CLI/service journeys are the equivalent E2E layer |
| Production build/build smoke | adopted | Manifest/package smoke and exact export contract |
| Static checks lane | adopted | PowerShell, Markdown, shell, YAML, Dockerfile, and EditorConfig checks |
| Canonical verify command | adopted | `./scripts/verify-local.sh` |
| Fast pre-commit lane | adopted | `./scripts/precommit.sh` |
| Hook enforcement | adopted | Checked-in `.githooks`, install and active verification |
| Secret scanning | adopted | Repo-root-only, read-only, containerized gitleaks |
| Dependency/vulnerability audits | adopted | OSV-Scanner, Trivy filesystem and image scans, pinned module inventory |
| Provider stubs and fakes | adopted | Deterministic SSH/runtime, audit, clock, filesystem, and key seams; WinRM fail-closed seam only |
| SQLite persistence | adopted | Real bundled provider, checksummed initial schema, writer/operation-lock concurrency, crash, rollback, capacity, output-v2, and query proof |
| Native database packaging | adopted; exact OS run pending | Locked managed/native assets and executable smoke for every claimed controller RID |
| Test data, seeds, resets | adopted | Run-scoped stores, keys, known-hosts, ledgers, and cleanup |
| Deployment branch policy | not-applicable | Module has no runtime deployment; gate-owned branch/release policy applies |
| Bounded runners/artifacts | adopted | Timeouts, heartbeat, stall detection, ignored `.artifacts/` tree |
| Tool/runner version policy | adopted | Exact versions plus immutable image digests/checksums |
| Flake/quarantine policy | adopted | No retries; time-boxed quarantine cannot guard a release |
| Agent contract/inventories | adopted | Repo-local `AGENTS.md` and checked-in inventories |

## 4. Tool Matrix

The implemented full matrix is in `docs/testing/tooling-matrix.md`. Tool and
scanner images use reviewed immutable digests or checksum-verified packages.

## 5. Test Layers and Coverage

### Unit

Pester runs inside the pinned PowerShell test image. Repository-wide coverage
must be at least 90% for statements, branches, functions, and executable lines;
new or materially changed modules target at least 95% for all four.

Pester command coverage alone does not prove four independent metrics. It can
support executable-statement and line aggregation, and PowerShell's AST can
enumerate functions, but Pester does not provide genuine branch outcomes.

The adopted coverage collector proves true decision outcomes against golden
fixtures covering `if`/`elseif`/implicit and explicit `else`, `switch`, loops,
ternary and short-circuit operators, `try`/multiple `catch`/`finally`, early
control flow, nested scriptblocks, and class methods. It self-tests uncovered
outcomes and fails independently for statements, branches, functions, and
lines. Source instrumentation runs only in an isolated copy and has
semantic-equivalence tests against the uninstrumented module. An
`explicit_branch_arm_coverage` approximation is not relabelled as standard
branch coverage, and thresholds are not approximated or lowered.

The current 2026-08-25 readiness receipt is 647/647 product tests with
95.3557% statements (7761/8139), 90.0669% branches (2557/2839), 96.3504%
functions (264/274), and 95.3931% lines (6419/6729). The branch phase includes
the authenticated SQLite migration integration so migration control flow is
measured by the same integrity-checked branch collector.

Design evidence: [Pester documents command coverage rather than behavioral or
branch completeness](https://pester.dev/tutorial/code-coverage/measuring), while
PowerShell's supported
[`Parser.ParseFile`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.language.parser.parsefile)
and [`Ast.FindAll`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.language.ast.findall)
APIs provide the source-model basis for the feasibility spike.

### Integration

The inventory in `docs/testing/critical-path-inventory.md` is authoritative.
Transport and runtime interfaces use deterministic fakes for every failure
class. A Compose service provides a real OpenSSH server configured with a
PowerShell 7 subsystem for direct protocol integration and negative
`WindowsPowerShell51` availability evidence. Test-only PTY automation may drive
the native password prompt; no prompt automation is shipped in product code.

At least one real transport and key-bootstrap journey must place the managed
`known_hosts`, key, database, and output roots beneath a directory named
`Library/Application Support`. It must prove that only a unique per-session
environment reference crosses the SSH option boundary, that the exact canonical
path exists only in process environment during the synchronous open, and that
the environment is restored on success and failure. The journey also verifies
strict wrong-pin refusal with global known-hosts fallback and host-key updates
disabled. Space-free `/tmp` roots are insufficient evidence for this path.

The Linux fixture cannot positively host Windows PowerShell 5.1. Unit and
integration seams prove bridge planning, identity checks, ordered envelope
classification, cleanup, no fallback, limits, and fan-out attribution. A
separate live Windows lane must prove positive Desktop 5.1 and mixed-runtime
execution against the exact candidate archive and hash.

SQLite integration adds clean construction from the committed initial migration,
multi-process WAL/busy handling, exact-record target CAS, writer/operation-lock
ownership, monotonic database/anchor serialization, operation arming,
identity-bound streaming output, capacity/backpressure, DB/artifact fault
boundaries, corruption/rollback detection, and proof that persistence failure
never causes a remote retry or false recovery of a live batch.

### CLI E2E equivalent

There is no browser surface, so Playwright is not applicable. Fresh
`pwsh -NoProfile` processes import the generated package through
`HH_TEST_MODULE_PATH` and exercise every public cmdlet, persisted state across
processes, all eleven confirmed public cmdlets, default and explicit runtime selection, two runtime profiles for one
endpoint, negative runtime availability, interactive password onboarding, key
conversion, full-stream output, multi-target fan-out, trust failures, deferred
WinRM, SQLite-only restart persistence, legacy/schema refusal, audit filtering,
cursor paging, pending/output retrieval, tamper refusal, `-WhatIf` no-root
behavior, operation-lock contention, and armed/unarmed recovery. The inventory is in
`docs/testing/e2e-workflow-inventory.md`.

### Build smoke

The build lane runs `Test-ModuleManifest`, packages the module into an isolated
artifact directory, imports that package in a clean container process, verifies
the eleven-command export contract, exact managed/native SQLite assets and
licenses, asserts `SELECT sqlite_version()`, creates the committed schema, and
executes a no-network help/smoke path on every claimed controller RID at the
patched PowerShell floors 7.4.19, 7.5.10, and 7.6.5. SSH-capable paths also
prove the OpenSSH 8.4+ expansion capability. Persistence integration and E2E
must import this package rather than the source module.

## 6. Stubs, Fakes, and Test Data

| Boundary | Deterministic decision |
|---|---|
| SSH transport | Interface fake for unit/error paths plus real Compose PowerShell 7 SSH target |
| Runtime bridge | Injected compatibility-session seams; positive Desktop 5.1 and mixed runtime use the exact-candidate live Windows lane |
| WinRM transport | Fail-closed interface seam only; no success simulation or first-release support claim |
| Credential prompt | Test-only PTY driver; passwords never enter product logs or target state |
| SSH agent/key store | Run-scoped fake agent and disposable key directory |
| Key and anchor provider | Real Docker-volume provider in canonical containers; optional disposable macOS Keychain compatibility lane |
| Audit sink | In-memory and SQLite adapter fakes plus real DB/operation-event/artifact/anchor fault integration |
| Clock/IDs/DNS | Injected deterministic clock, ID source, and resolver |
| Filesystem | Per-run database/WAL/SHM/writer/operation-lock, fallback key/anchor, known-hosts, reserved output, and recovery roots; legacy sentinels are negative fixtures only |

No live external provider participates in canonical proof. Windows SSH
qualification is explicit and exact-SHA, and supplements rather than replaces
the container gate. Every test run uses a unique namespace and cleanup trap.

## 7. Enforcement Model

**Gate-owned proof.** The HostHunter-specific standalone laptop gate must re-prove the exact
candidate SHA through `./scripts/release/verify-candidate.sh <sha>` from a clean
checkout before the first push. Developer pushes do not run the full suite.

Commands:

- Full: `./scripts/verify-local.sh`
- Pre-commit: `./scripts/precommit.sh`
- Slim pre-push: `./scripts/prepush.sh`
- Hook install: `./scripts/hooks-install.sh`
- Hook verification: `./scripts/hooks-verify.sh`

Pre-commit will run containerized static checks, repo-scoped gitleaks, and a
small deterministic unit smoke. Pre-push will run gitleaks, dependency audits,
static/governance checks, module contract checks, critical integration, and
critical CLI journeys. It will not duplicate the full coverage/build/image gate.

## 8. Security Setup

- Gitleaks scans only the resolved repository root mounted read-only and redacts
  findings.
- OSV-Scanner examines supported dependency/SBOM inputs.
- Trivy scans the repository filesystem and built test/runtime images.
- The ignored exact module package receives its own inventory, SBOM, hash,
  licence, OSV, and Trivy scan; a root scan that skips `.artifacts/` is not
  package evidence.
- The PowerShell dependency inventory is exact-version pinned and checked for
  drift because general scanners do not guarantee PowerShell Gallery coverage.
- Scanner images are pinned by tag and immutable digest before execution.
- The testing-foundation implementation receives a threat model covering hook
  execution, mounted paths, untrusted repository content, image provenance,
  report leakage, and command injection.

## 9. Deployment Policy and Remote CI Role

The module has no hosted runtime deployment. Branch classes are `dev/*` for
developer work and `main` for approved release candidates. GitHub stores public
source and review state only; no GitHub Actions workflow reruns local proof.
Release and merge are eligible only after standalone exact-SHA gate proof.

Only `jimtin` may push, merge, administer, or install repository-scoped
integrations. No collaborator or team receives write access in v1. Public forks
and pull requests do not grant write access or trusted execution. External
contribution code receives manual source review before any maintainer-laptop
command is run.

## 10. Bounded Runners and Artifacts

| Lane | Hard timeout | Stall threshold | Heartbeat | Planned artifact |
|---|---:|---:|---:|---|
| Static | 5 min | 2 min | 30 sec | `.artifacts/static/` |
| Unit/coverage | 12 min | 3 min | 30 sec | `.artifacts/coverage/`, `.artifacts/junit/` |
| Integration | 15 min | 4 min | 30 sec | `.artifacts/integration/`, `.artifacts/logs/` |
| CLI E2E | 20 min | 4 min | 30 sec | `.artifacts/e2e/` |
| Security | 20 min | 5 min | 30 sec | `.artifacts/security/` |
| Build/image | 10 min | 3 min | 30 sec | `.artifacts/build/` |
| SQLite fault/concurrency | 20 min | 4 min | 30 sec | `.artifacts/integration/sqlite/` |
| Native qualifications | 20 min | 4 min | 30 sec | `.artifacts/qualification/` |
| Exact candidate | 90 min | lane-specific | 30 sec | `.artifacts/release/<sha>/` |
| Full gate | 60 min | lane-specific | 30 sec | `.artifacts/summary/` |

Generated artifacts are ignored and must not modify tracked files. There is no
retry-until-green. A flake may be quarantined only with owner, issue, reason,
expiry no longer than 14 days, and exclusion from release-guarding lanes.

## 11. Agent Contract and Inventories

Repo-local `AGENTS.md` records the
canonical command, gate-owned model, container-only rule, four 90% coverage
thresholds, 95% changed-scope target, fake-provider policy, secret-scan wrapper,
artifact paths, and no-remote-CI rule.

The critical-path and CLI E2E inventories live under `docs/testing/` and are
updated in the same change as any affected feature.

## 12. Acceptance Ledger, Test Ledger, and Parallel Work

### Acceptance ledger

| Requirement | Intended change | Evidence | Status | Deferred/non-goal |
|---|---|---|---|---|
| Container-only proof | Test and tool images plus orchestration wrappers | Host wrapper inspection and container process evidence | verified | None |
| Four-metric 90% coverage | True branch-outcome collector plus AST/Pester aggregation | Golden fixtures, negative thresholds, product report | verified | No branch proxy or metric approximation |
| Critical integration | SSH target, runtime/transport/audit seams | Critical-path inventory plus live Windows receipt | 9/9 container/direct, negative, and deterministic bridge paths verified; live 5.1 pending | WinRM positive operation deferred |
| All CLI actions | Fresh-process service journeys | E2E action matrix | 23/23 SQLite package journeys verified; process/fault matrix verified; live 5.1 pending | Browser Playwright not applicable |
| Fast commit hook | Containerized fast lane | Hook install/verification and lane proof | verified | None |
| Slim push hook | Gate-owned slim lanes | Hook install/verification and lane proof | verified | Full gate remains standalone-owned |
| Security foundation | Gitleaks, OSV, Trivy, module pin audit | Clean local reports and seeded scope checks | verified | Semgrep not justified |
| Bounded execution | Timeout/heartbeat/stall wrapper | Foundation self-tests and lane execution | verified | None |
| Durable repo truth | Design, matrices, report, agent contract | File and command reconciliation | verified | None |
| Owner-only public repository | GitHub permissions, Actions disabled, external-code manual review | live settings re-read after push | pending | Public readers may fork or propose changes |
| SQLite persistence and audit query expansion | Reviewed database plan, eight CLI actions, package-only provider, operation ownership, output v2 and recovery model | updated critical/action matrices plus focused and working-tree requalification | verified working tree; exact candidate pending | no legacy importer, automatic prune, backup/restore, or WinRM |

### Test ledger

| Planned config/production file | Focused proof before next layer | Status |
|---|---|---|
| Test/tool Dockerfiles and Compose file | Build images and inspect pinned tool versions | verified |
| Coverage feasibility spike and gate | Golden decisions, semantic equivalence, negative thresholds, product metrics | verified |
| Canonical wrapper | Lane selection and failure propagation | verified |
| Hook wrappers/config | Install, verify, and controlled failures | verified |
| Security wrappers | Seeded canary and repo-root scope checks | verified |
| Fake services and SSH fixture | Deterministic ready/reset/failure states plus negative 5.1 availability | verified |
| Runtime schema and bridge | Schema migration, identity, streams, cleanup, no fallback, mixed fan-out | verified deterministically; live positive 5.1 pending |
| Live Windows qualification | Exact candidate direct 7, bridged 5.1, mixed batch, key transition | pending |
| SQLite provider and initial schema | Locked provider, package-only lazy resolver, clean `0001`, checksum/unknown-schema rejection | verified working tree on PS7.4 and PS7.6 |
| Target SQLite adapter | Exact target parity, exact-record CAS, new generation/state MAC, multi-process writes | verified |
| Audit SQLite adapter and anchor | Intent/operation/terminal transactions, HMAC projection binding, atomic platform anchor, live-owner-safe recovery | verified working tree; exact native anchor pending |
| Output v2 writer | Invocation-bound chunks/footer, durable publication, capacity reservation, streaming/backpressure | Linux and macOS verified; exact Windows pending |
| Audit query cmdlets | Exact types/parameters/errors, pending/cursor records, single-artifact ordered output | verified |
| Candidate/release runners | Package scan, clean-checkout SHA and production-image proof, Docker-controller live Windows qualification against the same package/image hashes | implemented; exact candidate execution pending |
| `AGENTS.md` | Documented commands reconciled to executable files | verified |

### Parallel Work

The main agent first owns and freezes the shared initial schema, connection and
transaction interfaces, writer/operation locks, crypto/output envelope, anchor,
errors, and fault seams. Only then may disjoint workers own: (1) locked provider
assets/package loader; (2) target repository/tests; and (3) audit/query/output
repository/tests. The main agent alone owns public-cmdlet rewiring, shared
configuration, E2E files, stale-test reconciliation, live qualification, threat
modelling, gitleaks, exact-candidate proof, and publication. Workers must not
edit the same files or revert concurrent changes.

## 13. Version and Currency Policy

Versions in the tooling matrix were checked against official sources on
2026-08-23. Execution resolves each container's multi-architecture manifest
digest and records it before first use; tags alone are not canonical pins.
Monthly maintenance checks official releases and updates manifests and digests
only through the full local gate. No floating `latest`, `stable`, `main`, or
mutable action references are allowed.

## 14. Exceptions and Deferred Items

| Item | Reason | Owner decision/follow-up |
|---|---|---|
| WinRM implementation and qualification | User requires a controlled lab for authentication, trust, and certificate policy | Reject WinRM in v1; plan and qualify separately when the lab exists |
| Positive Windows PowerShell 5.1 container fixture | Desktop 5.1 is Windows-only | Use deterministic seams plus an exact-candidate live Windows SSH lane |
| PowerShell branch coverage | Pester does not report branch outcomes | Isolated source instrumentation now records true outcomes and is self-tested against golden fixtures |
| Central audit collector | First release is a single-controller local ledger | Preserve pluggable sink boundary; threat model local admin limitation |
| Browser Playwright | No browser or GUI surface exists | Black-box PowerShell CLI journeys are the equivalent E2E layer |
| External pull-request execution | Public source changes are untrusted | Manual source review first; no GitHub Actions or automatic laptop execution |
