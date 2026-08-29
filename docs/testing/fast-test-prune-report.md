# Fast Test Prune Report

Status: implemented and focused-verified

## Summary

- Goal: replace overlapping broad test orchestration with one fast development
  stack and one once-per-SHA release stack.
- Replacement path: focused tests, one unit smoke, one 12-cmdlet/SQLite journey,
  impact-selected native macOS proof, and independent release-only components.
- Old path: custom AST branch coverage, duplicated hook builds/suites, broad SSH
  integration after cmdlet acceptance, and combined heavy receipts.
- Recommendation: remove the superseded orchestration progressively while
  retaining authenticated SQLite, managed-host, Windows, and security proof.
- Residual unknowns: actual full native-profiler duration and percentage remain
  release-candidate evidence; they are not measured during implementation.

## Behavior and Ownership Map

| Behavior | Live entrypoint | Current path | Owner | Existing proof | Missing proof |
| --- | --- | --- | --- | --- | --- |
| Focused unit iteration | `scripts/lanes/focused-unit.sh` | one test container/Pester selection | test runner | 44/44 in 2.28 seconds | none |
| Ordinary unit verdict | `scripts/lanes/unit.sh smoke` | one Pester invocation | test runner | 672/672 in 21.48 seconds | none |
| Cmdlet and SQLite verdict | `scripts/verify-cmdlets.sh` | production-derived verifier + SSH fixture | cmdlet runner | 12/12; SQLite integrity `ok` | exact-SHA reuse at release |
| Native coverage | `scripts/lanes/unit.sh coverage` | standard Pester profiler | release proof | collector contracts | future exact-SHA result |
| Windows proof | `scripts/qualification/windows-cmdlets.sh` | saved-key exact-image journey | release gate | qualification contracts | future exact-SHA live result |
| SQLite recovery | `scripts/lanes/sqlite-integration.sh` | focused fault tests | release proof | existing integration tests | one future exact-SHA result |
| Release finality | `scripts/release/verify-candidate.sh` | immutable component receipts | laptop gate | receipt contracts | future exact-SHA result |

## Removal Candidates

| Candidate | Classification | Evidence | Risk | Required proof | Action |
| --- | --- | --- | --- | --- | --- |
| `scripts/coverage/Instrument-HHBranches.ps1` | superseded | only served rejected synthetic branch collector | medium | native coverage contracts and behavioral branch inventory | remove |
| `tests/coverage/fixtures/BranchFixture.ps1` | superseded | only tested removed transformer | low | replacement collector contract | remove |
| `tests/unit/CoverageCollectorContract.Tests.ps1` | superseded | asserted removed AST design | low | native coverage contract | replace |
| `scripts/lanes/unit-smoke.sh` implementation | superseded | duplicated Pester setup | low | delegation to `unit.sh smoke` | collapse |
| pre-commit image build/full smoke | superseded | duplicated release-owned build and exceeded hook budget | medium | hook allow/deny contract | remove |
| pre-push build/toolchain/module/SSH/general integration | superseded | repeated exact-SHA and cmdlet proof | medium | unit smoke plus cmdlet journey contracts | remove |
| broad `release-critical-integration` | superseded | SSH and lifecycle already proven by cmdlet/native/Windows journeys | medium | retained focused SQLite recovery suite | remove from release graph |
| authenticated SQLite, encryption, anchors, audit, recovery | active | reachable from every cmdlet persistence path | high | existing unit/integration/cmdlet proof | retain |
| managed-host engine and boundary guard | active | exclusive controller-to-host path | high | AST and delegation tests | retain |
| Windows qualification | active | only positive proof for Windows-only policy behavior | high | focused contracts and future live exact-SHA proof | retain release-only |
| artifact cleanup contract | compatibility | protects immutable consumed-SHA receipts | medium | cleanup contract | retain/update |

## Progressive Removal Log

| Layer | Scope | Change | Targeted evidence | Security impact | Rollback |
| --- | --- | --- | --- | --- | --- |
| 1 | dirty experiment | external backup and clean `31d6baa` restore | checksum, inventory, clean status | prevents stale candidate proof | external patch bundle |
| 2 | coverage | native three-metric collector; remove AST path | focused native coverage contracts | removes source-rewrite attack surface | restore owned files from backup only |
| 3 | hooks | slim pre-commit/pre-push graph | hook negative contracts | reduces repeated privileged Docker work | restore previous wrappers |
| 4 | release | independent component receipts and bounded phases | release receipt contracts | prevents verdict suppression/replay | revert coherent release slice |
| 5 | Windows/package | least-privilege volume clone and exact asset allowlist | Windows/provider contracts | reduces credential-copy and package-tamper risk | revert coherent qualification slice |

## Implementation Evidence

- Combined focused contracts: 44 passed, 0 failed, 2.28 seconds.
- Static/governance lane: passed once in 10.3 seconds.
- Ordinary unit smoke: 672 passed, 0 failed, one Pester invocation in 21.48
  seconds.
- macOS client synchronization: the normal import path rebuilt and replaced the
  stale controller once; no test runner performed a build.
- Cmdlet/SQLite acceptance: 12 unique cmdlets passed on the first invocation;
  SQLite integrity was `ok`, persisted state was read back in fresh processes,
  and target cleanup retained audit history.
- Threat-model report checker: passed.
- Deleted-surface sweep: remaining custom-AST wording is documentation or an
  explicit negative assertion; no active executable entrypoint remains.

Release-only coverage, security/image scans, production build proof, focused
SQLite fault proof, and positive live-Windows qualification were deliberately
not run during implementation. They remain independent, once-per-exact-SHA
release components.
