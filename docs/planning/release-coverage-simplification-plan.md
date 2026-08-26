# Release Coverage Simplification Plan

Status: CONFIRMED — implementation authorized 2026-08-26

## Goal

Replace the release-only coverage framework with one bounded container command
that preserves genuine coverage of every shipped PowerShell source file while
removing the orchestration and per-hit persistence responsible for repeated,
long-running test loops.

The release contract remains at least 90 percent independently for statements,
branches, functions, and lines. The engineering target is 92 percent or more.

## Confirmed decisions

1. Preserve genuine branch-outcome coverage with two fixed unit passes inside
  one PowerShell runner. Do not redefine command hits as branch coverage.
2. Coverage accounting is unit-only and includes every shipped production
  `.ps1` and `.psm1` file. Integration and live-Windows evidence remain
  separate and cannot increase unit coverage.
3. Every independent exact-SHA release phase runs at most once and produces a
  terminal result. Windows qualification runs before coverage, so coverage
  can never obscure the cmdlet or Windows verdict.

## Required behavior

One isolated test container runs one PowerShell process with exactly two
sequential Pester invocations:

1. **Untouched-source pass** — Pester's native profiler measures executable
  statements and lines. Function ownership is derived from the original AST
  and the profiler's executed points.
2. **Branch-outcome pass** — the same unit tests run against an ephemeral copy
  instrumented only for explicit branch outcomes. Hits are held in memory and
  flushed once after the pass.

The branch pass preserves the existing outcome semantics for the control-flow
families used by production source: `if`, `switch`, `for`, `foreach`, `while`,
and `try/catch`. A newly introduced unsupported decision construct fails
closed.

The lane has no SSH fixture, Windows host, database service, integration suite,
worker pool, shards, nested PowerShell process, per-hit files, named mutex,
checksum protocol, persisted instrumented tree, or automatic retry.

## Metric contract

| Metric | Definition |
| --- | --- |
| Statements | Executable source commands reported by native Pester coverage |
| Lines | Unique executable source lines reached |
| Functions | AST-discovered functions with an owned executable point reached |
| Branches | Explicit true/false or entered/not-entered outcomes recorded by the branch pass |

Each metric must have a non-zero denominator and independently meet the
90-percent threshold. Test failures fail the lane regardless of percentages.
There are no production-source exclusions. The source inventory is discovered
from the exact candidate tree rather than hard-coded.

## Prune classification

### Active — retain

- Pester 6.1 native profiling and the unit suite.
- The four independent coverage thresholds.
- The bounded-runner timeout owner.
- Exact-SHA release state and historical immutable receipts.
- `coverage-summary.json` as the compatibility receipt path.
- Critical SQLite integration and live-Windows qualification as separate lanes.

### Active behavior with superseded implementation — rewrite

- `scripts/coverage/Invoke-HHUnitCoverage.ps1`
- `scripts/coverage/Instrument-HHBranches.ps1`
- `scripts/lanes/unit.sh`

### Superseded or dead — delete after replacement tests exist

```text
scripts/coverage/Prepare-HHInstrumentedModule.ps1
scripts/coverage/Test-HHBranchCoverage.ps1
scripts/coverage/Test-HHCoverageThresholds.ps1
scripts/lanes/coverage-spike.sh
tests/coverage/BranchFixture.Tests.ps1
tests/coverage/Invoke-BranchCoverageSpike.ps1
tests/coverage/Invoke-CoverageIntegritySelfTest.ps1
tests/coverage/Invoke-CoverageThresholdSelfTest.ps1
tests/coverage/Invoke-ProductCoverage.ps1
tests/coverage/fixtures/BranchFixture.expected.json
tests/coverage/fixtures/BranchFixture.metrics.expected.json
tests/coverage/fixtures/BranchFixture.ps1
tests/coverage/fixtures/EarlyControlFixture.ps1
tests/coverage/fixtures/thresholds/all-pass.json
tests/coverage/fixtures/thresholds/branches-below.json
tests/coverage/fixtures/thresholds/functions-below.json
tests/coverage/fixtures/thresholds/lines-below.json
tests/coverage/fixtures/thresholds/missing-functions.json
tests/coverage/fixtures/thresholds/statements-below.json
tests/coverage/fixtures/thresholds/zero-statements.json
```

Replace these with one compact branch fixture and one normal unit contract that
covers supported decisions, unsupported-syntax failure, zero denominators, and
each independent threshold failure.

## Coverage-gap closure

The retained failing receipt reports 2,343 of 2,703 branch outcomes covered
(86.6815 percent), with 360 misses. Classify each miss as active, dead, or
unknown. Add meaningful tests for active paths, investigate unknown paths, and
prune proven-dead production logic only as a separately reviewed product
change. Never use exclusions, integration results, live-host results, historical
receipts, or shallow percentage-only tests to close the gap.

Target enough meaningful branch coverage to exceed 92 percent before relying
on the exact-SHA result. The full product coverage lane remains release-only;
development runs use the compact collector fixture and focused changed-scope
tests rather than duplicating the release proof.

## Artifacts and terminal states

The lane emits only:

```text
unit-tests.xml
coverage.xml
coverage-summary.json
coverage.log
```

The atomic summary records the candidate SHA and tree, source inventory and
hash, collector and Pester versions, test totals, duration, all four
covered/total/percentage/deficit values, and the complete uncovered-location
list. Terminal statuses are `passed`, `test_failed`, `threshold_failed`,
`tooling_blocked`, `timeout`, or `aborted`. The outer wrapper writes a fallback
terminal receipt if the runner is interrupted.

The normal runtime target is below 180 seconds. The hard timeout is 300 seconds
with a 120-second stall limit. There are no retries.

## Exact-SHA release flow

```text
read-only preflight
        -> atomic claim
        -> build exact images once
        -> 11-cmdlet verifier
        -> live-Windows qualification
        -> simplified coverage
        -> critical integration
        -> security scans
        -> read-only aggregate receipt
```

Independent phases continue once after an independent failure so one candidate
produces a complete diagnostic. Only genuine dependencies can produce
`not_run_due_to_<dependency>`. A build failure blocks image consumers; a cmdlet
failure blocks Windows qualification. Coverage does not block integration or
security, and Windows does not block coverage. The cmdlet and Windows receipts
remain independent. A consumed SHA is never rerun; fixes require a new SHA.

## Implementation sequence

1. Add the compact collector fixture and replacement in-memory branch engine.
2. Add the untouched-source native profiler pass and direct four-metric check.
3. Collapse `scripts/lanes/unit.sh` to the single bounded runner.
4. Add meaningful unit tests for the existing active uncovered branches.
5. Change release ordering and terminal receipt handling without changing the
  cmdlet receipt.
6. Delete the superseded coverage framework and sweep code, tests, fixtures,
  docs, environment variables, and cleanup rules for stale references.
7. Update the repository testing contract, tooling matrix, adoption/testing
  documentation, and existing threat model.
8. Run focused container checks only during development. Do not run the full
  product coverage program as a duplicate pre-push proof.
9. Run the required changed-scope threat review, dependency audit, and
  containerized gitleaks check.
10. Push one clean candidate SHA and let the standalone release gate execute
    the complete proof exactly once.

## Acceptance and test ledger

| Requirement | Implementation | Focused evidence before release | Status |
| --- | --- | --- | --- |
| Honest four-metric coverage | Native source pass plus explicit branch-outcome pass | Compact collector contract and parser/static checks | Verified |
| Radical runtime simplification | One container, one `pwsh`, two Pester invocations, in-memory hits | Process/receipt contract test and bounded focused run | Verified |
| Unit-only numerator | Remove migration/integration closure from coverage entrypoint | Negative contract asserting integration paths are absent | Verified |
| Every shipped source file counted | Exact-tree inventory and source hash in summary | Inventory mismatch and zero-denominator negative tests | Verified |
| At least 90 percent each; 92-percent target | Direct independent threshold evaluation and meaningful branch tests | Each-metric threshold fixture plus focused subsystem tests | Implemented; exact-SHA measurement pending |
| Cmdlet and Windows verdicts remain visible | Windows precedes coverage; independent immutable component receipts | Release orchestration contract tests | Verified |
| No retry or diagnostic rerun | Terminal receipt includes all deficits and uncovered locations | Failure, timeout, interruption, and duplicate-attempt tests | Verified |
| Superseded coverage surface removed | Delete classified scripts, fixtures, env references, and docs | Deleted-surface `rg` sweep and static checks | Verified |
| Security trust boundaries retained | Read-only exact-SHA input, receipt binding, no production probes | Threat-model update, package probe scan, gitleaks | Implemented; pre-push gitleaks pending |
| Exact-SHA release proof | Standalone gate consumes one clean candidate once | Final component and aggregate receipts | Pending |

Non-goals are changes to the eleven cmdlets, managed-host engine, authenticated
SQLite, encryption, audit artifacts, anchors, recovery behavior, or public
runtime semantics. Critical integration and live-Windows qualification remain
required but do not participate in the unit-coverage numerator.

## Security controls

Bind coverage to a clean exact SHA, mount candidate source read-only, inventory
and hash every production source file, write atomic receipts, reject zero or
missing denominators, independently validate all four thresholds, and prove no
instrumentation token exists in the packaged module or production image.

Update the existing threat model for stale receipt reuse, source omission,
threshold weakening, instrumentation leakage, partial receipt acceptance, and
coverage obscuring user-facing verdicts.

## Parallel work

- Coverage worker: branch transformer, in-memory collector, compact fixture,
  and coverage-runner tests.
- Test worker: meaningful unit tests for uncovered active branches only.
- Documentation worker: testing documents and deleted-surface inventory.
- Main agent: integration, release ordering and receipts, threat model,
  gitleaks, final validation, and exact-SHA handoff.

Workers have disjoint write ownership and must not revert or overwrite other
work in the shared tree.

## Rollback

The coverage cutover does not change production runtime behavior. Rollback is a
revert of the coherent testing-infrastructure change. Do not retain the old
collector as a runtime fallback. Historical receipts remain untouched, and a
failed exact SHA remains consumed.

## Definition of done

- Statements, branches, functions, and lines each meet or exceed 90 percent.
- The engineering result reaches at least 92 percent through meaningful tests.
- Every shipped production PowerShell source file is counted.
- Coverage is unit-only and integration cannot change its numerator.
- One container, one runner process, and exactly two Pester invocations.
- Normal runtime is under 180 seconds and cannot exceed 300 seconds.
- There is no per-hit disk I/O, sharding, worker fan-out, or retry behavior.
- A failed lane reports every uncovered location without a diagnostic rerun.
- The cmdlet and Windows verdicts remain independently visible.
- Superseded coverage files and stale references are removed.
- Required focused checks, threat review, dependency audit, gitleaks, and
  exact-SHA release proof are complete.
