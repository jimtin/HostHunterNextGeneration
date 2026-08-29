# Deleted coverage surface inventory

Status: confirmed cutover checklist for the fast test contract authorized on
2026-08-29.

This inventory records the superseded coverage machinery and the required
post-cutover sweep. It is not permission to remove product source or to exclude
active source from the coverage denominator.

## Rewrite in place

| Path | Required replacement |
| --- | --- |
| `scripts/coverage/Invoke-HHUnitCoverage.ps1` | Sole standard-profiler entrypoint with one terminal summary |
| `scripts/lanes/unit.sh` | Thin release-only wrapper; no orchestration or retry |

## Remove after replacement contract passes

| Superseded surface | Incoming references observed before cutover |
| --- | --- |
| `scripts/coverage/Instrument-HHBranches.ps1` | custom AST branch collector and its contract test |
| `tests/coverage/fixtures/BranchFixture.ps1` | custom AST collector fixture |
| `scripts/coverage/Prepare-HHInstrumentedModule.ps1` | `tests/coverage/Invoke-ProductCoverage.ps1` |
| `scripts/coverage/Test-HHBranchCoverage.ps1` | branch spike, integrity self-test, and product coverage scripts |
| `scripts/coverage/Test-HHCoverageThresholds.ps1` | old unit coverage and threshold self-test scripts |
| `scripts/lanes/coverage-spike.sh` | standalone branch-spike entrypoint |
| `tests/coverage/BranchFixture.Tests.ps1` | old golden branch fixture |
| `tests/coverage/Invoke-BranchCoverageSpike.ps1` | `scripts/lanes/unit.sh` and the spike wrapper |
| `tests/coverage/Invoke-CoverageIntegritySelfTest.ps1` | branch spike only |
| `tests/coverage/Invoke-CoverageThresholdSelfTest.ps1` | `scripts/lanes/unit.sh` only |
| `tests/coverage/Invoke-ProductCoverage.ps1` | `scripts/lanes/unit.sh` only |
| `tests/coverage/fixtures/BranchFixture.expected.json` | old branch fixture tests |
| `tests/coverage/fixtures/BranchFixture.metrics.expected.json` | old unit-lane fixture gate |
| `tests/coverage/fixtures/BranchFixture.ps1` | old branch fixture tests |
| `tests/coverage/fixtures/EarlyControlFixture.ps1` | old integrity self-test |
| `tests/coverage/fixtures/thresholds/*.json` | old threshold self-test |

`tests/coverage/artifact-cleanup-contract.sh` is not classified for deletion. It
must be retained or updated if it still proves the new four-artifact cleanup
contract.

## Obsolete identifiers and behavior

The cutover is incomplete while an active script, test, hook, container file, or
environment example still relies on any of these:

- `HH_BRANCH_LOG`;
- `Invoke-HHBranchProbe` or `HH_BRANCH_COVERAGE`;
- compact branch shards, marker files, per-shard checksums, or shard merging;
- coverage workers or custom child collectors;
- per-hit mutex acquisition, artifact-directory scans, JSON rewrites, hashing,
  or atomic moves;
- `coverage-spike` artifacts or entrypoints;
- `Invoke-ProductCoverage.ps1` as an intermediate orchestrator;
- the migration integration test contributing to the unit-coverage numerator;
- any SSH, Windows, SQLite service, or eleven-cmdlet journey dependency in the
  coverage command; or
- any custom AST source rewrite, numerical synthetic branch threshold, retry,
  or second diagnostic coverage invocation for one SHA.

Historical planning text may name the removed machinery when it clearly explains
why it was replaced. The confirmed release coverage plan may retain the deleted
path list as a migration record. Neither is an executable reference.

## Required post-cutover sweep

Run a repository-wide search and classify every match:

```sh
rg -n --hidden --glob '!.git/**' \
  'HH_BRANCH_LOG|Invoke-HHBranchProbe|HH_BRANCH_COVERAGE|Instrument-HHBranches|compact branch shard|coverage[-_ ]?worker|coverage-spike|Invoke-ProductCoverage|Prepare-HHInstrumentedModule|Test-HHBranchCoverage|Test-HHCoverageThresholds'
```

Permitted results are limited to:

1. this deletion inventory;
2. the confirmed migration plan; and
3. historical explanatory prose that cannot be mistaken for an active command.

All executable references are defects. The final sweep must also prove that no
branch-probe function or instrumentation token exists in the packaged module or
production image.
