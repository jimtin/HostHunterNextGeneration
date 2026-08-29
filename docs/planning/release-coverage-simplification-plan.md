# Release Coverage Simplification Plan

Status: SUPERSEDED by the confirmed fast test contract on 2026-08-29.

The earlier custom four-metric AST collector was rejected because it expanded
the test framework, exceeded its runtime budget, and could not yet measure
PowerShell short-circuit, loop, catch, and duplicate-source decisions with the
required semantic integrity.

The authoritative implementation plan is
`docs/planning/hosthunter-fast-test-contract.md`.

## Retained release contract

- Coverage remains release-only and runs once for an exact SHA.
- Every shipped module and native-client PowerShell source file is included.
- Standard native evidence must reach at least 90 percent for statements,
  executable lines, and invoked functions, with a 92 percent engineering target.
- Named behavioral tests cover public validation, authentication choices,
  dispatch outcomes, SQLite mutations, and recovery branches.
- Test failures, missing files, zero denominators, malformed results, timeout,
  and interruption fail closed with a terminal receipt.
- Coverage never changes or obscures cmdlet, Windows, persistence, build, or
  security verdicts.

## Removed design

The following concepts are superseded and must not return to executable code:

- custom AST branch rewriting or probe functions;
- a synthetic numerical PowerShell branch-percentage gate;
- instrumented source copies;
- branch shards, workers, mutexes, checksums, or per-hit disk writes;
- repeated diagnostic coverage passes;
- SSH, SQLite integration, live Windows, or cmdlet evidence in the coverage
  numerator; and
- automatic retry of a failed, interrupted, or timed-out coverage run.

## Completion evidence

Implementation is complete when the focused coverage contract tests pass, the
deleted-surface sweep has no active custom-instrumentation references, the
release receipt validates native metrics independently, and one future exact-SHA
release proof executes the coverage phase once.
