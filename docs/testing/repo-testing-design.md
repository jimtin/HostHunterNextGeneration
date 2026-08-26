# Repository testing design

Status: confirmed.

## Product boundary

The package exports exactly eleven PowerShell cmdlets. The canonical controller
is the production Linux container. Managed-host behavior uses PowerShell 7 over
OpenSSH through the single private managed-host engine. Authenticated SQLite,
encrypted evidence, anchors, tamper/rollback detection, and recovery are part of
the product and remain tested.

The supported operator entrypoint on macOS is the current-user
`HostHunter.Client` module. Its profile import automatically starts or reuses
the exact-fingerprint controller and generates native proxy functions from the
packaged export metadata. The client has one generic Docker bridge and no
managed-host transport or cmdlet-specific behavior.

## Development verdict

`./scripts/verify-cmdlets.sh` is the only development acceptance command. It
runs once with no retries or shards, using a production-derived verifier and one
disposable SSH fixture. One ordered stateful journey calls all eleven cmdlets,
performs real public writes, fresh-process public reads, and read-only SQLite
integrity/count/generation checks. Its independent receipt is authoritative for
cmdlet behavior.

The Linux journey expects a finite audited failure from the Windows policy
cmdlet. That row proves dispatch, persistence, and termination on a non-Windows
host; it is not positive Windows capability proof.

## Exact-SHA release proof

`scripts/release/verify-candidate.sh <SHA>` is laptop-gate owned. It atomically
claims a clean committed SHA before work and refuses every subsequent attempt
for that SHA. It builds the exact production images once and records every
component receipt independently. The release graph is:

1. exact-SHA preflight and claim;
2. build the exact production images once;
3. run the eleven-cmdlet verifier once;
4. run positive live-Windows qualification against that exact image;
5. run the bounded release-only coverage command;
6. run critical SQLite, recovery, SSH, and persistence integration;
7. run dependency, filesystem, secret, and image scans; and
8. aggregate existing receipts without invoking work.

Every independent phase runs at most once even when another independent phase
fails. A real dependency failure records `not_run_due_to_<dependency>` instead
of a false test failure. Every terminal condition writes an immutable receipt,
and the aggregator reads receipts only. Coverage, integration, or scan failures
cannot alter or hide the eleven-row cmdlet or Windows verdict.

Positive Windows support requires one bounded live-Windows PowerShell 7/OpenSSH
qualification immediately after the cmdlet verifier and before coverage. It
uses only public cmdlets/the engine, performs fixed cleanup and policy
restoration, and never automatically retries.

## Release-only coverage contract

Coverage runs in one container through one PowerShell process. It performs two
fixed, sequential unit-test passes; these are collectors, not retries:

1. Untouched production source under Pester native coverage measures statements,
  executable lines, and AST-owned functions.
2. An ephemeral instrumented copy runs the same unit suite and records genuine
  branch outcomes in memory, flushing once when the run completes.

Every shipped production source file is included. Integration, SSH fixtures,
live Windows, and the eleven-cmdlet journey never contribute to the coverage
numerator. Statements, branches, functions, and lines must each be at least 90
percent, with 92 percent as the engineering target. Unsupported decision syntax,
zero denominators, test failures, malformed results, and missing source files
fail closed.

The normal target is 180 seconds or less and the hard timeout is 300 seconds.
There are no retries, shards, nested runners, worker processes, per-hit files,
or network/database services. A single atomic summary always records all four
metrics, their deficits, and every uncovered location so failure diagnosis never
requires a second coverage run.

"Every shipped production source file" includes both the authoritative module
and `client/HostHunter.Client`; the collector accepts the client as an explicit
additional source root and instruments it only in its ephemeral second pass.

## Hooks

Pre-commit remains a fast containerized static/import/unit smoke. Pre-push is a
slim local secret/dependency/static/critical-integration gate; it must not repeat
the full exact-SHA release proof. GitHub does not execute the test suite.
