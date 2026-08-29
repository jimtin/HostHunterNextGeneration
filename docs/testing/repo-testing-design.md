# Repository testing design

Status: confirmed.

## Product boundary

The package exports exactly twelve PowerShell cmdlets. The canonical controller
is the production Linux container. Managed-host behavior uses PowerShell 7 over
OpenSSH through the single private managed-host engine. Authenticated SQLite,
encrypted evidence, anchors, tamper/rollback detection, and recovery are part of
the product and remain tested.

The supported operator entrypoint on macOS is the current-user
`HostHunter.Client` module. Its profile import automatically starts or reuses
the source-fingerprint-bound controller and generates native proxy functions from the
packaged export metadata. The client has one generic Docker bridge and no
managed-host transport or cmdlet-specific behavior.

Onboarding is key-first. Password fallback requires a full risk warning and a
second confirmation. Saved passwords are purpose-separated authenticated
SQLite envelopes bound to database identity and target revision; the key stays
in the separate secret volume. Managed-host operations seed the controller
loopback broker through standard input, making authentication invisible after
onboarding. Proven key conversion and target deletion purge the credential
atomically. Uncertain key outcomes never retry or fall back.

## Development verdict

`./scripts/verify-cmdlets.sh` is the only development acceptance command. It
runs once with no retries or shards, using a production-derived verifier and one
disposable SSH fixture. One ordered stateful journey calls all twelve framework cmdlets,
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
3. run the twelve-cmdlet verifier once;
4. run positive live-Windows qualification against that exact image;
5. run the bounded release-only coverage command;
6. run the focused authenticated-SQLite fault and recovery integration;
7. run dependency, filesystem, secret, and image scans; and
8. aggregate existing receipts without invoking work.

Every independent phase runs at most once even when another independent phase
fails. A real dependency failure records `not_run_due_to_<dependency>` instead
of a false test failure. Every terminal condition writes an immutable receipt,
and the aggregator reads receipts only. Coverage, integration, or scan failures
cannot alter or hide the twelve-row cmdlet or Windows verdict.

Positive Windows support requires one bounded live-Windows PowerShell 7/OpenSSH
qualification immediately after the cmdlet verifier and before coverage. It
uses only public cmdlets/the engine, performs fixed cleanup and policy
restoration, and never automatically retries.

## Release-only coverage contract

Coverage runs in one networkless container using the standard Pester profiler.
Every shipped production source file under the authoritative module and native
client roots is included. Integration, SSH fixtures, live Windows, and the
twelve-cmdlet journey never contribute to the coverage numerator. Statements,
executable lines, and invoked functions must each be at least 90 percent, with
92 percent as the engineering target. Zero denominators, test failures,
malformed results, and missing source files fail closed.

Branch confidence is behavioral rather than synthetic. Named unit and focused
integration tests must cover public validation, key/password/fallback choices,
managed-host pre-dispatch/completed/uncertain/cleanup outcomes, and SQLite
empty/save/replace/delete/tamper/rollback/recovery states. There is no custom
AST transformer or numerical branch-percentage gate.

The coverage command has one timeout owner, one terminal summary, and no
retries, shards, nested runners, worker processes, instrumented source copies,
per-hit files, or network/database services. A failure lists uncovered native
locations so diagnosis proceeds through focused tests rather than another broad
coverage run.

## Hooks

Pre-commit runs the secret scan, static/governance checks, and changed/focused
tests only, with a 45-second hard bound. Pre-push runs secret/dependency scans,
static/governance checks, one ordinary unit smoke, and one twelve-cmdlet/SQLite
journey, with a two-minute normal target. The native macOS journey is selected
only when its owned surface changes. Neither hook runs release coverage,
production builds, image scans, live Windows, or broad persistence matrices.
GitHub does not execute the test suite.
