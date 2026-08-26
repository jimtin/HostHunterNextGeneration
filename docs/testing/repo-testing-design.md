# Repository testing design

Status: confirmed.

## Product boundary

The package exports exactly eleven PowerShell cmdlets. The canonical controller
is the production Linux container. Managed-host behavior uses PowerShell 7 over
OpenSSH through the single private managed-host engine. Authenticated SQLite,
encrypted evidence, anchors, tamper/rollback detection, and recovery are part of
the product and remain tested.

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
for that SHA. It records the cmdlet receipt independently, then runs
`scripts/verify-local.sh` once for:

1. static/governance checks;
2. at least 90 percent statement, branch, function, and line unit coverage;
3. critical SQLite, recovery, SSH, and persistence integration;
4. dependency, filesystem, secret, and image scans;
5. the production controller build.

Every terminal condition writes an immutable passed, failed, blocked, or aborted
receipt. The aggregator reads receipts only. A heavy-proof failure cannot alter
or hide the eleven-row cmdlet verdict.

Positive Windows support additionally requires one bounded live-Windows
PowerShell 7/OpenSSH qualification against the exact controller image. It uses
only public cmdlets/the engine, performs fixed cleanup and policy restoration,
and never automatically retries.

## Hooks

Pre-commit remains a fast containerized static/import/unit smoke. Pre-push is a
slim local secret/dependency/static/critical-integration gate; it must not repeat
the full exact-SHA release proof. GitHub does not execute the test suite.
