# HostHunter repository contract

## Supported product

HostHunter exports exactly these eleven cmdlets:

- `Get-HHTarget`
- `Set-HHTarget`
- `Test-HHTarget`
- `Remove-HHTarget`
- `Invoke-HHCommand`
- `Enable-HHSshKeyAuthentication`
- `Get-HHAuditRecord`
- `Get-HHAuditOutput`
- `Set-HHWindowsProcessAuditPolicy`
- `Set-HHEscalationPreference`
- `Get-HHEscalationPreference`

The production controller is Linux in Docker. Managed hosts use PowerShell 7 over
OpenSSH. WinRM, Windows PowerShell 5.1, native macOS/Windows controllers, and the
Forensics parser/API are not supported product surfaces.

`Invoke-HHManagedHostOperation` is the only production-module gateway for
controller-to-managed-host communication. The five host-facing public cmdlets
must call it exactly once and must retain their semantic operation labels.
Internal Docker lifecycle, health checks, volumes, local SQLite, and local
cryptographic files are outside this boundary.

Do not remove or weaken authenticated SQLite, encrypted output artifacts,
anchors, tamper and rollback detection, or interrupted-operation recovery.
Historical target rows may remain readable and removable, but unsupported
transport/runtime profiles must fail closed before network dispatch.

## Test flow

Development acceptance is exactly one command:

```sh
./scripts/verify-cmdlets.sh
```

It runs once, without retries or shards, in a production-derived verifier plus
one disposable SSH fixture. It must produce exactly eleven unique cmdlet rows
and verify public behavior plus read-only SQLite state deltas. A Linux run proves
a finite audited unsupported result for Windows process policy; positive policy
proof belongs to the bounded live-Windows qualification.

Coverage (minimum 90 percent independently for statements, branches, functions,
and lines; 92 percent engineering target), critical SQLite integration,
security/dependency/image scans, and the production build are release-only.
Coverage uses every shipped production source file and unit tests only. Its one
bounded container command owns one PowerShell process and exactly two fixed
passes: untouched-source native coverage followed by an ephemeral
branch-instrumented pass. Never add retries, shards, worker fan-out, per-hit disk
I/O, network fixtures, or integration/live results to the coverage numerator.

`scripts/release/verify-candidate.sh <SHA>` claims an exact clean SHA atomically,
builds the exact images once, runs the cmdlet verifier once, runs positive
Windows qualification before coverage, and runs every independent release
phase at most once. Each phase writes an immutable terminal receipt; later
independent phases continue after an earlier failure, while genuine dependency
failures are recorded as `not_run_due_to_<dependency>`. The read-only aggregate
never invokes work. The claimed SHA is forever refused afterward. Never add
automatic retries, overwrite receipts, or make coverage or another release
phase alter or obscure the cmdlet or Windows verdict.

A live Windows release qualification must use the packaged public cmdlets and
the managed-host engine. Test harness setup may manage Docker, but qualification
must not use raw `ssh`, `scp`, WinRM, or private transport calls to prove
behavior. The Windows mutation must be restored and cleanup failures are fatal.

All test and release proof runs execute in containers. Before any GitHub push,
run the repo secret scan and the required changed-scope threat review. Do not
commit, push, merge, or deploy without explicit user authorization.
