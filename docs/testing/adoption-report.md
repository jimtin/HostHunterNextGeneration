# Testing adoption report

Status: implemented and working-tree qualified on Linux and Windows; clean
exact-SHA release proof remains pending until the intended changes are committed.

## Adopted flow

- Exactly eleven exported cmdlets.
- One ordered container acceptance journey with real SQLite reads and writes.
- One private managed-host engine and a fail-closed AST boundary check.
- One production Linux controller and one disposable acceptance SSH fixture.
- One immutable, once-per-exact-SHA release state machine.
- One planned release-only coverage command: one container, one PowerShell
  process, and two fixed unit-only passes with independent 90 percent thresholds
  for statements, branches, functions, and lines (92 percent engineering target).
- Live Windows qualification precedes coverage. Coverage, critical integration,
  scans, and production build remain independently receipted and cannot alter
  the cmdlet or Windows verdict.

The former coverage-worker/shard framework is being replaced rather than tuned.
The replacement has no retries, nested runners, worker fan-out, per-hit disk
writes, SSH/Windows/database fixture, or integration results in its numerator.

## Removed flow

The Forensics/parser/API stack, WinRM, Windows PowerShell 5.1 dispatch, native
macOS/Windows controllers, controller-floor matrix, duplicate runtime journeys,
generic runtime shell/run entrypoints, and parser-sidecar state are no longer
part of the supported product or canonical testing graph.

## Current evidence

The working-tree focused verifier has produced eleven passing unique cmdlet rows
against the Linux SSH fixture, with SQLite integrity `ok`. The managed-host
boundary and immutable receipt contract focused tests have passed in containers.
These are development artifacts, not clean exact-SHA release evidence.

The production-derived working-tree controller passed all eleven cmdlets on the
saved Windows PowerShell 7/OpenSSH host. It positively verified Security Event
4688, restored the starting audit and command-line settings, removed the exact
qualification key, and cleaned its disposable containers and volumes. This is
current development evidence, not the once-only clean exact-SHA release receipt.
