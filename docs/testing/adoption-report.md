# Testing adoption report

Status: implemented and working-tree qualified on Linux and Windows; clean
exact-SHA release proof remains pending until the intended changes are committed.

## Adopted flow

- Exactly eleven exported cmdlets.
- One ordered container acceptance journey with real SQLite reads and writes.
- One private managed-host engine and a fail-closed AST boundary check.
- One production Linux controller and one disposable acceptance SSH fixture.
- One immutable, once-per-exact-SHA release state machine.
- Heavy coverage, critical integration, scans, and production build isolated
  from the cmdlet verdict and executed only by the release gate.

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
