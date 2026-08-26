# Managed Host Engine Readiness

**Verdict: CONDITIONAL — implementation may proceed; release requires live
Windows credentials and a reachable Windows PS7/OpenSSH host.**

## Goal and users

Give a HostHunter operator one accountable path for validating targets,
testing them, executing PowerShell, installing an SSH key, and managing Windows
process-audit policy. The engine is private; the eleven cmdlets remain the only
user interface.

## Control flow

Public host-facing cmdlet -> validated closed request ->
`Invoke-HHManagedHostOperation` -> durable intent and exact phase manifest ->
dispatch arm -> private SSH adapter -> captured streams/outcome -> encrypted
artifact and terminal SQLite record -> public projection.

The five allowed operations are `ValidateTarget`, `TestTarget`,
`InvokeCommand`, `EnableSshKeyAuthentication`, and
`SetWindowsProcessAuditPolicy`. An unknown operation or payload fails before
state/network. No caller-supplied executor or manifest scriptblock is allowed.

## Data and security

- Preserve the current schema and `.hhout` format; do not rewrite operator
  volumes.
- Keep data, secrets, anchors, SSH keys, and evidence as separate trust roots.
- Trust discovery, identity probing, session open/invoke/close, key bootstrap,
  policy mutation and cleanup all belong behind the engine.
- Local SQLite/files/volumes and HostHunter's Docker-internal lifecycle are not
  managed-host communication.
- A command supplied to `Invoke-HHCommand` may itself perform network work on
  the remote host; HostHunter audits the originating command and outcome but
  does not sandbox that downstream behavior.

## Failure and recovery

Pre-intent validation creates no state or connection. Pre-arm failure is
not-dispatched. A definite remote failure is completed/failed. Any uncertain
dispatch or commit is terminal unknown and is never retried. Cleanup failure
is logged and prevents aggregate success. An interrupted armed phase is
recovered to uncertain without redispatch.

## Definition of done

The AST boundary guard is fail-closed, every host-facing cmdlet delegates once,
the ordered eleven-step SQLite journey passes without retry, live Windows
qualification passes for the exact image, obsolete surfaces are absent, and an
immutable exact-SHA release receipt aggregates independent cmdlet and heavy
proof verdicts without changing either.
