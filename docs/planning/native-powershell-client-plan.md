# Native PowerShell Client Plan

Status: CONFIRMED — implementation authorized 2026-08-26

## Acceptance ledger

| Requirement | Implementation | Focused evidence | Status |
| --- | --- | --- | --- |
| Native macOS PowerShell commands | Install `HostHunter.Client` into the current-user module path | installed-module qualification | verified |
| Automatic Docker startup | Import performs one bounded start/build when required | start/reuse/failure contract tests | verified |
| Automatic command synchronization | Container discovery returns authoritative proxy metadata | add-command-without-client-edit test | verified |
| No duplicated product logic | Generated proxies call one generic bridge; container owns every cmdlet | static client-boundary guard | verified |
| Native streams and objects | Versioned framed CLIXML protocol forwards output and all PowerShell streams | protocol unit/integration tests | verified |
| Secure interactive passwords | One-shot prompt over redirected stdin and an in-memory container credential broker | leakage and key-transition tests | verified |
| Safe growth and compatibility | Source/image/protocol fingerprints fail closed on drift | mismatch and stale-cache tests | verified |
| Existing security guarantees | Managed-host engine, SQLite, encryption, anchors and recovery remain authoritative | existing cmdlet journey and threat review | verified |

## User-action matrix

HostHunter is a PowerShell CLI, so package-backed client journeys are the
Playwright-equivalent user layer.

| User action | Surface | State | Expected behavior | E2E evidence | Unit/integration evidence | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Open PowerShell | profile auto-import | Docker stopped, unchanged source | Docker Desktop/controller start once and commands become available | installed-client journey | lifecycle contract | verified |
| Open another PowerShell | profile auto-import | matching controller already healthy | existing controller is reused without a build | installed-client journey | reuse contract | verified |
| Pull or edit HostHunter | module import | source fingerprint changed | one bounded rebuild occurs; no Git operation is attempted | source-change journey | fingerprint contract | verified |
| Discover a new cmdlet | generated proxy surface | container exports an additional command | command appears without client implementation changes | discovery fixture | proxy-generation unit test | verified |
| Invoke a cmdlet | native PowerShell | valid parameters | parameters and typed output cross the generic bridge | eleven-cmdlet client journey | protocol tests | verified |
| Pipe input | native PowerShell pipeline | one or more input records | binding occurs in the authoritative container command once | pipeline journey | proxy/pipeline tests | verified |
| Receive streams | native PowerShell host | output, warning, error, verbose, debug, information or progress | each stream remains live and correctly typed | stream fixture | protocol tests | verified |
| Register password target | `Set-HHTarget` | no key yet | local secure prompt is requested only when SSH asks for it | SSH fixture journey | broker leakage tests | verified |
| Convert to key | `Enable-HHSshKeyAuthentication` | password profile | password is reused in memory for bounded phases, then discarded | SSH fixture journey | broker lifecycle tests | verified |
| Cancel or lose Docker | any host-facing cmdlet | operation active | no redispatch; one terminating client error; server audit remains authoritative | interruption fixture | protocol/recovery tests | verified |

## Replacement classification

| Surface | Classification | Action |
| --- | --- | --- |
| Managed-host engine and eleven production cmdlets | active | retain unchanged |
| JSON dispatcher used by existing scripts | compatibility | retain until the native client proves all eleven cmdlets |
| `hosthunter.sh invoke` user workflow | superseded | remove only after replacement journey and docs are green |
| Direct `docker exec -it` onboarding instructions | superseded | remove from active documentation after secure prompting passes |
| Cmdlet-specific Mac wrappers | dead-by-design | forbid with a static guard |

## Failure and security contract

- Import, build, start and repair each make at most one attempt and never retry.
- A protocol or source mismatch fails closed; stale proxy metadata is not used.
- Passwords never enter arguments, JSON request bodies, environment variables,
  persistent files, logs, receipts or metadata caches.
- The client-to-controller request uses redirected standard input. A
  controller-local in-memory broker answers native SSH askpass requests and is
  destroyed after the invocation.
- The client never opens SSH, TCP or HTTP connections to managed hosts. Docker
  is its only external process boundary.
- An interrupted or uncertain managed-host operation is never automatically
  replayed.

## Parallel work

Parallel agents are unavailable under the active tool policy. Implementation
uses sequential slices with disjoint file ownership and a focused check after
each slice.
