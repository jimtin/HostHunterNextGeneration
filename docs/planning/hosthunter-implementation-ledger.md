# HostHunter Simplification Implementation Ledger

## Contract

This ledger implements `hosthunter-simplification-plan.md` from commit
`b7e53b86f49d497f661953c921e2c31e5b9c5fe2` on branch
`codex/hosthunter-simplification`.

The product surface is exactly eleven exported cmdlets. Linux Docker with
PowerShell 7 is the only controller. SSH/OpenSSH is the only managed-host
transport. Authenticated SQLite, encryption, anchors, `.hhout` evidence,
tamper/rollback detection, and crash recovery remain required.

`Invoke-HHManagedHostOperation` will be the only production-module gateway
from the controller to a managed host. Docker lifecycle/health traffic, local
SQLite/files/volumes, and test-fixture setup are outside that boundary.

## Acceptance ledger

| ID | Requirement | Intended change | Focused proof | Status | Non-goal/deferred |
| --- | --- | --- | --- | --- | --- |
| R1 | Exactly 11 public cmdlets | Keep the manifest/export allowlist and remove every unrelated product surface | package import asserts exact names | verified | no new public cmdlets |
| R2 | One managed-host engine | Route Set/Test/Invoke/Enable/Policy through one private closed-operation facade | AST boundary guard plus five delegation tests | verified | user commands may initiate downstream traffic on the host |
| R3 | Identical accountable logging | Engine owns intent, phase arming, dispatch, output and terminalization with semantic operation labels | one intent and one terminal result per target; authenticated `.hhout` where applicable | verified | do not relabel every operation `InvokeCommand` |
| R4 | Real SQLite read/write proof | Run one ordered journey against a fresh store and inspect it read-only after every step | public fresh-process reads plus SQL integrity/count/generation deltas | verified | tests never write directly with SQL |
| R5 | Preserve security guarantees | Retain authenticated DB, keys, anchors, encrypted output and recovery | focused tamper/rollback/recovery integration | implemented | clean exact-SHA release proof remains pending |
| R6 | Fast container flow | Use one production-derived verifier and one disposable SSH target | `verify-cmdlets.sh` emits an 11-row receipt with no retry | verified | no unit/coverage/scans/build in cmdlet verdict |
| R7 | Windows works | Exercise all five host-facing cmdlets through the engine against Windows PS7/OpenSSH | separate production-image live-Windows receipt; all 11 rows combined | verified for working tree | clean exact-SHA release receipt remains pending until commit |
| R8 | Prune obsolete scope | Remove Forensics/parser/ECS/outbox/API, WinRM, PS5.1, native controllers and redundant runners | deleted-surface sweep and import/runtime checks | verified | compatibility fields remain only for historical DB records |
| R9 | Simple production container | One Linux controller and five separated trust-domain volumes | production image/runtime contract | verified | no parser sidecar or idle compatibility services |
| R10 | No repeated release loops | Atomically claim an exact SHA once and always write immutable terminal receipts | interrupted/fail/pass duplicate-claim tests | verified | fixes require a new SHA |
| R11 | Release proof cannot hide user-facing verdicts | Store cmdlet and Windows receipts independently; run Windows before coverage; run independent coverage/integration/security phases once | read-only aggregator preserves every verdict and blocked dependency | implemented; coverage simplification in progress | no automatic reruns or diagnostic coverage rerun |
| R13 | Radical release coverage simplification | Replace workers/shards/per-hit writes with one container, one PowerShell process and two unit-only passes over all shipped source | four independent metrics >=90%, 92% target, complete failure receipt, <=300s | in progress | no integration/live numerator or production exclusions |
| R12 | Remove dirty-tree blockage | Discard old dirty state and start at the approved previous commit | clean branch at exact baseline | verified | discarded files are intentionally not preserved |

## Test ledger

| Production area | Focused unit/contract proof | Integration/E2E proof | Status |
| --- | --- | --- | --- |
| Public export contract | exact 11 names; engine remains private | fresh package import | verified |
| Managed-host gateway | closed operation values; no direct transport/audit calls from Public | engine marker and DB lifecycle for five host-facing cmdlets | verified |
| Target persistence | validation, CAS, add/remove semantics | Set/Get/Test/Remove with fresh-process reads and SQL deltas | verified |
| Command evidence | stream capture, finite failure, terminalization | Invoke, Get-AuditRecord and Get-AuditOutput round trip | verified |
| SSH key transition | install/proof/commit/uncertain handling | password to key transition and post-key command | verified |
| Windows policy | fixed payload/result parser and native `AUDIT_NONE` normalization | live Windows mutation, Event 4688 proof, exact restoration and key cleanup | verified for working tree |
| Escalation configuration | authenticated generation/mutation semantics | Set/Get fresh-process persistence | verified |
| Recovery/integrity | unarmed, armed, tamper and rollback cases | one focused SQLite critical-path container lane | implemented; release proof pending |
| Release claim | claim/finalize/interrupt/duplicate state machine | one exact-SHA release invocation | contract verified; exact-SHA run pending |

The expensive release gate may start only after all changed-scope rows above
are verified or explicitly blocked with evidence.

The final development verifier passed all eleven rows in one invocation on
2026-08-26. Its receipt is a working-tree artifact bound to the module and
image digests; it is not clean exact-SHA release evidence.

The production-derived working-tree Windows image also passed all eleven rows
against the saved Windows PowerShell 7/OpenSSH host. The run verified Security
Event 4688, restored the starting policy exactly, removed its exact remote key,
and removed all disposable Docker resources. The immutable release gate must
repeat this once for the eventual clean candidate SHA.

## Parallel work

After this shared contract is present, independent workers may own: (1) the
managed-host engine and public adapters, (2) the focused cmdlet journey and
verifier, and (3) exact-SHA receipt mechanics. The primary agent owns
integration, pruning, stale-test reconciliation, threat modeling, and the
final container proof. Workers must not edit outside assigned paths or revert
another worker's changes.
