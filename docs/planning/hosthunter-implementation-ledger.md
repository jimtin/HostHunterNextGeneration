# HostHunter Simplification Implementation Ledger

## Contract

This ledger implements `hosthunter-simplification-plan.md` from commit
`b7e53b86f49d497f661953c921e2c31e5b9c5fe2` on branch
`codex/hosthunter-simplification`.

The product surface is twelve exported framework cmdlets: the simplified
original eleven plus `Get-TargetHostDetails`. The native macOS client separately
provides `Start-HHVisualization` and `Stop-HHVisualization`. Linux Docker with
PowerShell 7 is the only controller. SSH/OpenSSH is the only managed-host
transport. Authenticated SQLite, encryption, anchors, `.hhout` evidence,
tamper/rollback detection, and crash recovery remain required.

`Invoke-HHManagedHostOperation` will be the only production-module gateway
from the controller to a managed host. Docker lifecycle/health traffic, local
SQLite/files/volumes, and test-fixture setup are outside that boundary.

## Acceptance ledger

| ID | Requirement | Intended change | Focused proof | Status | Non-goal/deferred |
| --- | --- | --- | --- | --- | --- |
| R1 | Exactly 12 public framework cmdlets plus two client-local lifecycle commands | Keep the manifest/export allowlist and remove every unrelated product surface | package import asserts exact names and client contract asserts local commands | verified | future framework additions must use generic client sync and boundary contracts |
| R2 | One managed-host engine | Route Set/Test/Invoke/Details/Enable/Policy through one private closed-operation facade | AST boundary guard plus six delegation tests | verified | user commands may initiate downstream traffic on the host |
| R3 | Identical accountable logging | Engine owns intent, phase arming, dispatch, output and terminalization with semantic operation labels | one intent and one terminal result per target; authenticated `.hhout` where applicable | verified | do not relabel every operation `InvokeCommand` |
| R4 | Real SQLite read/write proof | Run one ordered journey against a fresh store and inspect it read-only after every step | public fresh-process reads plus SQL integrity/count/generation deltas | verified | tests never write directly with SQL |
| R5 | Preserve security guarantees | Retain authenticated DB, keys, anchors, encrypted output and recovery | focused tamper/rollback/recovery integration | implemented | clean exact-SHA release proof remains pending |
| R6 | Fast container flow | Use one production-derived verifier and one disposable SSH target | `verify-cmdlets.sh` emits a 12-row receipt with no retry | implemented; final working-tree run pending | no unit/coverage/scans/build in cmdlet verdict |
| R7 | Windows works | Exercise all six host-facing cmdlets through the engine against Windows PS7/OpenSSH | separate production-image live-Windows receipt; all 12 framework rows combined | implemented; new exact-SHA proof pending | no password or raw-SSH qualification path |
| R8 | Prune obsolete scope | Remove Forensics/parser/ECS/outbox/API, WinRM, PS5.1, native controllers and redundant runners | deleted-surface sweep and import/runtime checks | verified | compatibility fields remain only for historical DB records |
| R9 | Simple production container | One Linux controller and five separated trust-domain volumes | production image/runtime contract | verified | no parser sidecar or idle compatibility services |
| R10 | No repeated release loops | Atomically claim an exact SHA once and always write immutable terminal receipts | interrupted/fail/pass duplicate-claim tests | verified | fixes require a new SHA |
| R11 | Release proof cannot hide user-facing verdicts | Store cmdlet and Windows receipts independently; run Windows before coverage; run independent coverage/integration/security phases once | read-only aggregator preserves every verdict and blocked dependency | implemented; coverage simplification in progress | no automatic reruns or diagnostic coverage rerun |
| R13 | Radical release coverage simplification | Replace workers/shards/per-hit writes with one container, one PowerShell process and two unit-only passes over all shipped source | four independent metrics >=90%, 92% target, complete failure receipt, <=300s | in progress | no integration/live numerator or production exclusions |
| R14 | Qualification reuses invisible authentication | Preflight the live runtime, clone the five HostHunter trust-domain volumes, prove the existing public key once through the engine, and destroy only disposable copies | idempotent key-proof unit tests; qualification contract tests; exact-SHA live receipt | focused verified; exact-SHA proof pending | source operator state is mounted read-only during clone and is never removed or rewritten |
| R12 | Remove dirty-tree blockage | Discard old dirty state and start at the approved previous commit | clean branch at exact baseline | verified | discarded files are intentionally not preserved |

## Test ledger

| Production area | Focused unit/contract proof | Integration/E2E proof | Status |
| --- | --- | --- | --- |
| Public export contract | exact 12 framework names; engine remains private; two client lifecycle commands local | fresh package import | verified focused |
| Managed-host gateway | closed operation values; no direct transport/audit calls from Public | engine marker and DB lifecycle for six host-facing cmdlets | verified |
| Mission and host details | bounded producer, schema validation, partial-field projection, stable opaque identity | authenticated schema-v3 persistence and 12-row journey | focused unit/integration verified; final journey pending exact-SHA proof |
| Target persistence | validation, CAS, add/remove semantics | Set/Get/Test/Remove with fresh-process reads and SQL deltas | verified |
| Command evidence | stream capture, finite failure, terminalization | Invoke, Get-AuditRecord and Get-AuditOutput round trip | verified |
| SSH key transition | install/proof/commit/uncertain handling plus idempotent proof for an existing saved public key | password-to-key transition and one audited existing-key proof | verified focused |
| Windows policy | fixed payload/result parser and native `AUDIT_NONE` normalization | cloned-state live Windows mutation, Event 4688 proof, and derived exact restoration | implemented; exact-SHA proof pending |
| Escalation configuration | authenticated generation/mutation semantics | Set/Get fresh-process persistence | verified |
| Recovery/integrity | unarmed, armed, tamper and rollback cases | one focused SQLite critical-path container lane | implemented; release proof pending |
| Release claim | claim/finalize/interrupt/duplicate state machine | one exact-SHA release invocation | contract verified; exact-SHA run pending |

The expensive release gate may start only after all changed-scope rows above
are verified or explicitly blocked with evidence.

The final development verifier passed all eleven rows in one invocation on
2026-08-26. Its receipt is a working-tree artifact bound to the module and
image digests; it is not clean exact-SHA release evidence.

Exact candidate `11aca1fe562f4bd5e80f7d6fe0a3fa13db9ccba6` passed the
focused twelve-cmdlet Linux verifier, but its Windows phase called the packaged
module directly without the native interaction broker. `Set-HHTarget` therefore
failed on an unsupported `confirmation_request` frame before host contact. The
candidate is terminally consumed and must never be rerun.

The replacement Windows qualification does not request a password or use raw
SSH. Before claiming a SHA it proves that the five source volumes, sole runtime
controller, and exactly one selected saved key are ready. It clones the data,
secret, anchor, SSH-key, and evidence volumes into run-scoped disposable
volumes while the source controller is paused, pauses visualization only in the
clone, then uses the saved PublicKey target through all public cmdlets and the
managed-host engine. `Enable-HHSshKeyAuthentication` performs one audited
key-only proof when the target is already keyed. Policy restoration is derived
from the live pre-mutation outcome. A new exact SHA must prove this once before
publication.

## Parallel work

After this shared contract is present, independent workers may own: (1) the
managed-host engine and public adapters, (2) the focused cmdlet journey and
verifier, and (3) exact-SHA receipt mechanics. The primary agent owns
integration, pruning, stale-test reconciliation, threat modeling, and the
final container proof. Workers must not edit outside assigned paths or revert
another worker's changes.
