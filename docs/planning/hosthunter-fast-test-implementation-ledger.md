# HostHunter Fast Test Implementation Ledger

Status: implemented and focused-verified; release-only proof deferred

| Requirement | Intended change | Focused evidence | Status | Non-goal |
| --- | --- | --- | --- | --- |
| Preserve and clear the dirty experiment | External binary patch plus untracked-file backup; restore clean `31d6baa` | Backup checksum, file inventory, clean baseline status | verified | Reintroducing the experimental AST collector |
| Focused development tests stay small | One container invocation, no coverage, 30-second hard bound | 44 focused Pester tests passed in 2.28 seconds | verified | Broad-suite discovery during development |
| Unit smoke stays fast | One PowerShell/Pester invocation without coverage | 672 tests passed once in 21.48 seconds | verified | Shards, workers, profiler, source rewriting |
| Every exported cmdlet and SQLite are accepted once | One 12-row stateful verifier and read-only SQLite deltas | 12/12 passed once; SQLite integrity `ok` | verified | A separate lane per cmdlet |
| Native macOS validation is impact-scoped | Run only for native-client/profile/onboarding changes | Hook impact-selection contract and automatic macOS client synchronization | verified | Running the macOS journey on every change |
| Windows proof is release-only | One exact-image Windows qualification with terminal receipt | Qualification contract tests; live proof deferred to exact-SHA gate | implemented | Development/pre-push live Windows calls |
| Coverage is honest and bounded | Native statements, lines, invoked functions >=90; behavioral branch tests | Native coverage contracts passed; numerical proof deferred to release | implemented | Numerical custom AST branch percentage |
| Hooks do not duplicate release work | Slim pre-commit and pre-push command graphs | Fast hook contract 5/5 passed | verified | Coverage, builds, image scans, or Windows in hooks |
| Release work runs once per exact SHA | Atomic claim, immutable terminal receipts, no retry | Release receipt contracts 18/18 passed | verified | Reusing or rerunning a consumed SHA |
| Cmdlet verdict cannot be obscured | Independent component receipts and read-only aggregation | Receipt-coherence and forged-receipt contracts passed | verified | A single combined pass/fail hiding component results |
| Proven release blockers are reapplied | Least-privilege volume copy and exact SQLite asset manifest | Windows/provider packaging contracts passed | verified | A live release run during implementation |
| Superseded test machinery is removed | Classified progressive deletion plus deleted-surface sweep | No active executable references remain | verified | Removing active SQLite/security guarantees |
| Security boundaries remain intact | Updated evidence-grounded threat model | Threat-model report checker passed | verified | Rewriting authenticated persistence |
| Final validation does not loop | Readiness preflight, focused checks, one bounded canonical validation | Static 10.3 seconds; unit 21.48 seconds; cmdlets passed first attempt | verified | Repeated broad runs after failure |

## Test Ledger

| Changed area | Required test seam | Planned command | Status |
| --- | --- | --- | --- |
| Coverage/unit runner | Coverage and process-cardinality contracts | Focused Pester file in test container | verified |
| Pre-commit/pre-push | Command allow/deny graph and bounds | Focused hook contract file in test container | verified |
| Cmdlet verifier | Unique export rows, receipt terminality, SQLite journey | `./scripts/verify-cmdlets.sh` once after preflight | verified: 12/12 |
| Release receipt state | Duplicate claim, interruption, mismatch, aggregation | Focused release receipt contract file | verified: 18/18 |
| Windows volume preparation | UID/mode/capability and cleanup contract | Focused Windows qualification contract file | verified focused; live release deferred |
| SQLite asset restoration | Exact RID asset manifest and existence | Focused provider packaging contract file | verified |
| Documentation and deleted surfaces | Active-contract and stale-reference checks | Static contract lane plus `rg` sweep | verified |
