# Endpoint CIM collection implementation ledger

Status: confirmed and implementation authorized  
Date: 2026-08-29

## Acceptance ledger

| ID | Requirement | Implementation surface | Focused proof | Status | Non-goal |
| --- | --- | --- | --- | --- | --- |
| CIM-01 | Export five thin target collection cmdlets | Public adapters, module manifest, runtime metadata | Export contract plus one 17-row package journey | verified | One cmdlet per event ID |
| CIM-02 | Use the sole managed-host connection engine exactly once | Closed engine operations and boundary guard | AST boundary and delegation tests | verified | Direct SSH, WinRM, or public-cmdlet composition |
| CIM-03 | Collect bounded Windows 4688 events | Fixed Security-channel collector and process-start normalizer | v0/v1/v2 fixtures plus live Windows `First 1` | implemented; live proof release-only | Raw EVTX/XML transfer or background polling |
| CIM-04 | Collect bounded Windows authentication events | Fixed IDs 4624/4625/4634/4647/4648/4672 and normalizers | Versioned fixtures and semantic-negative tests | implemented; live proof release-only | Arbitrary event-log forwarding |
| CIM-05 | Collect primary process tokens by PID or exact process name | Fixed Windows token helper | PID/name, PID-reuse, inaccessible and ambiguity tests | implemented; live proof release-only | Silent `SeDebugPrivilege` enablement |
| CIM-06 | Collect effective rights for saved or explicit identity | Fixed LSA and bounded membership resolver | Direct/group/deny/partial/unavailable fixtures | implemented; live proof release-only | Guessing Local Policy/GPO/MDM origin |
| CIM-07 | Preserve complete collected command lines as accepted sensitive evidence | CIM contract, normalizer, encrypted store and producer | Exact sensitive-canary round trip; no diagnostic duplication | verified | Command-line redaction |
| CIM-08 | Record exact canonical bytes before delivery | Additive SQLite migration and forensic repository | Fresh migration, encrypted append, fault injection | verified | Visualizer as evidence authority |
| CIM-09 | Resume events from a durable cursor without loops | Per-target/source cursor and bounded result receipt | cursor, truncation, log-gap and interruption tests | implemented; live truncation proof release-only | Automatic retries or background workers |
| CIM-10 | Publish only registered schemas through one route | Producer capability list and generic event PUT | create/replay/conflict/unsupported API integration | verified | Route or sender per event type |
| CIM-11 | Keep tests fast and focused | Existing focused/unit/integration/cmdlet runners | <=30s focused lanes; 90s cmdlet hard cap | verified | Shards, fan-out, source instrumentation, broad development gate |
| CIM-12 | Qualify positive Windows behavior once per exact SHA | Existing public-cmdlet Windows qualifier | One bounded combined receipt, no retry | implemented; exact-SHA release pending | Deliberate 4625/account-lockout test |
| CIM-13 | Collect bounded Windows 4689 process-end events on demand and during initial target collection | `Get-TargetProcessEndEvents`, closed engine operation, existing Security-log collector and generic forensic repository | 4689 normalization, strict cursor resume, encrypted persistence, one 17-row journey and exact-SHA Windows positive proof | implemented; focused proof verified; Windows release proof pending | Polling, subscriptions, automatic policy mutation, or HostHunter-side lifecycle correlation |

## User-action coverage matrix

HostHunter is a PowerShell CLI. The package-backed cmdlet journey and native
macOS bridge journey are the equivalent user-action/E2E layers.

| User action | Surface | Role/state | Expected behavior | E2E evidence | Unit/integration evidence | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Get process starts | `Get-TargetProcessStartEvents` | operator; saved Windows target | returns bounded canonical 4688 records, cursor and `HasMore` | 17-row journey precondition; exact-SHA Windows positive | v0/v1/v2 normalizer and persistence tests | implemented; Windows release proof pending |
| Get process ends | `Get-TargetProcessEndEvents` | operator; saved Windows target | returns bounded canonical 4689 records, persists before delivery, and never infers outcome or stable identity | 17-row journey precondition; exact-SHA Windows positive | v0 normalizer, strict cursor, schema and persistence tests | implemented; focused proof verified; Windows release proof pending |
| Save target while a mission exists | `Set-HHTarget` | operator; newly validated target and retained mission | performs one bounded initial process-end collection; failure warns but does not undo the saved target | 17-row journey plus exact-SHA Windows qualification | initial-collection engine contract | implemented; focused proof verified; Windows release proof pending |
| Get authentication activity | `Get-TargetAuthenticationEvents` | operator; saved Windows target | returns bounded canonical authentication records without changing audit policy | 17-row journey precondition; exact-SHA Windows positive | six event-family fixture tests | implemented; Windows release proof pending |
| Get token by PID | `Get-TargetProcessAccessToken -ProcessId` | operator; live process | verifies process instance and returns primary-token state | exact-SHA Windows qualification | token helper success/race/access-denied tests | implemented; Windows release proof pending |
| Get token by name | `Get-TargetProcessAccessToken -ProcessName pwsh.exe` | operator; one or more exact matches | returns at most 64 exact-name matches or a bounded ambiguity failure | exact-SHA Windows qualification | normalization, zero/multiple/overflow tests | implemented; Windows release proof pending |
| Get saved user's rights | `Get-TargetUserEffectiveRights` | operator; saved login identity | resolves applicable assignments and provenance or truthful partial result | exact-SHA Windows qualification | rights and membership fixtures | implemented; Windows release proof pending |
| Get explicit user's rights | `Get-TargetUserEffectiveRights -Identity` | operator; resolvable or missing identity | uses structured identity input; never guesses a SID | package validation plus Windows qualification | resolve/failure/input tests | implemented; Windows release proof pending |
| Collect with no active mission | all five cmdlets | operator; visualization never activated | fails clearly before endpoint contact and writes no forensic record | 17-row package journey state assertion | delegation and no-network tests | verified |
| Collect while publishing is paused/unavailable | all five cmdlets | operator; retained mission | records locally, reports pending delivery, never retries inline | focused lifecycle replay | encrypted SQLite and replay integration | verified |
| Run on Linux target | all five cmdlets | operator; non-Windows target | finite pre-contact mission result in the development journey; finite `UnsupportedPlatform` once a mission exists | exact package journey with mission | closed-operation tests | development journey verified; mission-active and Windows release proof pending |
| Request invalid bounds/name/PID/identity | all five cmdlets | operator; invalid input | fails before intent or network | parameter-contract tests | focused validation tests | verified |

## Test ledger

| Production area | Focused test owner | Required evidence | Status |
| --- | --- | --- | --- |
| CIM schemas and examples | CIM contract tests in both repositories | byte-identical mirror; positive and negative schema fixtures | verified |
| Public adapters and exports | managed-host/export contract tests | exactly 17 exports; five collection adapters call engine once | verified |
| Security-event native parsing | new forensic normalizer tests | all supported versions, omissions, invalid native values | verified |
| Token helper | new token collector tests | handles, PID reuse, exact process name, status branches | verified |
| Effective-rights resolver | new rights collector tests | membership paths, deny precedence, unknown attribution | verified |
| SQLite forensic ledger | fresh migration integration | encrypted append, state MAC, cursor, gap, recovery | verified |
| Visualizer producer | producer contract tests | capability check, exact digest, bounded one-attempt send | verified |
| Visualizer consumer | API/store integration | registration, immutable create/replay/conflict | verified |
| Native macOS metadata | native client contract | automatic command declaration and generic bridge | verified |
| Windows behavior | exact-SHA qualifier | one harmless process, five collection commands, fixed cleanup | implemented; release-only proof pending |
| Process-end public surface | export, boundary and native-client contracts | seventeenth framework export; automatic macOS proxy; exactly one `GetProcessEndEvents` delegation | verified |
| Process-end normalization and resume | security normalizer and remote collector tests | 4689 v0 fields, no fabricated correlation/outcome, strict timestamp/record-id cursor progression | verified |
| Process-end audit migration | fresh and upgrade migration integration | fresh v5, v4-to-v5 preservation, crash recovery and operation allowlist | verified |
| Process-end Windows behavior | exact-SHA qualifier | public cmdlet observes one harmless known-PID process with known exit code and restores both audit subcategories | pending; release-only proof |

## Current validation state

- Focused production, migration, public-surface, native-client, Windows-
  qualification contract, security, and static checks are green.
- The synchronized runtime is healthy and exports seventeen framework commands.
- The first 17-row verifier attempt exposed an unwritable receipt directory.
  The replacement attempt exposed loss of the fixture-reader supplementary
  group while fixing that directory. The verifier now retains both group
  `10002` and the host artifact GID, and its focused contract is green.
- A later, separately authorized verifier repair added a same-invocation
  preflight, preserved both permission groups, and ran the verifier exactly once
  after focused readiness. All 17 rows passed; SQLite schema v5 and integrity
  `ok` were recorded. Clean exact-SHA Windows release proof remains pending.

## Execution controls

- Preserve all pre-existing dirty files; do not reset or overwrite unrelated work.
- No focused check is rerun without first changing the failing implementation.
- No broad coverage, release, build, scan, or live-Windows run occurs during
  implementation iteration.
- The main agent owns shared manifests, engine integration, migrations, final
  reconciliation, threat review, readiness preflight, and canonical proof.
- No additional parallel workers are used for this change because the current
  policy does not authorize them and the affected engine, manifest, migration,
  and journey files are tightly coupled.
