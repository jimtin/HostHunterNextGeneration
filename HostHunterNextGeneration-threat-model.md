# HostHunterNextGeneration Threat Model

## 1. Summary

- HostHunter writes a durable audit intent before connection and never retries
  an uncertain command. Stream artifacts use AES-256-GCM; the canonical ledger
  and sealed head use an HMAC chain.
- The highest residual confidentiality risk is deliberate retention of complete
  command text in the local ledger and complete remote streams in decryptable
  local evidence. Anyone with the controller user's authority can access them.
- macOS now keeps the 32-byte audit key in the login Keychain through a bounded
  native Security-framework worker. The raw key is never placed in arguments,
  environment variables, or a plaintext key file, but a local administrator and
  candidate-controlled host code remain outside the integrity guarantee.
- SSH host identity and requested PowerShell runtime are both pinned. Windows
  PowerShell 5.1 is reached only through a validated PowerShell 7 SSH runspace;
  runtime, transport, trust, authentication, and command retries never fall back.
- The most valuable remaining mitigation is a candidate-independent laptop-gate
  controller that owns scanner policy and never executes an external contribution
  before manual review. The first-release owner-only policy supplies the current
  procedural control.
- SQLite is now the sole structured persistence boundary. Identity-bound
  encrypted audit fields, streaming `.hhout` v2 output, authenticated target
  generations, per-operation dispatch evidence, crash recovery, capacity
  reservation, and monotonic anchor comparison are implemented and exercised
  by package-only fault tests. Exact-candidate native macOS and Windows
  qualification remains a release gate rather than an implemented claim.

## 2. Scope and Method

In scope: `src/HostHunterNextGeneration/`, repository hooks and local gate
wrappers, Docker Compose topology, the disposable SSH fixture, coverage and
scanner tooling, local audit artifacts, the macOS Keychain boundary, the
PowerShell 7 to Windows PowerShell 5.1 compatibility boundary, and the planned
public GitHub repository permissions.

Out of scope: a central audit collector, guaranteed physical erasure on SSDs,
Windows DPAPI key storage, a production service deployment, and positive WinRM
operation. WinRM is deferred until a separate controlled lab exists.

The product is a local PowerShell 7 module. It connects to authenticated SSH
PowerShell endpoints; there is no listening web service. Canonical proof runs in
local containers and GitHub Actions are prohibited. Positive Windows PowerShell
5.1 and password-to-key qualification are explicit live, exact-candidate lanes.

The confirmed SQLite amendment in
`docs/planning/sqlite-persistence-plan.md` is implemented. Legacy JSON/JSONL
state is rejected without import or mutation; no active dual-write or fallback
store remains.

Confidence tags: `confirmed` means directly supported by cited repository or
live qualification evidence; `inferred` means a reasonable consequence of that
evidence; `unknown` means the final external state has not yet been verified.

## 3. System Model

### Product runtime

| Component | Role | Entrypoints | Evidence | Confidence |
|---|---|---|---|---|
| PowerShell module | Target CRUD, runtime validation, command dispatch, SSH-key transition, audit retrieval, escalation preference, and Windows process-audit policy | Eleven exported cmdlets | `src/HostHunterNextGeneration/` | confirmed |
| Target repository | Secret-free profiles, authenticated complete-set state, generation/revision CAS | Target cmdlets | `Private/TargetModel.ps1`, `Private/TargetRepository.ps1` | confirmed |
| Audit subsystem | Encrypted intent/manifests, per-operation arming, HMAC chain, streaming artifacts, and crash recovery | Remote-operation and audit-query cmdlets | `Private/AuditRepository.ps1`, `Private/AuditOrchestration.ps1`, `Private/AuditRecovery.ps1` | confirmed |
| Audit-key providers | macOS login Keychain; restrictive file fallback on other controllers | Audit startup | `Private/AuditKeyStore.ps1`, `Private/Workers/MacOSKeychainWorker.ps1`, `Private/Configuration.ps1` | confirmed |
| SSH transport | Strict known-host trust, direct PowerShell 7, explicit 5.1 bridge, six-stream capture, per-target output cap, fan-out | SSH probe and command operations | `Private/SshTrust.ps1`, `Private/SshTransport.ps1` | confirmed |
| SSH key bootstrap | Exact Ed25519 marker install, separate key-only proof, exact rollback | `Enable-HHSshKeyAuthentication` | `Private/SshKeyBootstrap.ps1` | confirmed |
| WinRM guard | Rejects unqualified positive operation | WinRM-shaped input | `Private/WinRmTransport.ps1`, `Public/Set-HHTarget.ps1` | confirmed |

### SQLite persistence implementation

| Component | Planned role | Planned entrypoints | Evidence | Confidence |
|---|---|---|---|---|
| SQLite provider/schema | Sole structured target, configuration, and audit store with checksummed migrations | All eleven public cmdlets | `Private/SqliteProvider.ps1`, `Private/SqlitePersistence.ps1`, `Private/Migrations/` | focused proof; exact candidate pending |
| Windows audit-policy adapter | Native Process Creation/Termination policy and optional 4688 command-line inclusion | `Set-HHWindowsProcessAuditPolicy` | `Private/WindowsProcessAuditPolicy.ps1` | focused proof; native exact-candidate proof pending |
| Privilege activation adapter | Activates only a declared privilege already present in the remote token and restores prior state | `-Escalate`, `WindowsTokenPrivilege` | `Private/PrivilegeEscalation.ps1`, authenticated preference repository | focused proof; native exact-candidate proof pending |
| External output artifacts | Invocation-bound chunked encrypted ordered evidence in `.hhout` v2 | Remote completion and `Get-HHAuditOutput` | `Private/AuditArtifactV2.ps1`, `Private/DurableFilePublisher.ps1`, package-backed E2E | confirmed on Linux/macOS; Windows native proof pending |
| Database/target anchor | Atomic monotonic Keychain item on macOS; owner-private colocated fallback on Linux/Windows | Structured writes and remote-capable startup | `Private/PersistenceAnchor.ps1`, `Private/AuditKeyStore.ps1` | confirmed |
| Operation ownership | Distinct bounded lock prevents recovery of a live remote batch | Recovery and remote-capable cmdlets | `Private/PersistenceLock.ps1`, `Private/AuthenticatedPersistence.ps1` | confirmed |
| Packaged SQLite graph | Locked managed/native assets loaded from a qualified RID package | First persistence operation | `eng/sqlite/`, build and package integration lanes | confirmed |
| Audit query surface | Bounded record filters and verified single-invocation output | `Get-HHAuditRecord`, `Get-HHAuditOutput` | public cmdlets, query repository, package-backed E2E | confirmed |
| Durable publisher | Atomically publishes `.hhout` only after file and namespace durability barriers | Artifact completion | `Private/DurableFilePublisher.ps1`, `eng/durability/` | confirmed on Linux/macOS; Windows native proof pending |
| Windows persistence ACL adapter | Restricts data root, DB, key, and anchor to current user, SYSTEM, and local Administrators | Windows persistence creation/reopen | `Private/WindowsPersistenceAcl.ps1` | confirmed by policy units; native Windows proof pending |

### Build, gate, and development

| Component | Role | Entrypoints | Evidence | Confidence |
|---|---|---|---|---|
| Git hooks | Block commit and push on declared local lanes | Git `pre-commit`, `pre-push` | `.githooks/`, `scripts/hooks-install.sh` | confirmed |
| Host wrappers | Orchestrate bounded Compose and scanner runs | `scripts/verify-local.sh`, `scripts/precommit.sh`, `scripts/prepush.sh` | named scripts | confirmed |
| Test and SSH containers | Static/unit/client proof plus disposable PowerShell-over-SSH endpoint | Compose `test`, `ssh-target` | `Dockerfile.test`, `compose.test.yml`, `tests/fixtures/ssh/` | confirmed |
| Scanner containers | Secret, dependency, filesystem, and image scans | `scripts/security/scan-*.sh` | scanner wrappers | confirmed |
| Artifact store | Ignored logs and machine-readable proof | Host `.artifacts/` bind | `.gitignore`, `compose.test.yml` | confirmed |
| Public GitHub repository | Public source and review state; owner-only mutation policy | Git push, settings, pull requests | `AGENTS.md`, `SECURITY.md`, release plan | unknown until post-publication re-read |
| Standalone candidate gate | Rebuilds and verifies a detached exact SHA outside the candidate checkout | Release candidate command | `scripts/release/verify-candidate.sh`, external gate wrapper | confirmed implementation; exact-SHA receipt pending |

## 4. Trust Boundaries

| Boundary | From to To | Protections observed | Gaps | Evidence |
|---|---|---|---|---|
| Reviewed checkout to laptop gate | Repository code to host user and Docker authority | Owner-only mutation policy, manual review, hooks, bounded runners, detached exact-SHA gate | Candidate scripts and Keychain worker still execute with host-user authority after review | `AGENTS.md`, `.githooks/`, `scripts/release/` |
| Host to Docker daemon | Wrappers to local daemon | Fixed Compose project; validation containers receive no Docker socket | Host wrappers can issue Docker commands | `compose.test.yml`, verification wrappers |
| Registry and gallery to build | External packages/images to proof image | Exact versions, immutable digests, archive checksums | A trusted maintainer can still approve a compromised new pin | both Dockerfiles, scanner wrappers |
| Test client to SSH fixture | Candidate tests to disposable endpoint | Internal network, strict host key, no host bind, teardown | Test code can read the fixture credential by design | `compose.test.yml`, fixture scripts |
| Controller to SSH endpoint | Local module to remote PowerShell 7 runspace | Explicit SHA-256 fingerprint, managed `known_hosts`, native authentication, one attempt | Native PowerShell can omit precise OpenSSH failure details | SSH transport and integration tests |
| PowerShell 7 to Windows PowerShell 5.1 | Authenticated outer runspace to local compatibility process | Windows-only guard, Desktop 5.1 and process identity proof, tagged ordered envelopes, no fallback | A remote host can stall the child process; no product command-duration limit | `Private/SshTransport.ps1` |
| Remote output to local evidence | Untrusted endpoint data to in-memory capture and audit artifact | Six-stream allowlist, sequence checks, finite serialization, 100 MiB cap, AES-GCM at rest | Complete output can contain secrets; local user can decrypt it | transport and accountability source |
| HostHunter to macOS Keychain | Parent module to metadata-only `security` lookup and native byte worker | Exact login Keychain, hashed data-root account, raw key only on anonymous pipes, 15-second timeout and confirmed termination | Worker source is part of the checkout; same user/admin can inspect process memory | `Private/AuditKeyStore.ps1`, `Private/Workers/MacOSKeychainWorker.ps1` |
| HostHunter to SQLite evidence | Command, target, and result writers to authenticated local state | Encrypted sensitive fields, audit HMAC chain, target-state MAC, external anchor, startup recovery | Same user/admin can access runtime memory and platform keys | persistence and audit source |
| Module to packaged SQLite provider | Reviewed PowerShell to managed/native dependency graph | Exact lock/hashes, package-relative allowlisted RID, version assertion, extension loading disabled | Native code executes with controller-user authority | provider source and package proof |
| SQLite rows to encrypted fields | Searchable projections to command/identity/manifests | Identity-bound AEAD plus HMAC projection bindings | Same user/admin can request the platform master key and decrypt | audit repository and tamper tests |
| SQLite outcome to `.hhout` v2 | Artifact identity/publication to terminal DB record | Reserved artifact ID, chained chunk AAD/footer, DB hash and retrieval verification, no-replace rename and parent-directory durability barrier | Windows native `MoveFileExW` proof is pending | artifact/query source, `eng/durability/`, package tests |
| SQLite heads to platform anchor | DB commit to atomic Keychain or colocated seal update | Writer mutex, expected-value update and exact readback | Linux/Windows whole-root rollback remains undetectable | authenticated persistence and anchor tests |
| Operation lock to recovery | Remote batch ownership to next-process crash recovery | Separate no-follow lock held through terminal seal; killed unarmed/armed workers and live-owner contention tested without retry | Exact-candidate rerun remains pending | recovery source and SQLite fault lane |
| Windows user to persistence tree | Controller process to key, anchor, DB, and output state | Exact non-inherited ACL permits current user, SYSTEM, and local Administrators only; existing unsafe ACLs fail closed | Local administrators remain trusted; native exact-candidate proof is pending | `Private/WindowsPersistenceAcl.ps1`, persistence safety tests |
| HostHunter to Windows audit and registry APIs | Authenticated remote PowerShell to effective audit policy and command-line inclusion | Exact GUID/value allowlists, query-before-write, requery, privacy-first ordering, conditional compensation, no retry | Group Policy or another administrator can race or later replace effective state | policy and privilege adapters; native qualification pending |
| Owner to public GitHub | Authenticated owner and installed integrations to public repository | Intended single-owner write/admin, Actions disabled, branch deletion/force-push protection | Final collaborators, apps, rules, visibility, and Actions state require live verification | release plan; post-publication audit pending |

There is no public-network listener, browser session, tenant boundary, webhook,
or background queue. The SQLite database is local and adds no listener. Web
attacks, tenant crossover, and webhook replay are
therefore not applicable to this release.

## 5. Assets

| Asset | Where it lives | Why it drives risk |
|---|---|---|
| Controller and gate authority | macOS user, Docker daemon, SSH agent, Keychain | Candidate host execution can affect repositories, credentials, and managed endpoints |
| Endpoint password | Native interactive SSH path and macOS Keychain-backed local helper outside this repository | Compromise permits password authentication to the private endpoint |
| Endpoint private keys and passphrases | Per-user HostHunter key root, SSH agent, or explicitly selected key | Compromise permits remote administration |
| Complete command text | Encrypted fields in the owner-private SQLite database | May contain operational secrets and sensitive intent |
| Complete remote streams | Encrypted `.hhout` artifacts | May contain credentials, customer data, or forensic evidence |
| Audit master key | macOS login Keychain or non-macOS mode-0600 file fallback; briefly in process memory | Joint key/evidence compromise defeats confidentiality and local integrity claims |
| Repository administration | GitHub owner account, repository settings, installed apps | Unauthorized write could seed code for later trusted local execution |
| Proof integrity | Exact candidate SHA, scanner pins/config, reports | Determines whether a candidate is safe to publish |

## 6. Attacker Profile

Capabilities:

- Can propose malicious source through a public fork or pull request.
- If a managed endpoint is compromised, can emit adversarial objects and streams,
  hang, terminate, or change its SSH host identity.
- A local process running as the controller user can read plaintext ledger
  metadata and request access to that user's Keychain items.
- A local administrator can inspect process memory and modify user-owned files.

Non-capabilities:

- Cannot push, merge, administer, install repository integrations, or trigger the
  trusted laptop gate merely by opening a pull request under the confirmed policy.
- Cannot reach the disposable SSH fixture from the public internet under the
  checked-in internal-network topology.
- Does not receive the Docker socket or unrelated host-directory mounts inside
  validation containers.
- Cannot make a 5.1 request silently execute in PowerShell 7, or bypass the
  pinned SSH fingerprint merely by controlling command output.
- Is not assumed to have already compromised the OS kernel, Docker daemon,
  GitHub owner account, or an already-approved immutable upstream digest.

## 7. Abuse Paths

| ID | Attacker goal | Path | Class | Likelihood | Impact | Priority | Existing controls | Evidence |
|---|---|---|---|---|---|---|---|---|
| AP-01 | Execute with laptop-user authority | External proposal → missed manual-review issue → candidate hook/worker execution → host credentials | execution | low | high | medium | Owner-only writes; no automatic external execution; bounded hooks and lanes | `AGENTS.md`, `SECURITY.md`, `.githooks/` |
| AP-02 | Hide a leaked secret | Candidate scanner config → false-negative local scan → publication | detection-evasion | low | high | medium | Deterministic external snapshot includes tracked and non-ignored untracked files, force-tracked ignored canary proof, history scan, manual review | `.gitleaks.toml`, `scan-secrets.sh` |
| AP-03 | Read sensitive evidence | Local user process → plaintext command ledger or platform-key-backed stream decryption → retained evidence | exfiltration | medium | high | high | Restrictive files, AES-GCM streams, platform key, no committed artifacts | audit source, `.gitignore` |
| AP-04 | Substitute an SSH endpoint | DNS or server change → credential prompt or command dispatch → managed endpoint authority | access | low | high | medium | Explicit full fingerprint plus strict managed `known_hosts`; change fails closed | SSH trust source and tests |
| AP-05 | Steal the fixture password | Candidate test → group-readable runtime volume → fixture credential | access | high | low | low | Disposable credential, internal network, teardown, no host bind | Compose and fixture scripts |
| AP-06 | Escape a compromised fixture | Remote command → writable fixture root → network or host resources | execution | low | high | medium | Internal network, absent host bind, disposable container | `compose.test.yml` |
| AP-07 | Supply compromised proof tooling | Registry or gallery compromise → newly approved pin → gate result | integrity | low | high | medium | Immutable digests, exact versions, checksum verification, reviewed updates | Dockerfiles and scanner wrappers |
| AP-08 | Forge or erase accountability | Local admin → Keychain or file key plus evidence files → forged ledger, head, and output | integrity | medium | high | high | Intent-first lifecycle, authenticated encryption, chain and sealed head, recovery to `Unknown` | audit and Keychain source |
| AP-09 | Exhaust or stall the controller | Compromised endpoint → unlimited-duration direct or 5.1 command → controller resources | availability | medium | medium | medium | Per-target 100 MiB cap, connection timeout, no retry, bounded test lanes | transport source |
| AP-10 | Persist unintended remote access | Key bootstrap → wrong or lingering authorized-key entry → managed endpoint access | access | low | high | medium | Ed25519-only exact marker, separate key-only proof, exact-entry rollback, password profile retained on failure | bootstrap source and tests |
| AP-21 | Leak or retain qualification credentials | Native qualification → passphrase in process configuration, lingering agent identity, or wrong Keychain service cleanup → reusable local/remote authority | access | low | high | medium | Interactive passphrases only, run-scoped agent, exact identity removal and agent stop, production-derived Keychain services, pre-delete presence and post-delete absence checks | qualification scripts and focused contract tests; exact native receipts pending |
| AP-22 | Mistake token activation for elevation | Filtered token → `-Escalate` → operator assumes UAC/admin boundary was crossed | authorization | medium | high | high | Closed method registry; declared privilege only; ERROR_NOT_ALL_ASSIGNED fails; explicit no-UAC documentation | privilege adapter and focused tests; native proof pending |
| AP-23 | Leave a privilege enabled | success/error/cancellation → restore skipped or fails → later code inherits privilege | authorization | low | high | high | exact prior token state restored in finally; failed restore prevents success and requires reconciliation | privilege adapter tests; native proof pending |
| AP-24 | Expose secrets through 4688 command lines | inclusion enabled → sensitive arguments enter Security log | disclosure | medium | high | high | explicit non-default option; plaintext warning; no redaction claim; exact state verification | public tests; Windows qualification pending |
| AP-25 | Overwrite concurrent policy ownership | query → GPO/admin change → stale mutation or compensation | integrity | medium | high | high | requery, compare-before-compensate, conflict/reconciliation result, no retry | compensation tests; native proof pending |
| AP-26 | Redirect privileged execution through preference tampering | edit saved method → future `-Escalate` selects unintended method | authorization | low | high | high | closed enum, authenticated mutation chain, monotonic anchor, explicit-call precedence | schema-v2 and configuration tests |
| AP-11 | Confuse runtime attribution | Compromised endpoint → forged or malformed 5.1 stream protocol → incorrect audit result | integrity | low | high | medium | Outer PS7 and child Desktop 5.1 proof, stream/sequence/state allowlists, runspace attribution, fail-closed errors | transport source and tests |
| AP-12 | Gain repository write authority | Compromised owner or app → public repository mutation → later trusted execution | access | low | high | medium | Single-owner policy, no collaborators/teams, Actions disabled, planned branch protection and live settings audit | release plan; live state pending |
| AP-13 | Execute a substituted native provider | Tampered package/RID resolution → malicious SQLite library load → controller-user code execution | execution/integrity | low | high | high | Locked restore, exact hashes, package-relative RID allowlist, version assertion, SBOM and package scan | provider/package implementation and scans |
| AP-14 | Redirect a remote command | File tampering without the audit/anchor key → edit an active or inactive target row → resolve attacker endpoint → command dispatch | integrity | medium | high | high | Target-state MAC covers every profile/revision; authenticated anchor and strict SSH fingerprint | target repository and corruption tests |
| AP-15 | Swap or truncate output evidence | Move valid ciphertext between rows/invocations or remove final chunks → misleading audit output | integrity | low | high | medium | Database/ledger/invocation AAD, chained chunks/footer, DB hash/length, durable no-replace publication and retrieval verification | artifact/query implementation and tests |
| AP-16 | Regress audit/target state | Race two writers or restore DB behind anchor → hide command/redirect target | integrity | low | high | medium | Bounded writer mutex, expected-value anchor update/readback, monotonic checks, competing-writer and rollback fault tests | persistence implementation and SQLite fault lane; native final-candidate proof pending |
| AP-17 | Falsely recover a live command | Second process sees unterminated row → marks first process's live invocation unknown | integrity | low | high | medium | Separate operation lock, killed-worker/live-owner tests, no-retry declared/armed recovery | recovery implementation and SQLite fault lane |
| AP-18 | Break accountability through capacity exhaustion | Retained evidence or another process fills disk while eight targets emit output | availability/integrity | low | high | medium | Real 128 MiB per-invocation plus 64 MiB recovery reservation, streaming flush, aggregate cap, predispatch and external mid-command ENOSPC tests, honest unknown/no retry | persistence implementation and SQLite fault lane |
| AP-19 | Roll back complete non-macOS root | Restore fallback key, anchor, DB and artifacts together | integrity | low | high | high | Explicitly unmitigated in v1; no macOS-equivalent claim off macOS | Accepted residual in reviewed plan |
| AP-20 | Read or replace Windows persistence state through an unintended principal | Inherited or extra ACL principal → key/DB/output access → decrypt or alter evidence | access/integrity | low | high | medium | Existing ACLs are validated; new paths receive an exact protected three-principal ACL; unsafe state blocks operation | Windows ACL adapter and focused tests; native proof pending |

AP-03 and AP-08 remain high because complete evidence retention is a
confirmed product requirement and a central independently controlled sink is a
deferred non-goal. AP-01, AP-02, and AP-12 rise to critical if external
code is ever executed automatically or another principal receives write/admin
authority without a new threat review.

## 8. Recommended Mitigations

| Abuse path ID | Mitigation | Location | Control type |
|---|---|---|---|
| AP-01 | Move the laptop-gate controller and Keychain worker trust decision outside the candidate checkout before enabling automated external contributions | Standalone gate | Sandboxing and least privilege |
| AP-02 | Keep authoritative scan policy in trusted controller state and compare candidate policy hashes to an approved baseline | Gate controller and secret lane | Fail-closed proof |
| AP-03 | Add explicit retention/pruning without weakening accountability and later support an independently controlled evidence sink | Audit subsystem | Data minimization and secret isolation |
| AP-04 | Preserve explicit first trust and reject every fingerprint change before authentication | SSH trust adapter | Authentication and validation |
| AP-05 | Narrow fixture password access to password-auth journeys and rotate the runtime volume per run | Compose integration lane | Secret isolation |
| AP-06 | Add capability drops, `no-new-privileges`, resource limits, and egress restriction where the fixture remains functional | `ssh-target` service | Least privilege and quotas |
| AP-07 | Record resolved digest/checksum evidence and require full local proof for every pin update | Tooling matrix and Dockerfiles | Supply-chain integrity |
| AP-08 | Add an independently controlled append-only sink while retaining local verification; add an explicit verified key-rotation/recovery design | Audit subsystem | Tamper-evident audit and recovery |
| AP-09 | Add an explicit operator-selected command-duration limit and bounded compatibility-session cleanup | SSH transport | Timeouts and quotas |
| AP-10 | Add separately approved revoke/rotate commands with exact proof and rollback | Key lifecycle | Least privilege and recovery |
| AP-11 | Preserve protocol allowlists, completion correlation, and fail-closed attribution tests for every transport change | SSH transport tests | Validation and audit integrity |
| AP-12 | Re-read collaborators, teams, deploy keys, apps, Actions, branch rules, visibility, and remote SHA after every repository-policy change | GitHub administration | Least privilege and continuous verification |
| AP-13 | Restore and package only the committed lock graph, verify exact hashes/licences/SBOM, and scan the ignored final package itself | Provider/package lane | Supply-chain integrity |
| AP-14 | Authenticate every complete target snapshot and searchable projection before target resolution or dispatch | SQLite target adapter and anchor | Integrity validation |
| AP-15 | Preserve invocation-bound `.hhout` v2, durable publication, and cross-boundary corruption tests for every artifact-format change | Output writer/query | Authenticated evidence |
| AP-16 | Preserve serialized DB-to-anchor commits and rerun native Keychain CAS/rollback qualification on the exact candidate | Persistence/Keychain worker | Monotonic integrity |
| AP-17 | Preserve operation ownership and killed-process/no-retry fault cases in the exact-candidate gate | Public orchestration/recovery | Concurrency control |
| AP-18 | Preserve real capacity reservation and external ENOSPC/SQLITE_FULL fault cases in the exact-candidate gate | Output/persistence integration | Resource control |
| AP-19 | Keep the Linux/Windows whole-root rollback limitation explicit; require a future OS-external anchor for stronger claims | Platform storage | Honest residual-risk boundary |
| AP-20 | Run native Windows ACL creation/reopen/rejection proof against the immutable release package before publication | Windows qualification | Least privilege and fail-closed validation |
| AP-22 | Keep escalation providers closed and privilege-aware; never infer or enable every privilege for arbitrary command text | Public command and privilege resolver | Least privilege |
| AP-23 | Treat restoration failure as terminal failure with reconciliation required and finite evidence | Privilege scope and accountability | Cleanup integrity |
| AP-24 | Keep command-line inclusion explicit, warn before dispatch, and never claim Security-log redaction | Public policy cmdlet and documentation | Informed consent and data minimization |
| AP-25 | Preserve compare-before-compensate and no-retry semantics; report effective-now state and GPO override risk | Windows policy adapter | Concurrency integrity |
| AP-26 | Authenticate and anchor every preference mutation; reject unknown methods before dispatch | SQLite configuration repository | Integrity and allowlisting |

## 9. Assumptions and Open Questions

- `user-confirmed`: Only commands sent through HostHunter are in audit scope.
- `user-confirmed`: Complete command text and all six PowerShell streams are
  retained; `Reason` and `CaseId` are optional.
- `user-confirmed`: SSH password authentication is interactive initially;
  PowerShell support is mandatory; at most eight targets are in scope.
- `user-confirmed`: PowerShell 7 is the default runtime and Windows PowerShell
  5.1 is an explicit SSH compatibility choice with no fallback.
- `user-confirmed`: WinRM is deferred until a purpose-built controlled lab
  exists; no first-release positive WinRM claim is permitted.
- `user-confirmed`: The repository is public, but only `jimtin` may mutate or
  administer it; external contributions receive manual source review and never
  trigger trusted laptop execution automatically.
- `user-confirmed`: The SQLite plan has no legacy-data import, keeps target
  profiles plaintext inside owner-private storage, adds two audit-query cmdlets,
  and retains database/artifact evidence indefinitely in v1.
- `confirmed`: The macOS native Keychain create/read/delete lifecycle passed a
  disposable separate-process proof without a plaintext `audit.key`.
- `confirmed`: The SQLite contract, package RIDs, atomic anchor semantics,
  target/projection binding, operation ownership and arming, output v2,
  capacity, recovery, and query objects have focused, package-only, and
  container fault evidence in the current working tree.
- `unvalidated`: The immutable exact-SHA gate, native macOS anchor lifecycle,
  native Windows ACL/durable publication, and live PS7/5.1/bootstrap journey
  remain release blockers until the initial candidate exists.
- `accepted residual`: Linux/Windows colocated fallback key and anchor cannot
  detect rollback of the complete data root; only macOS Keychain supplies that
  first-release guarantee.
- `unvalidated`: The final GitHub visibility, collaborators, apps, Actions, branch
  rules, and remote SHA remain unknown until the post-publication settings audit.
- `unvalidated`: An independently controlled audit sink, retention/pruning,
  command-duration limits, Windows DPAPI storage, and key rotation are deferred.
