# HostHunterNextGeneration Threat Model

## 1. Summary

- High: a transport bypass could suppress audit; the AST boundary guard is the most valuable control.
- High: repeating uncertain SSH mutations could duplicate commands, keys, or policy changes.
- High: forged proxy metadata or credential-protocol frames could execute local
  client code or disclose a password.
- High: a durable saved password increases the impact of combined controller,
  data-volume, and secret-volume compromise; encryption protects a stolen
  database alone but cannot protect against a trusted running controller.
- High: automatic first-use SSH trust can pin an impersonating host when
  onboarding occurs across a hostile network without an independently supplied fingerprint.
- High: rollback of SQLite, anchors, secrets, or evidence could falsify history.
- High: a forged or replayed visualizer observation could merge the wrong host
  or reset a mission unless identities, body hashes, and idempotency keys stay bound.
- High: candidate-owned coverage code could omit source or forge passing native
  metrics unless the standalone gate independently validates the receipt.
- High: copying live authentication state for Windows qualification would widen
  secret exposure or create an inconsistent snapshot unless the source is
  paused, mounted read-only, copied only into labeled disposable volumes, and
  cleaned on every terminal path.
- Overall posture is fail-closed; focused integrity/recovery evidence is green.
  Candidate `11aca1fe562f4bd5e80f7d6fe0a3fa13db9ccba6` is terminally
  consumed after its Windows phase bypassed the native interaction broker. The
  saved-key correction and final twelve-command exact-SHA proof are pending.

## 2. Scope and Method

In scope: production module/container, host-details collection, visualizer
producer, cmdlet verifier, SSH fixture, and exact-SHA release receipts. Out of
scope: endpoint event logs, provider publication, and downstream networking
initiated by arbitrary user PowerShell. HostHunter runs as one Linux PowerShell
7 container; six public cmdlets contact OpenSSH hosts and six use authenticated
local state. Each entrypoint was traced through engine, transport, persistence,
container, visualizer contract, and release boundaries.

Confidence: confirmed means file evidence; inferred means a reasonable
consequence; unknown means not determined.

## 3. System Model

### Runtime

| Component | Role | Entrypoints | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| Controller | Imports module and invokes allowed cmdlets | controller entrypoint | Dockerfile.runtime; runtime scripts | confirmed |
| Public module | Twelve framework cmdlets | Public scripts | module manifest | confirmed |
| Managed-host engine | Closed six-operation coordinator | Invoke-HHManagedHostOperation | ManagedHostOperation.ps1 | confirmed |
| SSH adapter | Trust, PS7 identity, streams, cleanup | engine-only calls | SshTransport.ps1; SshTrust.ps1 | confirmed |
| Persistence | Authenticated SQLite, encrypted credential/output envelopes, anchors, recovery | local cmdlets and engine | audit, anchor, migrations | confirmed |
| macOS client | Twelve generated framework proxies, one alias, and two local lifecycle commands | profile import | HostHunter.Client | confirmed |
| Visualizer producer | One bounded status/read and write HTTP adapter | producer status GET; mission and observation PUT routes | VisualizerProducer.ps1; CIM_Specification | confirmed |
| interaction broker | Command-scoped risk confirmation, credential acquisition, and SSH askpass handoff | redirected stdin and controller loopback | client protocol; confirmation/credential/askpass helpers | confirmed |

### Build and test

| Component | Role | Entrypoints | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| Cmdlet verifier | One twelve-row behavior/DB verdict | verify-cmdlets.sh | compose.cmdlets.yml; E2E journey | confirmed |
| Release state | One immutable claim/verdict per SHA | verify-candidate.sh | release-receipt-state.py | confirmed |
| Candidate build | Builds four exact-SHA images once and binds immutable IDs | build-candidate.sh | build receipt | confirmed |
| Coverage proof | One networkless standard-profiler unit pass with three independent native metrics | unit.sh | coverage runner and summary | confirmed implementation; exact-SHA result pending |
| Remaining release proof | Critical integration and source/image scans | verify-local.sh | terminal phase receipt | confirmed |
| Windows qualifier | Disposable clone of the five operator trust roots, public-cmdlet saved-key proof, Event 4688 proof, and restoration | windows-cmdlets.sh; Test-HHWindowsCmdlets.ps1 | qualification scripts and exact-image receipt | confirmed implementation; new exact-SHA result pending |

## 4. Trust Boundaries

| Boundary | From → To | Protections observed (auth, validation, rate limits) | Gaps | Evidence |
| --- | --- | --- | --- | --- |
| B1 | operator → dispatcher/public cmdlet | exact allowlist; validation | remote command remains powerful | runtime dispatcher; AP-5 |
| B0 | macOS PowerShell → Docker controller | source fingerprint; closed actions; bounded NDJSON/CLIXML; non-executable proxy declarations; invocation-scoped credential broker | local Docker administrator is intentionally trusted | client module/protocol; AP-12, AP-13, AP-15 |
| B2 | public cmdlet → engine | closed operations; AST guard; one delegation | guard must stay mandatory | engine/guard; AP-1 |
| B3 | engine → SSH adapter → host | intent/arm; fingerprint; PS7 identity; bounds | host controls content/timing | transport/audit; AP-2, AP-4, AP-6 |
| B4 | controller → five state roots | separate data/secret/anchor/key/evidence mounts; AEAD; authenticated state generations | combined controller/data/secret access can use or decrypt saved passwords by accepted design | compose.runtime.yml; AP-3, AP-4, AP-15 |
| B5 | checkout → exact-SHA gate → receipts | read-only preflight; atomic claim; exclusive writes; terminal seal | operator trusted | release scripts; AP-7 |
| B8 | candidate source → coverage container → release verdict | read-only source; exact inventory/hash; three native thresholds; explicit behavioral branch contracts; external receipt validator | candidate owns the collector under test | coverage scripts; standalone gate; AP-9, AP-10, AP-11 |
| B6 | Docker lifecycle/health → controller | local orchestration | dismissed: no host data and parser/API removed | compose.runtime.yml |
| B7 | remote command → downstream systems | request/outcome audited | prevention dismissed: user code controls activity | Invoke-HHCommand; AP-5 |
| B9 | controller → private visualizer producer API | file-only token; private Docker network; bounded status GET; exact write-body SHA-256; UUID idempotency keys; bounded body/time | bearer token compromise permits forged producer reads/writes until rotation | VisualizerProducer.ps1; compose.runtime.yml; AP-16 |
| B11 | macOS lifecycle client → local Docker/Visualizer repositories | configured absolute paths; fixed allowlisted scripts/actions; loopback browser URL; bounded/redacted diagnostics | trusted local repository or Docker administrator can still replace executed lifecycle code | HostHunter.Client/Private/VisualizationLifecycle.ps1; installer; AP-19 |
| B10 | managed host identity → controller observation | remote native identity is SHA-256 digested, then controller HMACs it into an opaque endpoint ID | compromised endpoint can lie about its inventory | HostDetails.ps1; VisualizerRepository.ps1; AP-17 |
| B12 | live operator trust roots → disposable Windows-qualification roots | exact five-role label validation; sole-controller and saved-key readiness checks; source pause; read-only source mounts; copy in networkless hardened container; cloned mission pause; trap cleanup | trusted Docker administrator can inspect either source or disposable volumes by accepted design | windows-cmdlets.sh; AP-20 |

## 5. Assets

| Asset | Where it lives | Why it drives risk |
| --- | --- | --- |
| SSH credentials/keys | secret and key roots | grants host access |
| Host trust/profiles | SQLite and known-host state | controls execution destination |
| Intent/outcomes | SQLite audit tables | supports recovery/accountability |
| Remote output | encrypted evidence root | may contain sensitive data |
| Anchors/generations | anchor root and chains | detects rollback/tamper |
| Policy/authorized keys | managed hosts | partial mutation can persist privilege |
| Release verdicts | .artifacts/release/SHA | determines ship eligibility |
| Native coverage denominator and receipt | exact tree and independent coverage receipt | prevents omitted code, weakened thresholds, or stale proof from authorizing release |
| Interactive password | SecureString and command-scoped broker memory | grants initial managed-host access |
| Stored password envelope | SQLite ciphertext; key material in separate secret root | enables invisible privileged host authentication |
| Host observations | encrypted SQLite payload and authenticated visualizer state | drives endpoint identity and visualization |
| Mission identity/state | authenticated SQLite and visualizer API | controls visualization reset and observation grouping |
| Visualizer producer token | owner-private runtime secret file | authorizes write-only mission/observation ingestion |
| Disposable qualification state | run-scoped data, secret, anchor, key, and evidence volumes | temporarily grants the exact image the same host authority as the live controller |

## 6. Attacker Profile

Capabilities:

- control a managed host or craft hostile output;
- interfere with a network before SSH trust succeeds;
- contribute code attempting a bypass;
- access one exposed volume;
- interrupt local proof.

Non-capabilities:

- cannot administer Docker/root or replace all roots unless they already are a
  user-trusted local operator;
- cannot obtain trusted interactive credentials by assumption;
- cannot make Linux evidence prove Windows mutation.

## 7. Abuse Paths

| ID | Attacker goal | Path (entrypoint → boundary → asset) | Class | Likelihood | Impact | Priority | Existing controls | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AP-1 | contact host without audit | source change → B2 → transport/history | detection-evasion | medium | high | high | closed engine; AST guard | engine/guard |
| AP-2 | repeat mutation | interruption → B3 → command/key/policy | execution | medium | high | high | durable arm; Unknown; no retry | engine/recovery |
| AP-3 | falsify history | volume access → B4 → DB/evidence/anchors | integrity | medium | high | high | authentication; separate roots; encryption | persistence |
| AP-4 | steal secrets/output | leak → B3/B4 → credentials/evidence | exfiltration | medium | high | high | dedicated roots; redacted receipts; noninteractive empty-passphrase dedicated-key generation | Compose/receipts/key bootstrap |
| AP-5 | misuse command power | Invoke-HHCommand → B1/B7 → systems | execution | medium | high | high | explicit action; reason/case audit | command/engine |
| AP-6 | spoof identity/exhaust | hostile endpoint → B3 → trust/availability | access | medium | high | high | fingerprint; PS7 marker; limits | transport/Compose |
| AP-7 | overwrite/rerun verdict | failed process → B5 → receipts | integrity | low | high | medium | atomic claim; O_EXCL; seal | release scripts |
| AP-8 | misread Windows policy state | native `AUDIT_NONE` representation → B3 → restoration verdict | integrity | low | high | medium | effective-bit normalization; Event 4688 proof; exact restoration | policy implementation/tests/qualification |
| AP-9 | forge a coverage pass | candidate collector → B8 → release verdict | integrity / detection-evasion | medium | high | high | external gate recomputes inventory/hash and enforces three native metrics | coverage receipt validator |
| AP-10 | omit shipped source or weaken a threshold | candidate coverage configuration → B8 → release verdict | integrity / detection-evasion | medium | high | high | exact source inventory/hash and fixed external threshold contract | coverage receipt validator |
| AP-11 | exhaust or loop the gate | native profiler → B8 → local compute | availability | medium | medium | medium | one root timeout; terminal receipt; no retry or diagnostic rerun | coverage runner; verify-local.sh |
| AP-12 | execute injected local proxy code | forged metadata → B0 → macOS session | execution | low | high | medium | exact image fingerprint; unique names; declaration AST allows parameter metadata only; size caps | client metadata synchronization |
| AP-13 | disclose or replay a password | malicious frame/process → B0 → credential | access / exfiltration | medium | high | high | local secure prompt; one request; stdin; random broker token; loopback only; no args/env/files/logs; buffer clearing | client protocol qualification |
| AP-14 | pin an impersonating host on first contact | network interception → B3 → host trust/password | access / exfiltration | medium | high | high | deterministic supported-key selection; fingerprint announcement; pin before credential; optional supplied fingerprint; changed-key hard failure | SshTrust.ps1; trust and native-client tests |
| AP-15 | recover or silently use a saved remote password | controller compromise or combined data/secret access → B0/B4 → stored credential/managed host | access / exfiltration | medium | high | high | trusted-operator model; separate roots; AEAD endpoint/revision binding; no reveal/export surface; explicit storage warning; purge on key conversion/removal | credential repository, engine, and persistence tests |
| AP-16 | forge or replay visualization state | token theft or payload replay → B9 → mission/observation state | integrity | low | high | medium | private network; file secret; UUID resource IDs; exact body digest; PUT idempotency; one attempt | producer, Compose, visualizer contract |
| AP-17 | merge or expose endpoint identity | hostile endpoint data → B10 → endpoint graph | privacy / integrity | medium | high | high | raw identity hashed remotely; controller HMAC; raw value is not output, logged, persisted, or sent; target data remains attributed and partial | collector/repository/security tests |
| AP-18 | turn inventory into continuous surveillance | feature expansion → collector/API → endpoint telemetry | privacy / availability | low | high | medium | fixed on-demand/first-connect operation only; no event-log fields, polling, subscription, or retry worker | public surface, docs, deleted-surface sweep |
| AP-19 | execute or disclose through visualizer startup | replaced local repo/script or hostile diagnostic → B11 → operator shell/output | execution / disclosure | low | high | medium | trusted local-operator model; configured absolute repo; fixed `up.sh`/`down.sh`; fixed controller actions; loopback-only URL; diagnostic redaction and size bounds; no automatic retry | client lifecycle and native-client contract tests |
| AP-20 | steal credentials or corrupt operator state during qualification | release invocation → B12 → copied or source trust roots | exfiltration / integrity | low | high | medium | source labels, sole active user, and one saved key validated before claim; source controller paused; source mounts read-only; copied mission paused; copies stay in Docker volumes; no password/TTY/raw-SSH path; cleanup trap removes disposable volumes | windows-cmdlets.sh; WindowsQualification.Tests.ps1 |

AP-1 through AP-6 are medium likelihood because realistic untrusted inputs must
also defeat an evidenced control. AP-7 is low because exclusive writes directly
prevent overwrite. AP-9 and AP-10 remain high priority because a contributor
can change candidate-owned test code, but the independently maintained validator
prevents that code from silently omitting shipped source or lowering a metric.
AP-11 remains bounded by one terminal attempt and cannot trigger a retry loop.
Impact is high where privilege or release integrity is at stake.

## 8. Recommended Mitigations

| Abuse path ID | Mitigation | Location (file/component/boundary) | Control type |
| --- | --- | --- | --- |
| AP-1 | Keep boundary guard and negative bypass fixtures mandatory | scripts/static and module | preventative |
| AP-2 | Assert one arm/contact/terminal and zero redispatch | engine/recovery integration | preventative/detective |
| AP-3 | Retain tamper, rollback, anchor, output, migration tests | release integration | detective |
| AP-4 | Keep credentials dedicated, receipts redacted, scans required | qualification/security/release | preventative |
| AP-5 | Preserve reason/case audit and downstream responsibility docs | command docs/audit | governance |
| AP-6 | Keep fingerprint/PS7 and output/stall limits | SSH/container | preventative |
| AP-7 | Preserve consumed-SHA markers and require a new SHA | release cleanup | preventative |
| AP-8 | Preserve effective success/failure-bit comparison and restoration tests | Windows policy implementation | preventative/detective |
| AP-9 | Keep exact-tree inventory/hash and three-native-metric validation outside the candidate repository | standalone laptop gate | preventative |
| AP-10 | Require the exact shipped-source inventory and fixed 90-percent thresholds in the independent receipt validator | exact-SHA receipt state | preventative |
| AP-11 | Keep one root timeout, terminal timeout/aborted receipt, and zero retries | coverage/release runner | preventative/detective |
| AP-12 | Keep metadata schema/fingerprint/AST/duplicate checks and static no-transport client guard | native client | preventative |
| AP-13 | Keep one-prompt protocol, frame bounds, token-bound loopback, memory clearing, and fixture leakage assertions | native client/credential broker | preventative/detective |
| AP-14 | Keep changed-key rejection fail-closed and document supplying an independently verified fingerprint for onboarding across untrusted networks | managed-host engine/native client/docs | preventative/governance |
| AP-15 | Keep endpoint/revision-bound ciphertext, separate keys, no reveal/export path, explicit warning, atomic purge, and plaintext-leakage tests | credential repository/engine/broker/native client | preventative/detective |
| AP-16 | Keep producer token file-only, network-private, body-hash-bound, idempotent, bounded, and rotated with the visualizer deployment | producer/Compose/visualizer | preventative/detective |
| AP-17 | Keep remote digest plus controller HMAC, encrypted local payload, per-field provenance, and raw-identifier negative tests | collector/repository/contract | preventative/detective |
| AP-18 | Retain negative surface assertions for event logs, polling, subscriptions, and retry workers | module/runtime/testing docs | preventative/governance |
| AP-19 | Keep lifecycle scripts/actions closed, browser URL loopback-only, diagnostics bounded/redacted, startup failures isolated, and animation suppressed in automation | native client/installer | preventative/detective |
| AP-20 | Keep pre-claim source/saved-key readiness, pause/read-only clone, exact five-volume allowlist, cloned mission pause, noninteractive saved-key proof, redacted receipts, and cleanup-on-every-exit contract | Windows qualification wrapper and release state | preventative/detective |
| AP-2, AP-6, AP-8 | Repeat the green live-Windows journey against the packaged exact-SHA image | Windows release qualification | detective |

## 9. Assumptions and Open Questions

- user-confirmed: Linux Docker is the only controller; PS7/OpenSSH is the only host protocol.
- user-confirmed: authentication, encryption, anchors, rollback protection, and recovery remain.
- user-confirmed: internal Docker traffic is outside the host boundary.
- user-corrected: all controller-to-host behavior uses the audited engine.
- user-confirmed: coverage includes every shipped source file, remains unit-only,
  and preserves independent 90-percent statement, executable-line, and invoked-
  function thresholds; branch confidence is provided by explicit behavioral
  tests rather than custom AST instrumentation.
- user-confirmed: independent release phases run once, Windows precedes
  coverage, and no failed exact SHA is retried.
- user-confirmed: macOS PowerShell auto-starts Docker, synchronizes exports, and
  uses one generic native bridge; checked-out source changes rebuild once but
  never trigger an automatic Git pull.
- user-confirmed: choosing SSH authorizes automatic first-use host-key pinning;
  HostHunter announces the selected algorithm and fingerprint without a second
  trust prompt. Changed identities still fail closed before credentials are sent.
- user-confirmed: target names default to the authenticated remote computer name
  and target creation is additive.
- user-confirmed: HostHunter operators, the macOS account, and Docker
  administrators are trusted; the accepted warning states that this access can
  use saved remote credentials.
- user-confirmed: SSH key is the default onboarding choice; definite key setup
  failure may offer encrypted-password fallback only after the risks are shown
  and separately confirmed. Uncertain key outcomes never fall back or retry.
- user-confirmed: stored passwords are permanently deleted after proven key
  conversion and target removal.
- user-confirmed: only client-local `Start-HHVisualization` can create or
  continue a mission after authenticated producer status; controller and shell
  startup never create or reset one. `Stop-HHVisualization` pauses publishing.
- user-confirmed: host details are collected after target onboarding and on
  demand through the same audited engine; missing fields are acceptable.
- user-confirmed: only initial/on-demand host information is in scope. Windows
  event logs, process activity, polling, subscriptions, and automatic retries
  are excluded.
- unvalidated: minimum Windows and PowerShell versions remain to be fixed.
- terminal exact-SHA evidence: candidate
  `11aca1fe562f4bd5e80f7d6fe0a3fa13db9ccba6` passed the twelve-row
  Linux cmdlet verifier, then its live-Windows phase stopped at Set-HHTarget
  because the direct container module call could not service the native-client
  `confirmation_request`. The candidate remains consumed and aborted.
- remediation: the release gate now preflights the existing runtime, clones its
  five trust-domain volumes into disposable state, and uses the saved PublicKey
  profile noninteractively. Existing-key enablement performs one audited proof
  through the managed-host engine without bootstrap, password, retry, or raw
  SSH. A new exact SHA must prove the full Windows journey; the failed SHA must
  never be rerun.
