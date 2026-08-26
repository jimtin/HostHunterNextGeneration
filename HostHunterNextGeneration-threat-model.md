# HostHunterNextGeneration Threat Model

## 1. Summary

- High: a transport bypass could suppress audit; the AST boundary guard is the most valuable control.
- High: repeating uncertain SSH mutations could duplicate commands, keys, or policy changes.
- High: forged proxy metadata or credential-protocol frames could execute local
  client code or disclose a password.
- High: rollback of SQLite, anchors, secrets, or evidence could falsify history.
- High: candidate-owned coverage code could omit source or forge a passing
  percentage unless the standalone gate independently validates the receipt.
- High: the first exact-SHA Windows qualification stopped before key bootstrap
  because key generation unexpectedly requested a passphrase; the candidate is
  terminally failed and cannot be retried.
- Overall posture is fail-closed; focused integrity/recovery evidence and live
  Windows proof are green, with immutable exact-SHA release proof still pending.

## 2. Scope and Method

In scope: production module/container, cmdlet verifier, SSH fixture, and exact-SHA
release receipts. Out of scope: provider publication and downstream networking
initiated by arbitrary user PowerShell. HostHunter runs as one Linux PowerShell
7 container; five public cmdlets contact OpenSSH hosts and six use authenticated
local state. Each entrypoint was traced through engine, transport, persistence,
container, and release boundaries.

Confidence: confirmed means file evidence; inferred means a reasonable
consequence; unknown means not determined.

## 3. System Model

### Runtime

| Component | Role | Entrypoints | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| Controller | Imports module and invokes allowed cmdlets | controller entrypoint | Dockerfile.runtime; runtime scripts | confirmed |
| Public module | Eleven operator actions | Public scripts | module manifest | confirmed |
| Managed-host engine | Closed five-operation coordinator | Invoke-HHManagedHostOperation | ManagedHostOperation.ps1 | confirmed |
| SSH adapter | Trust, PS7 identity, streams, cleanup | engine-only calls | SshTransport.ps1; SshTrust.ps1 | confirmed |
| Persistence | Authenticated SQLite, anchors, encrypted output, recovery | local cmdlets and engine | audit, anchor, migrations | confirmed |
| macOS client | Native generated proxies and framed Docker bridge | profile import; eleven proxy functions | HostHunter.Client | confirmed |
| credential broker | Command-scoped SSH askpass handoff | redirected stdin and controller loopback | client protocol; askpass helper | confirmed |

### Build and test

| Component | Role | Entrypoints | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| Cmdlet verifier | One eleven-row behavior/DB verdict | verify-cmdlets.sh | compose.cmdlets.yml; E2E journey | confirmed |
| Release state | One immutable claim/verdict per SHA | verify-candidate.sh | release-receipt-state.py | confirmed |
| Candidate build | Builds four exact-SHA images once and binds immutable IDs | build-candidate.sh | build receipt | confirmed |
| Coverage proof | One process, two unit-only passes, four independent metrics | unit.sh | coverage runner and summary | confirmed |
| Remaining release proof | Critical integration and source/image scans | verify-local.sh | terminal phase receipt | confirmed |
| Windows qualifier | Public-cmdlet mutation, Event 4688 proof, and restoration | Test-HHWindowsCmdlets.ps1 | qualification script; working-tree receipt | confirmed working-tree live result |

## 4. Trust Boundaries

| Boundary | From → To | Protections observed (auth, validation, rate limits) | Gaps | Evidence |
| --- | --- | --- | --- | --- |
| B1 | operator → dispatcher/public cmdlet | exact allowlist; validation | remote command remains powerful | runtime dispatcher; AP-5 |
| B0 | macOS PowerShell → Docker controller | source fingerprint; closed actions; bounded NDJSON/CLIXML; non-executable proxy declarations | local Docker administrator remains trusted | client module/protocol; AP-12, AP-13 |
| B2 | public cmdlet → engine | closed operations; AST guard; one delegation | guard must stay mandatory | engine/guard; AP-1 |
| B3 | engine → SSH adapter → host | intent/arm; fingerprint; PS7 identity; bounds | host controls content/timing | transport/audit; AP-2, AP-4, AP-6 |
| B4 | controller → five state roots | separate mounts; authentication; encryption | Docker/root trusted | compose.runtime.yml; AP-3 |
| B5 | checkout → exact-SHA gate → receipts | read-only preflight; atomic claim; exclusive writes; terminal seal | operator trusted | release scripts; AP-7 |
| B8 | candidate source → coverage container → release verdict | read-only source; exact inventory/hash; four thresholds; external receipt validator | candidate owns the collector under test | coverage scripts; standalone gate; AP-9, AP-10, AP-11 |
| B6 | Docker lifecycle/health → controller | local orchestration | dismissed: no host data and parser/API removed | compose.runtime.yml |
| B7 | remote command → downstream systems | request/outcome audited | prevention dismissed: user code controls activity | Invoke-HHCommand; AP-5 |

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
| Coverage denominator and receipt | exact tree and heavy receipt | prevents omitted code or stale proof from authorizing release |
| Interactive password | SecureString and command-scoped broker memory | grants initial managed-host access |

## 6. Attacker Profile

Capabilities:

- control a managed host or craft hostile output;
- interfere with a network before SSH trust succeeds;
- contribute code attempting a bypass;
- access one exposed volume;
- interrupt local proof.

Non-capabilities:

- cannot administer Docker/root or replace all roots;
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
| AP-9 | forge a coverage pass | candidate collector → B8 → release verdict | integrity / detection-evasion | medium | high | high | external gate recomputes inventory/hash and enforces all four metrics | coverage receipt validator |
| AP-10 | ship instrumented runtime code | ephemeral branch rewrite → B8 → production image | integrity / execution | low | high | medium | separate untouched build; production image probe-token rejection | build-candidate.sh |
| AP-11 | exhaust or loop the gate | branch hit → B8 → local compute/storage | availability | low | medium | low | in-memory hit set; two fixed invocations; 300-second bound; no retries | coverage runner; verify-local.sh |
| AP-12 | execute injected local proxy code | forged metadata → B0 → macOS session | execution | low | high | medium | exact image fingerprint; unique names; declaration AST allows parameter metadata only; size caps | client metadata synchronization |
| AP-13 | disclose or replay a password | malicious frame/process → B0 → credential | credential access | medium | high | high | local secure prompt; one request; stdin; random broker token; loopback only; no args/env/files/logs; buffer clearing | client protocol qualification |

AP-1 through AP-6 are medium likelihood because realistic untrusted inputs must
also defeat an evidenced control. AP-7 is low because exclusive writes directly
prevent overwrite. AP-9 remains high priority because a contributor can change
candidate-owned test code, but the independently maintained validator prevents
that code from silently omitting shipped source or lowering a metric. AP-10 and
AP-11 are lower likelihood after the production-token check and bounded
in-memory collector. Impact is high where privilege or release integrity is at
stake.

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
| AP-9 | Keep exact-tree inventory/hash and four-metric validation outside the candidate repository | standalone laptop gate | preventative |
| AP-10 | Reject branch-probe tokens in the production image before qualification | exact-SHA build phase | preventative |
| AP-11 | Keep one process, two fixed invocations, terminal timeout receipt, and zero retries | coverage/release runner | preventative/detective |
| AP-12 | Keep metadata schema/fingerprint/AST/duplicate checks and static no-transport client guard | native client | preventative |
| AP-13 | Keep one-prompt protocol, frame bounds, token-bound loopback, memory clearing, and fixture leakage assertions | native client/credential broker | preventative/detective |
| AP-2, AP-6, AP-8 | Repeat the green live-Windows journey against the packaged exact-SHA image | Windows release qualification | detective |

## 9. Assumptions and Open Questions

- user-confirmed: Linux Docker is the only controller; PS7/OpenSSH is the only host protocol.
- user-confirmed: authentication, encryption, anchors, rollback protection, and recovery remain.
- user-confirmed: internal Docker traffic is outside the host boundary.
- user-corrected: all controller-to-host behavior uses the audited engine.
- user-confirmed: coverage includes every shipped source file, remains unit-only,
  and preserves four independent 90-percent thresholds.
- user-confirmed: independent release phases run once, Windows precedes
  coverage, and no failed exact SHA is retried.
- user-confirmed: macOS PowerShell auto-starts Docker, synchronizes exports, and
  uses one generic native bridge; checked-out source changes rebuild once but
  never trigger an automatic Git pull.
- unvalidated: Docker administrators and the gate operator are trusted.
- unvalidated: minimum Windows and PowerShell versions remain to be fixed.
- terminal exact-SHA evidence: candidate `652157af4a3ab21702b9895d3efffb3f946b8e5f`
  passed the eleven-cmdlet container journey, then the live-Windows phase stopped
  at an unexpected `ssh-keygen` passphrase prompt before remote key installation.
  The candidate remains consumed and failed.
- remediation: dedicated Ed25519 generation supplies an explicit empty
  passphrase without putting a credential in arguments, environment variables,
  files, logs, or receipts. A new exact SHA must prove the full Windows journey;
  the failed SHA must never be rerun.
