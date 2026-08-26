# HostHunterNextGeneration Threat Model

## 1. Summary

- High: a transport bypass could suppress audit; the AST boundary guard is the most valuable control.
- High: repeating uncertain SSH mutations could duplicate commands, keys, or policy changes.
- High: rollback of SQLite, anchors, secrets, or evidence could falsify history.
- High: Windows behavior is live-qualified for the working tree but is not yet
  release-proven for an exact committed SHA.
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

### Build and test

| Component | Role | Entrypoints | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| Cmdlet verifier | One eleven-row behavior/DB verdict | verify-cmdlets.sh | compose.cmdlets.yml; E2E journey | confirmed |
| Release state | One immutable claim/verdict per SHA | verify-candidate.sh | release-receipt-state.py | confirmed |
| Heavy proof | Coverage, integration, scans, production build | verify-local.sh | lane scripts | confirmed |
| Windows qualifier | Public-cmdlet mutation, Event 4688 proof, and restoration | Test-HHWindowsCmdlets.ps1 | qualification script; working-tree receipt | confirmed working-tree live result |

## 4. Trust Boundaries

| Boundary | From → To | Protections observed (auth, validation, rate limits) | Gaps | Evidence |
| --- | --- | --- | --- | --- |
| B1 | operator → dispatcher/public cmdlet | exact allowlist; validation | remote command remains powerful | runtime dispatcher; AP-5 |
| B2 | public cmdlet → engine | closed operations; AST guard; one delegation | guard must stay mandatory | engine/guard; AP-1 |
| B3 | engine → SSH adapter → host | intent/arm; fingerprint; PS7 identity; bounds | host controls content/timing | transport/audit; AP-2, AP-4, AP-6 |
| B4 | controller → five state roots | separate mounts; authentication; encryption | Docker/root trusted | compose.runtime.yml; AP-3 |
| B5 | checkout → exact-SHA gate → receipts | atomic claim; exclusive writes; terminal seal | operator trusted | release scripts; AP-7 |
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
| AP-4 | steal secrets/output | leak → B3/B4 → credentials/evidence | exfiltration | medium | high | high | dedicated roots; redacted receipts | Compose/receipts |
| AP-5 | misuse command power | Invoke-HHCommand → B1/B7 → systems | execution | medium | high | high | explicit action; reason/case audit | command/engine |
| AP-6 | spoof identity/exhaust | hostile endpoint → B3 → trust/availability | access | medium | high | high | fingerprint; PS7 marker; limits | transport/Compose |
| AP-7 | overwrite/rerun verdict | failed process → B5 → receipts | integrity | low | high | medium | atomic claim; O_EXCL; seal | release scripts |
| AP-8 | misread Windows policy state | native `AUDIT_NONE` representation → B3 → restoration verdict | integrity | low | high | medium | effective-bit normalization; Event 4688 proof; exact restoration | policy implementation/tests/qualification |

AP-1 through AP-6 are medium likelihood because realistic untrusted inputs must
also defeat an evidenced control. AP-7 is low because exclusive writes directly
prevent overwrite. Impact is high due to privilege or audit integrity.

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
| AP-2, AP-6, AP-8 | Repeat the green live-Windows journey against the packaged exact-SHA image | Windows release qualification | detective |

## 9. Assumptions and Open Questions

- user-confirmed: Linux Docker is the only controller; PS7/OpenSSH is the only host protocol.
- user-confirmed: authentication, encryption, anchors, rollback protection, and recovery remain.
- user-confirmed: internal Docker traffic is outside the host boundary.
- user-corrected: all controller-to-host behavior uses the audited engine.
- unvalidated: Docker administrators and the gate operator are trusted.
- unvalidated: minimum Windows and PowerShell versions remain to be fixed.
- validated for the working tree: a saved local Windows host and interactive
  Keychain credential exercised all eleven public cmdlets through the managed-host
  engine, verified Security Event 4688 command-line capture, and restored the
  original audit-policy and SSH-key state.
- pending release proof: the standalone gate must repeat that bounded journey
  against the packaged exact committed SHA; the ignored local receipt is not a
  substitute for immutable release evidence.
