# HostHunter Forensics Part 1 Threat Model

## 1. Summary

- The highest-risk boundary is attacker-controlled endpoint evidence crossing
  archive, transfer, EVTX parser, and ECS-mapper boundaries on the controller.
- The local ECS Process Start slice now uses a pinned, native-sandboxed
  out-of-process parser, strict byte and schema limits, encrypted event/outbox
  bodies, deterministic identity, and immutable-source replay.
- Remote acquisition remains blocked until authenticated AES-256 ZIP64 and the
  non-logging artifact-secret relay pass native interoperability and leakage
  tests. No weaker encryption or plaintext fallback is acceptable.
- Exact remote cleanup is a separate high-risk authority. It must be unable to
  address original/live logs or staged raw evidence and must never replay an
  uncertain deletion automatically.
- A compromised endpoint can still lie about event content. HostHunter can
  prove acquisition, bytes, processing, and delivery; it cannot prove endpoint
  truthfulness.

## 2. Scope and Method

In scope: the confirmed Part 1 Process Start feature; proposed
`ExtractionArtifacts` and `Forensics` module trees; complete event-log
acquisition; artifact secret lifecycle; authenticated nested archives; binary
transfer; immutable spool; `evtx_dump`; ECS mapping; separate `forensics.db`,
key and monotonic anchor; API token and exact-byte outbox; remote generated-
outer cleanup; build/package assets; and local validation.

Out of scope: Part 2 application implementation, browser/viewer security,
Process Stop, process correlation, non-process ECS mappings, Rust processing,
positive WinRM, automatic evidence pruning, and claims that endpoint-produced
events are intrinsically trustworthy.

The system is a local PowerShell module controlled by one investigator. It has
no public listener. It connects to managed Windows endpoints over pinned SSH
and later sends normalized events to a loopback Part 2 API. Confidence tags:
`confirmed` is supported by current code or the user-confirmed contract;
`inferred` is a direct design consequence; `unknown` awaits Phase HH-0/native
qualification.

## 3. System Model

### Runtime

| Component | Role | Entrypoints | Evidence | Confidence |
|---|---|---|---|---|
| Existing HostHunter core | Target snapshots, SSH trust, command intent/arm/outcome, operation ownership | Existing public cmdlets and new private orchestration hooks | `src/HostHunterNextGeneration/Public/Invoke-HHCommand.ps1`, `Private/SshTransport.ps1`, `Private/AuditOrchestration.ps1` | confirmed |
| ExtractionArtifacts capability | Exact nested packaging, password protection, validation, expansion, transfer and generated-outer cleanup | Future file-acquisition consumers | Part 1 sections 5 and 7 | user-confirmed design; implementation unknown |
| Acquisition coordinator | Stages a complete directory and consumes bounded live artifact records | `Start-HHEventLogAcquisition` and retry/stop actions | Part 1 sections 6 and 7 | user-confirmed design; implementation unknown |
| Immutable spool | Retains encrypted outer, inner, raw EVTX, manifests and receipts | Transfer/validation workers and parser | Part 1 section 8; current `DurableFilePublisher.ps1` | inferred; durable primitive confirmed |
| Parser and ECS mapper | Runs pinned `evtx_dump` locally and emits ECS 9.5.0 Process Start | Verified local EVTX | `Forensics/Private/Parser`, `Normalization`, and `Contracts` | implemented; package and native macOS proof |
| Forensics persistence | Separate workflow DB, encrypted event/outbox bodies, authenticated ledger and monotonic anchor | Local parser/delivery workers | `Forensics/Private/Persistence`, `Migrations`, and `Delivery` | implemented for the local slice |
| Part 2 client | Sends dependency-ordered exact-byte PUT resources to loopback API | Local outbox worker | Part 1 section 12 | user-confirmed boundary; server out of scope |

### Build, CI, and development

| Component | Role | Entrypoints | Evidence | Confidence |
|---|---|---|---|---|
| Package builder | Packages exact module, native SQLite/durability/parser/archive assets and provenance | `scripts/lanes/build.sh` | `scripts/build/Test-HHModulePackage.ps1`, `Dockerfile.test` | confirmed current pattern; new assets unknown |
| Local gates | Containerized static, unit, integration, CLI E2E, security, build and image proof | Hooks and standalone exact-SHA gate | `AGENTS.md`, `scripts/verify-local.sh`, `scripts/release/verify-candidate.sh` | confirmed |
| Test fixtures | Synthetic/redacted EVTX, malicious archives, API stub, SSH target | Focused and canonical lanes | Part 1 section 17 | planned |

## 4. Trust Boundaries

| Boundary | From → To | Protections observed | Gaps | Evidence |
|---|---|---|---|---|
| Controller → Windows endpoint | HostHunter to SSH/PowerShell | Exact host-key pin, runtime proof, intent/arm/outcome, no retry | Endpoint can be compromised and can stall or lie | Existing SSH/audit source |
| Endpoint raw file → packager | Potentially hostile path/bytes to archive helper | Proposed restricted acquisition root, fixed entries and IDs | Helper/library not yet qualified | Part 1 section 7 |
| Keychain → endpoint packager | Random archive password through secret-only child input | Proposed opaque references, no args/env/files/logs | Relay and memory/unknown-delivery behavior not yet proven | Part 1 sections 7.2 and 14 |
| Encrypted outer → local archive reader | Untrusted bytes to authentication/decompression | Proposed fixed AES profile, exact two entries, bounds and hashes | Library/interoperability not yet selected | Part 1 sections 7.2 and 14 |
| Verified EVTX → `evtx_dump` | Attacker-controlled binary format to native parser | Pinned 0.12.2 asset/digest, private staging, bounded streams/resources, supervised consumer, macOS sandbox denies network/write/read/fork | Native parser remains code-processing attacker data | Focused parser tests and native macOS denial proof |
| Parser JSONL → ECS mapper | Parser-rendered untrusted values to canonical evidence | Strict UTF-8/JSON/provider/event/version/shape/size validation, real Draft 2020-12 schema checks and golden mappings | Future Windows event versions require explicit contract updates | Focused ECS tests |
| ECS mapper → forensics DB/outbox | Sensitive command lines and provenance to persistent state | Separate Keychain key/anchor, AEAD bodies, authenticated complete-row projection and exact-byte batches | Public orchestration intentionally remains unexported | Persistence/outbox focused tests |
| Outbox → loopback Part 2 API | Exact event bytes and producer credential to local service | Keychain credential, scoped verifier, idempotency/content digest | Part 2 implementation and auth contract unconfirmed | Part 1 section 12 |
| Cleanup coordinator → endpoint filesystem | Local receipt identity to remote delete authority | Proposed fixed staging root, immutable receipt, handle-bound identity/hash, separate intent | Implementation not yet present; wrong deletion is irreversible | Part 1 section 7.5 |
| Dependency registry → package | Native parser/archive/SQLite assets to controller execution | Existing exact versions/digests/SBOM/scans | Archive helper and parser packaging provenance not yet implemented | Build scripts and Part 1 HH-0 |

Public web, tenant, webhook, browser, and public-upload boundaries are low
relevance because Part 1 is a single-user local CLI with a loopback-only API.

## 5. Assets

| Asset | Where it lives | Why it drives risk |
|---|---|---|
| Raw EVTX and retained archives | Owner-private immutable spool | Potentially sensitive evidence; integrity and chain of custody matter |
| Command lines, users and paths | ECS event bodies and API requests | May contain plaintext credentials, tokens and personal data |
| Archive passwords and API token | macOS Keychain and process memory | Disclosure exposes retained artifacts or API write authority |
| Forensics master key and anchor | Separate Keychain items | Joint compromise defeats local confidentiality/integrity claims |
| `forensics.db` and outbox | Owner-private data root | Drives replay, cleanup eligibility, status and evidence provenance |
| Remote live logs and staged raw files | Managed Windows endpoint | Must never be cleanup targets |
| Remote generated transport ZIP | Restricted staging root | Only object the cleanup function may delete |
| Parser/archive native code | Packaged RID assets | Executes with controller/endpoint authority on attacker-shaped bytes |

## 6. Attacker Profile

Capabilities:

- A compromised managed endpoint can provide malicious EVTX/archive bytes,
  false metadata, unusual names, enormous files, malformed stream records, or
  stalls.
- A local process running as the controller user can read user-owned files and
  request access to that user's Keychain items.
- A malicious external contribution can propose dependency, parser, helper,
  scanner, or test changes for later maintainer review.
- The Part 2 loopback service may be unavailable, full, stale, or return
  ambiguous responses.

Non-capabilities:

- An external contributor cannot automatically execute code on the laptop or
  push/merge/administer the owner-only repository under the confirmed policy.
- A remote endpoint cannot choose the local spool root, Keychain account,
  outbox URI, or cleanup target directly.
- The attacker is not assumed to have already compromised the OS kernel,
  GitHub owner account, Docker daemon, or an approved immutable dependency
  digest.
- HostHunter is not expected to determine whether a compromised endpoint's
  logged claims are truthful; it must preserve that limitation explicitly.

## 7. Abuse Paths

| ID | Attacker goal | Path (entrypoint → boundary → asset) | Class | Likelihood | Impact | Priority | Existing controls | Evidence |
|---|---|---|---|---|---|---|---|---|
| AP-01 | Execute code or crash controller through evidence | Endpoint → encrypted package/raw EVTX → archive/parser → controller process | execution, availability | medium: endpoint compromise is in scope | high: controller-user code execution/evidence loss | high | Strict SSH identity and planned pinned bounded helpers | SSH source; confirmed HH-0 contract |
| AP-02 | Exfiltrate command lines or archive secrets | ECS/password/token → DB, argv, env, log, receipt or API diagnostic | exfiltration | medium: many serialization surfaces | high: operational secrets may be present | high | Existing Keychain/AEAD/redaction patterns; confirmed encrypted-body rule | key/audit source; Part 1 section 14 |
| AP-03 | Escape archive paths or exhaust disk | Malicious outer/inner → decompression/path handling → local spool/system disk | integrity, availability | medium | high | high | Fixed entries and proposed path/entry/ratio/size bounds | Part 1 sections 7 and 14 |
| AP-04 | Delete live or changed evidence | Forged/stale staged record → cleanup coordinator → endpoint filesystem | integrity, detection-evasion | low after strict design, otherwise plausible | high: irreversible evidence loss | high | Deletion authority limited to immutable generated-outer receipt; no replay | Part 1 section 7.5 |
| AP-05 | Poison canonical process identity | Malformed/duplicate timestamps, PIDs, GUIDs or record IDs → mapper → graph/outbox | integrity, detection-evasion | medium | high | high | Length-framed deterministic IDs, PID-never-alone, strict versions/golden vectors | Confirmed ECS contract |
| AP-06 | Forge provenance while preserving valid syntax | Compromised endpoint → false event content → valid archive/hash/ledger | integrity | high: endpoint controls source content | medium | medium | Host key, byte hashes, immutable receipts and explicit limitation | Confirmed scope |
| AP-07 | Duplicate or mutate delivered evidence | Timeout/conflict → rebuilt batch/body → Part 2 resource | integrity | medium | medium | medium | Exact-byte durable outbox, idempotency key/content digest, conflict quarantine | Part 1 sections 11-13 |
| AP-08 | Roll back or rewrite local workflow state | Local file access → DB/anchor/artifacts → stale or forged state | integrity | low for remote attacker; medium local | high | high | Separate HMAC ledger, target-state evidence and external monotonic Keychain anchor pattern | Current persistence implementation; Part 1 design |
| AP-09 | Exhaust acquisition resources | Complete directory/large files → packaging, transfer, parser, outbox → disk/CPU/memory | availability | medium | medium | medium | Measured reservations, backpressure, one parser, file/event limits, explicit deferred state | Part 1 sections 9, 11 and 13 |
| AP-10 | Execute a compromised native dependency | Registry/update → package asset → controller/endpoint | execution, integrity | low | high | high | Immutable digests, licenses, SBOM, package inventory, scanners and manual review | Existing build/gate policy |

Likelihood and impact use the confirmed local single-investigator deployment,
a potentially compromised endpoint, and no automatic execution of external
contributions. AP-01 through AP-05 remain release-blocking high priorities
until their listed recommended controls are implemented and tested.

## 8. Recommended Mitigations

| Abuse path ID | Mitigation | Location | Control type |
|---|---|---|---|
| AP-01 | Pin parser/archive assets by RID and digest; run parser out of process with no network and hard CPU/memory/time/stdout/stderr limits; fail on malformed shape | Parser runner, package builder, HH-0 qualification | dependency pinning, sandboxing, schema validation |
| AP-02 | AEAD-encrypt canonical event and exact HTTP body bytes before SQLite; keep secrets in distinct Keychain services; scan every forbidden serialization/log surface | Forensics persistence, secret relay, API client | secret isolation, encryption, redaction |
| AP-03 | Enforce fixed entry names/count/depth, no links/reparse/ADS, same-root publication, ZIP64/size/ratio/time/disk limits, and authenticate before publication | ExtractionArtifacts validation/expansion | input validation, sandboxing, quotas |
| AP-04 | Resolve cleanup solely from immutable receipt; open no-follow handle, compare volume/file identity and hash, delete through the same handle, and never auto-retry Unknown | Cleanup service and coordinator | authorization, fail-closed state machine, audit logging |
| AP-05 | Publish cross-language canonical tuple vectors; validate provider/event/version; preserve raw forms/null reasons; quarantine same ID/different hash | ECS mapper and API contract | schema validation, integrity checks |
| AP-06 | Label endpoint claims as acquired observations, retain raw EVTX, source hashes, host-key/target revision and parser identity, and avoid authenticity claims | Receipts, ECS `hosthunter.*`, documentation | provenance, audit logging |
| AP-07 | Persist encrypted exact bytes before PUT; resend only identical bytes; classify retryable/permanent/unknown responses; record every attempt | Delivery/outbox | idempotency, replay protection |
| AP-08 | Use separate key/anchor, append-only MAC ledger, startup verification, crash-ahead reseal only after full verification, and rollback refusal before dispatch | Forensics persistence | tamper evidence, fail-closed startup |
| AP-09 | Reserve measured raw+inner+outer+DB space before work, stream instead of buffering, bound queues, and expose PAUSED/DEFERRED rather than retry loops | Capacity, acquisition and parser scheduling | quotas, backpressure, observability |
| AP-10 | Locked dependency graph, immutable checksums, package inventory, SBOM/license record, malicious fixture corpus, gitleaks/OSV/Trivy and exact-SHA gate | `eng/`, Dockerfile, package/security lanes | supply-chain controls |

## 9. Assumptions and Open Questions

- `user-confirmed`: acquisition covers the complete requested event-log
  directory while normalization emits only Sysmon 1 and Security 4688.
- `user-confirmed`: ECS 9.5.0 is canonical and custom provenance uses
  `hosthunter.*`.
- `user-confirmed`: full command lines are retained as protected canonical
  evidence with a non-blocking warning.
- `user-confirmed`: the local verified-EVTX vertical slice precedes remote
  acquisition.
- `user-confirmed`: Part 2 is loopback/local and is not implemented in this
  repository slice.
- `unvalidated`: the later remote slice's authenticated AES-ZIP implementation, Windows
  staging primitive, secret relay and binary transfer meet the required native
  security/performance contract. These are HH-0 blockers, not assumptions used
  to lower risk.
- `unvalidated`: representative real-world file-size distributions and
  retention capacity. Until measured, limits remain conservative and remote
  acquisition cannot be qualified.
