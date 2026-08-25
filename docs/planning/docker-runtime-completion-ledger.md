# Docker Runtime And Delivery Completion Ledger

Status: IMPLEMENTATION APPROVED - 2026-08-26

This ledger is the source of truth for the approved cleanup, Docker runtime,
testing, and delivery work. HostHunter remains gate-owned: all canonical proof
runs locally in containers, the standalone laptop gate proves one exact
candidate SHA, and GitHub does not rerun tests.

## Acceptance ledger

| ID | Requirement | Implementation | Focused evidence | Status |
| --- | --- | --- | --- | --- |
| DR-01 | Preserve useful historical evidence, then remove raw coverage events, copied caches, superseded candidate trees, and other reproducible bulk | Create a compact redacted evidence index, verify its hashes, add an allowlisted cleanup command, and delete only classified ignored artifacts | Cleanup contract tests; before/after inventory; compact index validation; tracked-tree unchanged | verified: 25 GiB reduced to 6.4 MiB; 114 hash-verified receipts retained |
| DR-02 | Keep coverage working data and every retained successful proof bundle at or below 20 MiB | Replace per-hit JSONL/index/merged copies with compact per-outcome shards; enforce hard budgets; copy only allowlisted receipts | Coverage integrity self-test; budget overflow negative test; retained-bundle size assertions | verified focused |
| DR-03 | Run HostHunter entirely in Docker without macOS Keychain or a Windows credential store | Add a production multi-stage image and Compose runtime using non-root, read-only filesystems, no Docker socket, explicit resource/security controls, and external named volumes | Image contract tests; package-only import; clean-volume initialize/restart; filesystem/permission integration | verified focused: runtime contract 9/9 and lifecycle 7/7; production-image journey pending |
| DR-04 | Make Docker the canonical runtime for this and future releases | Add stable runtime launcher, doctor, initialization and exact-volume destruction workflows; update docs and release receipts | Fresh-machine-style Compose E2E; doctor negative matrix; documentation/static checks | implemented and focused-static green; canonical runtime proof pending |
| DR-05 | Provide permanent unattended Docker-volume secret and anchor storage | Add separate core and Forensics file providers with 0600 files, atomic no-replace/CAS writes, independent key/anchor volumes, provider identity binding, and fail-closed mismatch handling | Unit and multiprocess integration; wrong/missing/swapped key/anchor; partial rollback; restart | verified focused: 23 unit, 1 multiprocess integration, 95.10% changed-scope coverage; final candidate rerun pending |
| DR-06 | Preserve optional native macOS compatibility | Keep Keychain providers and native qualification as optional compatibility paths; Docker must not invoke them | Provider selection tests and Docker runtime scan asserting no native provider requirement | verified focused; exact runtime scan pending |
| DR-07 | Run every current public cmdlet as a user | Maintain an exact 11-cmdlet journey matrix covering success, WhatIf, restart, validation, mutation, read-only, failure, retry/unknown, and tamper states | Package-only CLI E2E plus exact-image Windows qualification | pending |
| DR-08 | Prove Windows PowerShell 7, Windows PowerShell 5.1, process auditing, escalation, and SSH-key journeys on the existing Windows target | Extend the exact-image qualification with PS7/PS51/mixed six-stream execution, process-policy snapshot/mutate/4688/restore, privilege restoration, protected-key transition, and exact cleanup | Redacted exact-candidate Windows receipt; no plaintext secrets or sampled command line | pending |
| DR-09 | Finish the approved ECS 9.5 Process Start internal slice without exposing incomplete acquisition cmdlets | Package and load the verified EVTX parser/normalizer/persistence/outbox internals; run deterministic Sysmon 1 and Security 4688 vertical journey in the isolated parser container; keep seven acquisition commands unexported | Parser/normalizer/persistence units >=95% changed-scope; package-only ECS integration; export inventory remains exactly 11 | verified focused and package-only; production-sidecar journey pending |
| DR-10 | Deliver exactly once | Run readiness, one exact-SHA standalone proof, exact-image native/live qualifications, threat-model review and gitleaks, then push that exact SHA to `main` and re-read remote state | Candidate receipt, package/image hashes, native/live receipts, gitleaks receipt, remote SHA/settings readback | pending |

## Test ledger

| Surface | Required proof | Status |
| --- | --- | --- |
| Compact coverage | Set/bitset aggregation, concurrent shards, deterministic merge, corruption/loss refusal, <=20 MiB cap | verified focused |
| Evidence retention | Allowlist only; no scanner cache, raw event log, checkout, package tree, or duplicate report copied into retained proof | verified focused and applied; retained history is 65,293 bytes |
| Runtime image | Exact package import, non-root UID, read-only root, dropped capabilities, no-new-privileges, bounded tmpfs, no Docker socket, logging disabled | pending |
| Runtime persistence | Fresh volumes, restart, exact provider identity, separate data/key/anchor volumes, owner-only modes, no Keychain invocation | provider focused proof green; production-runtime restart proof pending |
| Parser sidecar | Network none, no secrets/DB/SSH mounts, immutable input, bounded private socket stream, parser timeout/reap, no plaintext JSONL | focused contract and parser tests green; exact production-container journey pending |
| All 11 cmdlets | Complete action inventory in `docs/testing/e2e-workflow-inventory.md`, with each action executed through the built package | pending |
| Windows target | PS7, PS51, mixed attribution, six streams, process-start policy and command-line option, escalation, protected SSH key, password fallback, exact restoration/cleanup | pending |
| ECS Process Start | Sysmon 1 and Security 4688 -> ECS 9.5; deterministic IDs; encrypted at rest; non-start events excluded; malformed/oversize rejected | focused parser/persistence and package-only pipeline green; production-sidecar journey pending |
| Quality gates | >=90% statements/branches/functions/lines; >=95% changed scope; integration and CLI E2E green; static/dependency/image/security scans green | pending |
| Delivery | One clean exact SHA; proof bundle <=20 MiB; product image/archive separately hashed; gitleaks and threat model green; exact SHA pushed to main | pending |

## Removal classification

| Surface | Classification | Action |
| --- | --- | --- |
| Raw branch-hit JSONL and checksum indexes after compact merge | superseded | remove after compact receipt/index validation |
| Coverage partial merge files and instrumented module copies | reproducible | remove after current run finishes |
| Scanner caches copied into candidate evidence | dead duplication | stop copying; keep one external cache outside the repo |
| Superseded candidate checkout/package/evidence trees | reproducible | retain one compact historical summary, then remove |
| Current compact receipts and latest failure diagnostics | active | retain within budget |
| macOS Keychain providers | compatibility | retain and keep optional |
| WindowsPowerShell51 bridge | active | retain and live-qualify from the Linux controller |
| Seven planned Forensics acquisition cmdlets | incomplete/deferred | do not export in this release |

## Parallel work

| Lane | Exclusive ownership | Output |
| --- | --- | --- |
| Compact proof and cleanup | coverage collectors/reporters, release evidence copier, cleanup tooling and focused tests | deterministic compact evidence and verified cleanup command |
| Runtime container | production Dockerfile, runtime Compose, launcher/doctor/lifecycle scripts and focused container tests | production-grade multi-container runtime |
| Portable providers | Docker/file key and anchor provider code plus focused unit/integration tests | unattended non-Keychain core and Forensics persistence |
| Main integration | shared loader/package/docs, parser-sidecar integration, action inventory, final readiness/gate/qualification/push | one reconciled exact candidate |

## Non-goals and explicit boundaries

- Do not migrate or delete existing native macOS HostHunter state automatically.
- Do not publish the seven Part 1 acquisition cmdlets until their complete remote
  acquisition workflow exists.
- Do not add GitHub Actions.
- Do not treat Compose secrets as an encrypted secret manager.
- The Docker administrator is trusted in unattended mode and can read mounted
  keys or coordinate whole-environment rollback. This limitation must remain
  explicit in the threat model and operator documentation.
- The 20 MiB limit applies to retained proof bundles and coverage working data,
  not to the separately hashed runtime image or distributable module archive.
