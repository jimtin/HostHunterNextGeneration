# Invisible authentication implementation ledger

Status: CONFIRMED — implementation authorized 2026-08-27

## Acceptance ledger

| Requirement | Production change | Focused evidence | Status |
| --- | --- | --- | --- |
| Key-first onboarding | `Set-HHTarget` asks whether to install the recommended SSH key; Yes is default | native choice and key-onboarding journey | verified |
| Warn before saved password | exact risk warning plus a second confirmation before persistence | client protocol and native negative/positive journey | verified |
| Definite key failure fallback | offer encrypted-password fallback only after a definite failure | engine state-machine tests | verified |
| Uncertain key result stops | no fallback, retry, or target commit after uncertain dispatch/commit | engine negative tests | verified |
| Encrypted SQLite password | authenticated envelope in SQLite; decryption key remains in the separate secret volume | migration, crypto, and plaintext-leakage tests | verified |
| Invisible managed-host authentication | stored credential seeds the invocation broker without a client prompt | broker, transport, and macOS journey | verified |
| Credential lifecycle | replace atomically; delete after proven key conversion or target removal | repository integration tests | verified |
| No secret disclosure | no reveal/export/output/log/argument/environment/file/frame plaintext | bounded leakage assertions | verified |
| Clean test reset | destroy only the HostHunter controller and its five named volumes after isolated proof | fresh-runtime receipt and volume inventory | verified |
| Fun startup | interactive 3–4 second radar animation and welcome; suppressed elsewhere | client unit and fresh-profile checks | verified |
| Fast validation | focused lanes only; no coverage/build/scan/shard/retry | per-lane durations and terminal receipts | verified |

## User-action coverage matrix

HostHunter is a PowerShell CLI, so the installed-profile native journey is the
Playwright-equivalent user layer.

| User action | Surface | Role/state | Expected behavior | E2E evidence | Unit/integration evidence | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Open interactive PowerShell | profile import | trusted operator | radar animation runs once, then welcomes operator with derived command count | fresh installed-profile journey | animation rendering/suppression tests | covered |
| Open scripted/redirected PowerShell | profile import | automation | no animation or delay | native contract | suppression tests | covered |
| Onboard first-use SSH identity | `Set-HHTarget` | unknown pinned host | automatically pin and announce the selected fingerprint before any password request | native journey | SSH trust tests | covered |
| Accept recommended SSH key | `Set-HHTarget` | password-capable host | prompt once, install/prove key, save PublicKey target, retain no password | native key journey | engine/bootstrap/repository tests | covered |
| Decline recommended SSH key | `Set-HHTarget` | password-capable host | show full storage risks and ask again | native password journey | interaction tests | covered |
| Decline password storage | warning prompt | no target saved | request no password and persist nothing | focused CLI action test | engine/repository tests | covered |
| Accept password storage | warning prompt | trusted operator | prompt once, validate, atomically save encrypted credential | native password journey | migration/credential repository tests | covered |
| Key setup fails definitely | onboarding | known finite failure | show reason and offer warned password fallback | deterministic fixture | engine state-machine tests | covered |
| Key setup is uncertain | onboarding | uncertain remote result | stop; no fallback, retry, password commit, or success | negative fixture | engine/audit recovery tests | covered |
| Invoke using saved password | `Invoke-HHCommand` | encrypted password target | command succeeds without client credential frame | installed-profile journey | broker/engine tests | covered |
| Restart controller and invoke | runtime restart | encrypted password target | credential remains usable without prompt | installed-profile journey | persistence integration | covered |
| Saved password is rejected | any host operation | remote password changed | fail once with `Set-HHTarget` recovery guidance; never retry | negative fixture | transport/engine tests | covered |
| Convert password target to key | `Enable-HHSshKeyAuthentication` | stored password | no prompt; prove key and atomically delete credential | native journey | bootstrap/repository tests | covered |
| Remove target | `Remove-HHTarget` | stored password | atomically remove target and credential | cmdlet journey | repository integration | covered |
| Inspect target | `Get-HHTarget` | stored password | show `CredentialStorage: Encrypted`; never reveal secret | native journey | model/repository tests | covered |

## Security and data contract

- SQLite stores only an AEAD envelope. Associated data binds it to database
  identity, normalized target identity, endpoint, account, and target revision.
- Credential replacement increments the authenticated target generation and
  revision. A replayed valid envelope cannot authenticate against a newer
  target revision; whole-database rollback remains caught by the separate
  anchor volume.
- Password bytes cross only the native secure prompt, redirected standard
  input, the token-bound controller-loopback broker, the encrypt/decrypt call,
  and SSH askpass memory. Every owned buffer is cleared.
- Passwords never enter public target objects, audit artifacts, command
  metadata, arguments, process environment, files, receipts, or error text.
- Anyone controlling the trusted macOS account or Docker controller can use a
  saved credential. The warning states this before persistence.

## Focused test budgets

| Lane | Normal target | Hard limit |
| --- | ---: | ---: |
| Fresh migrations | 5 seconds | 15 seconds |
| Credential persistence | 10 seconds | 30 seconds |
| Plaintext leakage | 10 seconds | 30 seconds |
| Installed-profile macOS journey | 45–60 seconds | 120 seconds |

These lanes never invoke coverage, security scanners, image builds, shards,
worker fan-out, retries, or release aggregation. The animation is suppressed.

## Rollout and rollback

Implementation and focused proof use isolated test roots first. After they are
green, the exact HostHunter controller and its five named state volumes are
destroyed under the user's explicit testing-stage authorization. A fresh
runtime is rebuilt solely from committed migrations. Because compatibility is
explicitly waived, rollback to an older binary also requires destroying and
rebuilding the HostHunter state; no unrelated Docker project is touched.

## Parallel work

No parallel agents are used. Credential acquisition, encryption, target-state
anchoring, audit ordering, broker lifetime, and SSH dispatch are one coupled
security boundary, and the active tool policy prohibits delegation.
