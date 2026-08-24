# macOS Audit-Key Keychain Readiness

## Status

**IMPLEMENTED AND LIVE-VERIFIED - 2026-08-24**

This document proves the existing audit master-key item. The subsequently
confirmed `docs/planning/sqlite-persistence-plan.md` adds a second,
data-root-scoped Keychain item for the monotonic authenticated database/audit
and target-state head. That second item is planned and not yet implemented or
live-verified.

The SQLite readiness review further freezes that second item's contract: it is
a bounded versioned binary envelope, not a 32-byte key; updates use native
`SecKeychainItemModifyAttributesAndData` with expected-current comparison and
exact readback under the database writer mutex. Delete/recreate is prohibited
because it introduces a missing-anchor crash window. Missing-anchor creation is
allowed only for a provably empty sequence-zero database. These requirements do
not change the already verified master-key lifecycle below.

## Requirement summary

On a macOS controller, HostHunterNextGeneration must create and retrieve its
32-byte audit master key from the user's default macOS Keychain. The key must
never be written to the repository, a plaintext runtime file, a command-line
argument, a log, or a test artifact. Linux and Windows retain the existing
private file provider for this preview so container proof and future Windows
qualification remain possible; OS-native providers for those controllers are
separate follow-up work.

## Existing pattern

`Get-HHMasterKey` owns key acquisition behind the audit context, while all
cryptographic functions already accept an explicit 32-byte key. The change
therefore belongs in `Private/Configuration.ps1` and does not alter the public
cmdlet contract or the audit cryptography format.

## Architecture

- Use a generic-password item in the default login Keychain.
- Use service `com.hosthunter.nextgeneration.audit-key.v1`.
- Derive the account identifier from SHA-256 of the canonical data-root path,
  so separate HostHunter data roots receive separate keys without putting the
  path itself in the Keychain account field.
- Store exactly 32 raw bytes and validate the length on every read.
- Invoke `/usr/bin/security login-keychain` without a shell only to resolve the
  exact login-Keychain path. The CLI never reads or writes the key.
- Launch a bounded child `pwsh` worker that uses native Security-framework byte
  APIs. Creation receives the key through anonymous standard input; reads return
  exactly 32 bytes through anonymous standard output. Secret bytes never appear
  in argv, environment variables, files, logs, or errors.
- Never use `-U`: creation must not overwrite an existing item. If another
  process wins a creation race, re-read and use the authoritative stored key.
- If a legacy `audit.key` exists, fail closed rather than rotate, import, or
  delete it automatically. An explicit migration tool is deferred until a
  separately approved lifecycle defines how existing evidence is preserved.
- Keychain reads, writes, corrupt values, denial, timeout, and unexpected exit
  codes fail closed with messages that do not include secret output.

The rejected naive approach is passing the key with `security -w VALUE`:
Apple's installed command help labels `-w`/`-p` arguments insecure. The safe
prompted `-w` form was also tested and rejected because it requires a TTY and
does not consume redirected input. The other rejected approach is silently
generating a replacement after a read error, because that would make existing
audit evidence unverifiable.

## Verified limits and capabilities

- The audit format requires exactly 32 bytes; this is enforced by the existing
  cryptographic boundary.
- The installed `/usr/bin/security` command help confirms generic-password
  creation, login-Keychain selection, non-overwriting creation, and prompted
  `-w` input. Checked locally on 2026-08-23.
- A disposable host-only live contract confirmed native creation,
  retrieval from a separate child process, fixed-time 32-byte equality, exact
  deletion, and a missing post-delete read. No plaintext `audit.key` or
  disposable data-root directory remained.

## Data lifecycle and rollback

There is no audit-key file-to-Keychain schema migration. New macOS installations generate the key in
Keychain. A legacy file is never changed automatically; its presence blocks
remote activity with migration guidance. Rollback to the old code would
require intentionally exporting the Keychain value back to a mode-0600 file
and is not automatic.

## Failure and security behavior

- Missing item: generate once, create without overwrite, then verify.
- Locked, denied, unavailable, or timed-out Keychain: block remote activity.
- Corrupt or wrong-length value: block remote activity; never rotate silently.
- Concurrent creation: re-read the winner; never overwrite it.
- Legacy file detected: preserve it and block for operator resolution.
- Same-user compromise remains able to invoke trusted local tooling and is not
  solved by Keychain; this change improves at-rest secret handling and removes
  the colocated plaintext key.

## Proof evidence

- Container unit tests cover the parent process boundary and native-worker
  contract for reads, creation, corruption, failures, races, legacy detection,
  timeout termination, and redaction: 37 AuditKeyStore and 21 Configuration
  focused cases passed.
- Existing Linux file-provider tests remain green in the Configuration suite.
- Changed-scope four-metric coverage target is at least 95%; repository gates
  remain at least 90% for statements, branches, functions, and lines.
- Configured PSScriptAnalyzer and repository static checks must pass.
- The disposable host-only macOS native lifecycle passed. It is supplemental,
  not canonical container evidence.
- The 2026-08-24 canonical working-tree gate passed, including the full unit,
  static, security, and build lanes. Exact-commit proof, final history scanning,
  and publication remain pending.

## Parallel work

One worker owns `Configuration.ps1` and its focused unit tests. A separate
read-only worker audits public-release sensitivity. The main agent owns docs,
threat-model reconciliation, integration, live Keychain/Windows evidence,
commit policy, and publication.

## Open questions

None for this slice. Windows Credential Manager and Linux Secret Service are
explicitly deferred from the macOS-first preview.
