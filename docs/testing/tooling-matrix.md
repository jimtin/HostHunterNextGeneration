# Tooling matrix

| Layer | Tool | Container | Command | Artifact |
| --- | --- | --- | --- | --- |
| Cmdlet acceptance | Pester plus read-only SQLite assertions | production-derived verifier + SSH fixture | `./scripts/verify-cmdlets.sh` | `.artifacts/cmdlets/<sha>/cmdlets/receipt.json` |
| Boundary guard | PowerShell AST inspection | test image | `scripts/static/Test-HHManagedHostBoundary.ps1` | terminal result |
| Native client contract | Pester protocol/proxy/install tests | test image | focused `NativeClient*.Tests.ps1` | `.artifacts/native-client-*.xml` |
| Native macOS qualification | fresh installed-profile client + production controller + disposable SSH fixture | macOS orchestration; product execution remains containerized | `scripts/client/Test-HHInstalledNativeClientSsh.ps1` | terminal 11-command summary |
| Credential migration/persistence | Pester + fresh SQLite from committed migrations | test image | focused `SqlitePersistence.Tests.ps1` and `CredentialPersistence.Tests.ps1` | terminal result; hard limits 15s/30s |
| Credential leakage | ciphertext/root/process/broker-frame assertions | test image | focused credential and native-protocol files | terminal result; hard limit 30s |
| Release-only unit coverage | Pester native profiler + in-memory branch-outcome collector | one test container / one `pwsh` process | `scripts/lanes/unit.sh` | `.artifacts/release-proof/unit/{unit-tests.xml,coverage.xml,coverage-summary.json,coverage.log}` |
| Critical integration | Pester + disposable SSH/SQLite | test image + SSH fixture | `scripts/lanes/integration.sh` | `.artifacts/release-proof/integration/` |
| SQLite fault proof | Docker Compose fault workers | purpose-built containers | `scripts/lanes/sqlite-integration.sh` | integration logs/results |
| Production build | Docker BuildKit | runtime image | `docker compose -f compose.runtime.yml build controller` | immutable image ID |
| Secrets | gitleaks wrapper | security container | `scripts/security/scan-secrets.sh` | security receipt |
| Dependencies/files/images | OSV/Trivy wrappers | security containers | `scripts/lanes/security.sh <images...>` | `.artifacts/security/` |
| Exact-SHA state | Python immutable receipt state machine | host orchestration only | `scripts/release/verify-candidate.sh <sha>` | `.artifacts/release/<sha>/` |

Host orchestration may invoke Docker and aggregate receipts. Canonical validation
runs inside containers. The cmdlet lane has one timeout owner, no worker fanout,
no retries, and no coverage or scan work.

The native macOS qualification is a platform-bound user-entry check, not a
coverage numerator. It retrieves fixture credentials only into test-process
memory and never prints them. Its one ordered journey covers key-first and
warned stored-password onboarding, invisible stored-password invocation,
credential purge after key conversion, and all eleven public cmdlets. It has a
120-second hard timeout and no retries or shards.

The unit coverage command has one timeout owner and exactly two fixed sequential
passes over the same unit suite: untouched source for native statement/line and
AST-owned function coverage, then an ephemeral branch-instrumented copy. It has
no network dependency, integration numerator, nested runner, worker fanout,
shards, retries, or per-hit disk writes. All shipped production files are in
scope; each of statements, branches, functions, and lines must be at least 90
percent, with a 92 percent engineering target and a 300-second hard timeout.
