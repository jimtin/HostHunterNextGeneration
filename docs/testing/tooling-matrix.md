# Tooling matrix

| Layer | Tool | Container | Command | Artifact |
| --- | --- | --- | --- | --- |
| Cmdlet acceptance | Pester plus read-only SQLite assertions | production-derived verifier + SSH fixture | `./scripts/verify-cmdlets.sh` | development: `.artifacts/cmdlets/<source-fingerprint>/<run-id>/cmdlets/receipt.json`; release: `.artifacts/cmdlets/<sha>/cmdlets/receipt.json` |
| Boundary guard | PowerShell AST inspection | test image | `scripts/static/Test-HHManagedHostBoundary.ps1` | terminal result |
| Native client contract | Pester protocol/proxy/install tests | test image | focused `NativeClient*.Tests.ps1` | `.artifacts/native-client-*.xml` |
| Native macOS qualification | fresh installed-profile client + production controller + disposable SSH fixture | macOS orchestration; product execution remains containerized | `scripts/client/Test-HHInstalledNativeClientSsh.ps1` | terminal 17-framework-command summary |
| Credential migration/persistence | Pester + fresh SQLite from committed migrations | test image | focused `SqlitePersistence.Tests.ps1` and `CredentialPersistence.Tests.ps1` | terminal result; hard limits 15s/30s |
| Credential leakage | ciphertext/root/process/broker-frame assertions | test image | focused credential and native-protocol files | terminal result; hard limit 30s |
| Fast unit smoke | Pester without coverage | one test container / one invocation | `scripts/lanes/unit-smoke.sh` | `.artifacts/unit-smoke/{unit-smoke.xml,unit-smoke.log}` |
| Release-only unit coverage | Standard Pester profiler | one networkless test container | `scripts/lanes/unit.sh` | `.artifacts/release-proof/unit/{unit-tests.xml,coverage.xml,coverage-summary.json,coverage.log}` |
| SQLite fault proof | Docker Compose fault workers | purpose-built containers | `scripts/lanes/sqlite-integration.sh` | integration logs/results |
| Production build | Docker BuildKit | runtime image | `docker compose -f compose.runtime.yml build controller` | immutable image ID |
| Secrets | gitleaks wrapper | security container | `scripts/security/scan-secrets.sh` | security receipt |
| Dependencies/files/images | OSV/Trivy wrappers | security containers | `scripts/lanes/security.sh <images...>` | `.artifacts/security/` |
| Exact-SHA state | Python immutable receipt state machine | host orchestration only | `scripts/release/verify-candidate.sh <sha>` | `.artifacts/release/<sha>/` |
| Pre-commit | Gitleaks + static + focused unit selection | host orchestration, container execution | `.githooks/pre-commit` | `.artifacts/logs/precommit.log`; 45s hard limit |
| Pre-push | Gitleaks + dependency + static + unit smoke + cmdlet journey | host orchestration, container execution | `.githooks/pre-push` | `.artifacts/logs/prepush.log`; 180s hard limit / 120s normal target |

Host orchestration may invoke Docker and aggregate receipts. Canonical validation
runs inside containers. The cmdlet lane has one timeout owner, no worker fanout,
no retries, and no coverage or scan work. Its in-process preflight validates the
manifest-derived journey, migration inventory, fresh state, fixture readability,
and receipt durability before the first cmdlet. Fixture-secret and host-artifact
permissions use separate named supplementary groups.

The native macOS qualification is a platform-bound user-entry check, not a
coverage numerator. It retrieves fixture credentials only into test-process
memory and never prints them. Its one ordered journey covers key-first and
warned stored-password onboarding, invisible stored-password invocation,
credential purge after key conversion, and all seventeen public framework cmdlets. It has a
90-second hard timeout and no retries or shards.

The unit coverage command has one timeout owner and uses only standard native
coverage evidence. It has no network dependency, integration numerator,
instrumented source copy, nested runner, worker fanout, shards, retries, or
per-hit disk writes. All shipped production files and full source hashes remain
in its inventory. Commands inside the three Windows-only remote CIM bodies are
owned by the positive Windows qualification instead of the Linux unit
denominator; their factories and non-Windows fail-closed branches remain in
unit scope, and the receipt records the exact owned ranges and command count.
No other production commands are removed. Statements, executable lines, and
invoked functions must each be at least 90 percent, with a 92 percent
engineering target. Explicit behavioral tests own branch confidence.
