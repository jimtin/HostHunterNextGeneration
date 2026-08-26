# Tooling matrix

| Layer | Tool | Container | Command | Artifact |
| --- | --- | --- | --- | --- |
| Cmdlet acceptance | Pester plus read-only SQLite assertions | production-derived verifier + SSH fixture | `./scripts/verify-cmdlets.sh` | `.artifacts/cmdlets/<sha>/cmdlets/receipt.json` |
| Boundary guard | PowerShell AST inspection | test image | `scripts/static/Test-HHManagedHostBoundary.ps1` | terminal result |
| Unit coverage | Pester/custom four-metric collector | test image | `scripts/lanes/unit.sh` | `.artifacts/release-proof/unit/` |
| Critical integration | Pester + disposable SSH/SQLite | test image + SSH fixture | `scripts/lanes/integration.sh` | `.artifacts/release-proof/integration/` |
| SQLite fault proof | Docker Compose fault workers | purpose-built containers | `scripts/lanes/sqlite-integration.sh` | integration logs/results |
| Production build | Docker BuildKit | runtime image | `docker compose -f compose.runtime.yml build controller` | immutable image ID |
| Secrets | gitleaks wrapper | security container | `scripts/security/scan-secrets.sh` | security receipt |
| Dependencies/files/images | OSV/Trivy wrappers | security containers | `scripts/lanes/security.sh <images...>` | `.artifacts/security/` |
| Exact-SHA state | Python immutable receipt state machine | host orchestration only | `scripts/release/verify-candidate.sh <sha>` | `.artifacts/release/<sha>/` |

Host orchestration may invoke Docker and aggregate receipts. Canonical validation
runs inside containers. The cmdlet lane has one timeout owner, no worker fanout,
no retries, and no coverage or scan work.
