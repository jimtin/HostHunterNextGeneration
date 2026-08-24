# Tooling Matrix

## Status

**ADOPTED SQLITE TOOLCHAIN; EXACT-CANDIDATE AND NATIVE EXECUTION PENDING
2026-08-24**

All pre-migration foundation rows are active and container-proven. The confirmed
SQLite amendment rows are implemented unless explicitly marked pending below.
Direct PowerShell 7 and negative runtime paths remain
canonical-container evidence; positive Windows PowerShell 5.1 and mixed-runtime
evidence require a separate live Windows exact-candidate lane.

| Tool | Purpose | Layer | Container/service | Exact local command | Version checked 2026-08-23 | Update policy | Status | Exception/equivalent |
|---|---|---|---|---|---|---|---|---|
| PowerShell | Test/runtime shell | All PowerShell lanes | Checksum-built test image | `docker compose -f compose.test.yml run --rm test pwsh -NoProfile ...` | 7.6.5 | Monthly; full gate | active | Official archives verified by SHA-256 |
| PowerShell compatibility floor | Minimum supported controller proof | Package/integration | Separate checksum-built compatibility image | `./scripts/qualification/Test-HHControllerMatrix.ps1 -PowerShellVersion 7.4.19` | 7.4.19, checked 2026-08-24 | Monthly; full gate | active | Checksum-pinned x64/arm64 archives; packaged SQLite 3.53.4/schema-v1 smoke |
| .NET SDK | Locked NuGet restore only | Build/dependencies | Digest-pinned build stage | `./scripts/dependencies/restore-sqlite.sh` | 10.0.400, checked 2026-08-24 | On dependency change; full gate | active | Build-time only; SDK is not shipped with the module |
| Microsoft.Data.Sqlite.Core | Managed SQLite provider | Product persistence/build | Locked build-only SDK restore and packaged RID assets | `./scripts/dependencies/restore-sqlite.sh` | 10.0.11, checked 2026-08-24 | On dependency change; full gate | active | PowerShell calls provider directly; the durability helper is separate and first-party |
| SQLitePCLRaw.bundle_e_sqlite3 | Managed/native provider bundle | Product persistence/build | Locked build-only SDK restore and packaged RID assets | `./scripts/dependencies/restore-sqlite.sh` | 3.0.5, checked 2026-08-24 | On dependency change; full gate | active | `Batteries_V2.Init()` once; native library adjacent |
| SQLite | Embedded database engine package published by SourceGear | Product persistence/integration | Packaged per-RID native asset | `./scripts/dependencies/restore-sqlite.sh` | 3.53.4, checked 2026-08-24 | On dependency change; full gate | active | Exact NuGet package ID is `SQLite`; runtime version asserted in package integration |
| SQLite schema/integrity runner | `0001_initial_sqlite`, PRAGMAs, schema/checksum and chain validation | Unit/integration | Test image plus real per-run database | `./scripts/lanes/sqlite-integration.sh` | repo-owned | With every schema change | active | Existing unmatched DB fails; no v1 restore/import |
| SQLite fault/concurrency harness | WAL, operation/writer locks, busy/full/capacity, crash, anchor and artifact boundaries | Integration | Isolated Compose/fresh-process/bounded-volume harness | `./scripts/lanes/sqlite-integration.sh` | repo-owned | With persistence changes | active | Nine-scenario redacted receipt; no remote retry |
| Persistence changed-scope coverage | 95% target for repo-owned persistence logic plus 90% repository hard gate | Unit coverage | Custom test image | `./scripts/lanes/unit.sh` | repo-owned | Every persistence slice | active | Focused receipts accompany the authoritative product gate |
| Release-package scanner | Exact package inventory, SBOM, hashes, licences and vulnerabilities | Security/build | Immutable scanner images | `./scripts/security/scan-release-package.sh <package>` | repo-owned | Every candidate | active | Scans ignored `.artifacts` package explicitly |
| macOS Keychain database-head proof | Native atomic update/anti-rollback qualification | Native security/release | Host-orchestrated fresh workers on current Mac | `./scripts/qualification/macos-anchor.sh <sha> <package>` | repo-owned | Every exact release candidate | implemented; candidate execution pending | Containers use injected anchor; native proof is separate |
| Windows controller qualification | Provider/RID/ACL/reparse, PS7/5.1/mixed, protected-key transition, run-scoped agent, password recovery, and exact cleanup | Native/live release | Available Windows x64 laptop | `pwsh -NoLogo -NoProfile -NonInteractive -File scripts/qualification/Test-HHWindowsController.ps1 -CandidateSha <sha> -PackageArchivePath <package> -SshHost <host> -UserName <user> -HostKeyFingerprint <fingerprint>` | repo-owned | Every exact release candidate | focused contract green; candidate execution pending | Same package SHA-256 as exact-SHA gate; endpoint password and key passphrase remain interactive and never enter arguments, environment, files, logs, or receipts |
| Clean-checkout candidate runner | Full exact-SHA package/container proof | Release | Temporary clean worktree plus Compose | `./scripts/release/verify-candidate.sh <sha>` | repo-owned | Every candidate | implemented; candidate execution pending | Emits `.artifacts/release/<sha>/`; any edit invalidates receipt |
| Pester | Unit, integration, JUnit, command hits | Unit/integration | Custom test image | `scripts/lanes/unit.sh` | 6.1.0 | Monthly; full gate | active | AST/runtime gate supplies independent metrics |
| PSScriptAnalyzer | PowerShell static analysis | Static | Custom test image | `scripts/lanes/static.sh` | 1.25.0 | Monthly; full gate | active | |
| Coverage collector/gate | Statements/branches/functions/lines | Unit coverage | Custom test image | `scripts/lanes/unit.sh` | repo-owned | Change with golden fixtures | active | Runtime branch events plus Pester/AST metrics |
| editorconfig-checker | EditorConfig conformance | Static | Patched-source build in test image | `scripts/lanes/static.sh` | 3.11.1, Go 1.26.6, x/mod 0.40.0 | Monthly; full gate | active | Rebuilt because upstream binary image had fixed high/critical findings |
| ShellCheck | Shell wrapper lint | Static | Pinned ShellCheck image | `scripts/lanes/static.sh` | 0.11.0 | Monthly; full gate | active | Runs on every checked-in shell file |
| markdownlint-cli2 | Markdown lint | Static | Pinned test image | `scripts/lanes/static.sh` | 0.23.2 | Monthly; full gate | active | |
| yamllint | Compose/YAML lint | Static | Pinned test image | `scripts/lanes/static.sh` | 1.38.0 | Monthly; full gate | active | |
| hadolint | Dockerfile lint | Static | `hadolint/hadolint` | `scripts/lanes/static.sh` | 2.15.1 | Monthly; full gate | active | |
| actionlint | GitHub workflow lint | Static | none | none | not applicable | Revisit if workflows appear | not-applicable | GitHub Actions are prohibited for test reruns and no workflows are planned |
| gitleaks | Repo-only secret scan | Security | Immutable scanner image | `./scripts/security/scan-secrets.sh` | 8.30.1 | Monthly; full gate | active | Wrapper resolves and read-only mounts only repo root |
| OSV-Scanner | Dependency/SBOM vulnerability scan | Security | Immutable scanner image | `./scripts/security/scan-dependencies.sh` | 2.5.1 | Monthly; full gate | active | PowerShell module pin audit supplements ecosystem gaps |
| Trivy filesystem | Vulnerability/configuration scan | Security | `ghcr.io/aquasecurity/trivy` | `./scripts/security/scan-filesystem.sh` | 0.74.0 | Monthly; full gate | active | Post-incident immutable digest |
| Trivy image | Built-image scan | Security/build | `ghcr.io/aquasecurity/trivy` | `./scripts/security/scan-images.sh` | 0.74.0 | Monthly; full gate | active | Scans test and SSH fixture images |
| PowerShell module pin audit | Exact module inventory and drift | Security | Custom test image | `pwsh -File scripts/security/Test-ModulePins.ps1` | repo-owned | On dependency change | active | No stack-native PowerShell audit provides complete advisory coverage |
| Docker Compose | Local service orchestration | Integration/E2E | Host orchestrates; work runs in services | `./scripts/compose-run.sh ...` | Compose v2 contract | Host maintenance; design-compatible | active | Host orchestration only, never canonical test execution |
| Test-ModuleManifest | Manifest/build validation | Build | Custom test image | `scripts/lanes/build.sh` | PowerShell 7.6.5 | With PowerShell pin | active | Verifies eight exports, RID assets, versions, schema CRUD, and isolated package import |
| Black-box pwsh journeys | All public CLI actions | E2E equivalent | Custom test client plus SSH service | `HH_TEST_MODULE_PATH=<package> scripts/lanes/e2e.sh` | PowerShell 7.6.5 | With feature changes | active | 18 package-backed SQLite journeys; Playwright not applicable |

## Authoritative commands

- Full local proof: `./scripts/verify-local.sh`
- Fast pre-commit: `./scripts/precommit.sh`
- Slim gate-owned pre-push: `./scripts/prepush.sh`
- Hook install: `./scripts/hooks-install.sh`
- Hook verification: `./scripts/hooks-verify.sh`
- Locked SQLite restore: `./scripts/dependencies/restore-sqlite.sh`
- Product four-metric proof: `./scripts/lanes/unit.sh`
- Persistence fault/concurrency proof: `./scripts/lanes/sqlite-integration.sh`
- Exact package scan: `./scripts/security/scan-release-package.sh <package>`
- Exact clean-checkout candidate: `./scripts/release/verify-candidate.sh <sha>`

All commands in this section are implemented. Current working-tree evidence is
544/544 product units, 18/18 package-backed CLI journeys, nine SQLite fault
scenarios, and all four coverage metrics above 90%. Exact-commit and positive
live Windows 5.1 execution remain release qualifications, not container claims.

## Runtime qualification routing

- Canonical container lanes prove schema migration, direct PowerShell 7,
  negative `RuntimeUnavailable`, deferred WinRM, compatibility seams, audit
  attribution, and deterministic mixed-fan-out behavior.
- A separate live Windows lane proves positive Desktop 5.1 identity, ordered
  compatibility streams, mixed PowerShell 7/5.1 execution, and the authorized
  password-to-Ed25519 transition against the exact candidate archive and hash.
- Live qualification is never a substitute for the canonical container gate,
  and mock success never becomes a WinRM support claim.

## Version sources checked 2026-08-23; persistence/runtime sources checked 2026-08-24

- [PowerShell releases](https://github.com/PowerShell/PowerShell/releases/latest)
- [.NET 10 downloads](https://dotnet.microsoft.com/en-us/download/dotnet/10.0)
- [Pester on PowerShell Gallery](https://www.powershellgallery.com/packages/Pester)
- [PSScriptAnalyzer on PowerShell Gallery](https://www.powershellgallery.com/packages/PSScriptAnalyzer)
- [editorconfig-checker releases](https://github.com/editorconfig-checker/editorconfig-checker/releases/latest)
- [ShellCheck releases](https://github.com/koalaman/shellcheck/releases)
- [markdownlint-cli2 on npm](https://www.npmjs.com/package/markdownlint-cli2)
- [yamllint on PyPI](https://pypi.org/project/yamllint/)
- [hadolint releases](https://github.com/hadolint/hadolint/releases)
- [gitleaks releases](https://github.com/gitleaks/gitleaks/releases)
- [OSV-Scanner releases](https://github.com/google/osv-scanner/releases/latest)
- [Trivy container versions](https://github.com/aquasecurity/trivy/pkgs/container/trivy/versions)
- [Trivy 2026 supply-chain advisory](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
- [Microsoft.Data.Sqlite.Core 10.0.11](https://www.nuget.org/packages/Microsoft.Data.Sqlite.Core/10.0.11)
- [SQLitePCLRaw.bundle_e_sqlite3 3.0.5](https://www.nuget.org/packages/SQLitePCLRaw.bundle_e_sqlite3/3.0.5)
- [SQLite native package 3.53.4](https://www.nuget.org/packages/SQLite/3.53.4)

Because Trivy had a 2026 registry compromise, its tool image must be pinned to a
verified immutable post-incident digest. A mutable tag is expressly insufficient.
