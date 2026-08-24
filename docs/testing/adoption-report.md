# Testing Foundation Adoption Report

## Verdict

`working-tree-green-exact-candidate-and-native-release-proof-pending`

The SQLite-only target and audit repository, packaged provider, external
anchor, invocation-bound `.hhout` v2 artifacts, durable platform publication,
crash recovery, capacity reservation, and two audit query cmdlets are
implemented. The current packaged Linux/PowerShell 7 journey passes 18/18
actions. Product coverage passes all four repository gates. The candidate is
not yet release-ready because exact-commit macOS/Windows/GitHub proof remains
outstanding.
Positive Windows PowerShell 5.1 execution still requires a separate live Windows
SSH qualification of the exact committed candidate. Publication and live GitHub
settings verification also remain pending.

The earlier pre-migration full-gate receipt remains historical baseline only;
it must not be used as proof of this candidate.

WinRM is no longer an open first-release qualification item. The user deferred
it until a controlled lab exists, so v1 must prove a clear fail-closed negative
path instead of claiming WinRM support.

## Repo Truth Discovered

- Package manager: none; exact PowerShell Gallery test modules are installed in
  the checksum-verified pinned test image.
- Frameworks/services: PowerShell 7 controller module, Pester, Compose
  PowerShell-over-SSH fixture, and deterministic transport/storage/runtime
  seams.
- Existing commands: full, pre-commit, slim pre-push, hook install/verify, and
  static/unit/integration/security lanes.
- Existing hook framework: checked-in `.githooks`, installed and active.
- Existing CI/deploy configuration: none; remote CI test reruns are prohibited.
- Release runtime contract: direct PowerShell 7 by default; explicit Windows
  PowerShell 5.1 through a Windows-local compatibility session; SSH only.
- Public-repository contract: after publication, only `jimtin` may write or
  administer; external contribution code receives manual review before trusted
  local execution. Live settings verification remains pending.

## Enforcement Model

- Model: `gate-owned`.
- Hook install/verify:
  `./scripts/hooks-install.sh && ./scripts/hooks-verify.sh`.
- Full canonical command: `./scripts/verify-local.sh`.
- Exact clean-checkout command: `./scripts/release/verify-candidate.sh <sha>`.
  The separate HostHunter laptop gate exists outside this repository and will
  invoke that command exactly once for the immutable first candidate.

## Validation Evidence

| Check | Command | Container/service | Result | Artifact |
|---|---|---|---|---|
| Canonical full proof | `./scripts/verify-local.sh` | Docker/Compose and pinned scanner containers | current working-tree wrapper passed after the Windows ACL amendment; exact candidate rerun pending | `.artifacts/summary/verify-local.json` |
| Four-metric product proof | `scripts/lanes/unit.sh` | test container | 544/544 passed; 96.8122% statements (6894/7121), 90.048% branches (2253/2502), 96.1039% functions (222/231), 96.8729% lines (5700/5884) | `.artifacts/unit/product/coverage-summary.json` |
| SSH protocol contract | fixture contract script | test client plus disposable SSH target | password authentication and the pinned PowerShell 7 fixture passed | `.artifacts/integration/ssh-fixture-contract.json` |
| Critical package/SSH integration | `scripts/lanes/integration.sh` | test client plus disposable SSH target | 22/22 passed; two privileged capacity cases are run separately | `.artifacts/integration/integration-tests.xml` |
| CLI E2E equivalent | `scripts/lanes/e2e.sh` | fresh PowerShell processes plus SSH target | 18/18 SQLite package journeys passed | `.artifacts/e2e/e2e-tests.xml` |
| SQLite process/fault integration | `scripts/lanes/sqlite-integration.sh` | packaged module, subprocesses, bounded filesystems | 9/9 recovery, ownership, WAL, anchor, tamper, capacity, and external-full scenarios passed | `.artifacts/sqlite-integration/receipt.json` |
| Static, security, and build | full static/security/build lanes | pinned test and scanner containers | PSScriptAnalyzer, text/static checks, gitleaks, dependency audit, filesystem/image scans, and package/build smoke passed | `.artifacts/static/`, `.artifacts/security/`, `.artifacts/build/` |

These rows are current working-tree evidence. They are not exact-SHA, native Windows, or
publication evidence. The standalone gate must reproduce the complete program
from a clean detached checkout before the native and GitHub release steps.

## Dual-runtime evidence required

| Evidence | Deterministic boundary | Current status |
|---|---|---|
| Schema v1 to v2 migration and runtime-aware endpoint identity | container unit tests | verified in canonical working-tree gate |
| Default and explicit PowerShell 7 target journeys | real Linux SSH fixture plus fresh processes | verified in canonical working-tree gate |
| Windows PowerShell 5.1 unavailable with no fallback | real Linux SSH fixture plus fresh process | verified in canonical working-tree gate |
| Compatibility identity, cleanup, streams, and failure mapping | injected unit/integration seams | verified deterministically in canonical working-tree gate; live positive qualification pending |
| Positive 5.1 command and mixed-runtime fan-out | exact candidate on live Windows SSH target | pending live qualification |
| Exact remote-operation manifests and strict audit correlations | adversarial container unit/integration seams | verified in canonical working-tree gate |
| CAS target mutation and bounded cleanup | competing-writer, timeout, and cancellation seams | verified in canonical working-tree gate |
| Bootstrap dispatch uncertainty and cumulative output cap | adversarial bootstrap unit/integration seams | verified in canonical working-tree gate |
| Authorized Ed25519 transition | disposable fixture plus exact candidate in the designated live Windows environment | disposable fixture verified; exact-candidate live Windows transition pending |
| Native macOS Keychain audit-key lifecycle | focused units plus disposable fresh-process live contract | 37 AuditKeyStore + 21 Configuration focused units, native lifecycle, and aggregate working-tree gate passed |
| WinRM rejection without dispatch or store mutation | unit plus fresh-process negative journey | verified fail-closed; positive WinRM remains deferred |
| Owner-only public GitHub settings and disabled Actions | live GitHub re-read after publication | pending publication |

## Ledgers

- Acceptance ledger: container/direct PowerShell 7, negative runtime, deferred
  WinRM, deterministic compatibility, accountability hardening, and bootstrap
  fixture rows are verified for the current working tree. Positive live 5.1,
  exact-commit, and GitHub rows remain pending.
- Test ledger: container, coverage, hook, static, security, SSH fixture,
  integration, E2E, build, and bounded-runner rows are verified.
- Parallel work: disjoint coverage, SSH, and static/security lanes were
  integrated by the main agent; the canonical gate passed after integration.

## Exceptions and Deferred Items

| Item | Reason | Owner decision | Follow-up |
|---|---|---|---|
| WinRM implementation and qualification | Requires a purpose-built lab for authentication, trust, and certificate policy | User | Keep rejected in v1; plan separately when the lab exists |
| Positive Windows PowerShell 5.1 canonical fixture | Linux container cannot host Desktop 5.1 | Main agent | Use deterministic seams plus separate exact-candidate live Windows SSH qualification |
| Root SSH fixture process | `sshd` must start privileged before dropping sessions to uid 10001 | Main agent | Path-scoped Trivy exception expires 2026-09-06 |
| External contribution execution | Public source may contain attacker-controlled changes | Owner | Manual source review before any trusted local execution; no GitHub Actions |
