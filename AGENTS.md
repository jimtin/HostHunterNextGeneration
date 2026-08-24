# HostHunterNextGeneration Agent Contract

## Validation model

- This repository uses gate-owned proof. Before first publication the planned
  HostHunter-specific standalone laptop gate must be implemented and must run
  the complete suite on the exact candidate SHA; developer pushes run only the
  slim pre-push lanes.
- All static, unit, integration, CLI/service-journey, build, dependency,
  secret, filesystem, and image proof executes locally in containers. The host
  may only orchestrate Docker and maintain ignored artifacts.
- GitHub stores source and review state. Do not add GitHub Actions that rerun
  repository validation.
- Publication must leave the repository owner-written: only `jimtin` may push,
  merge, administer, or install repository-scoped integrations. This remote
  state is not proven until the post-publication settings re-read. Never execute
  external contribution code on the maintainer laptop before a manual source
  review.

## Required commands

- Full local proof: `./scripts/verify-local.sh`
- Fast commit gate: `./scripts/precommit.sh`
- Slim push gate: `./scripts/prepush.sh`
- Install hooks: `./scripts/hooks-install.sh`
- Verify hooks: `./scripts/hooks-verify.sh`
- Exact clean-checkout candidate proof (planned, not yet implemented):
  `./scripts/release/verify-candidate.sh <sha>`

Never bypass a hook or the standalone gate. Do not run the full suite before a
normal developer push; the standalone exact-SHA gate owns full proof.

SQLite integration and CLI E2E must import the generated package through
`HH_TEST_MODULE_PATH`; a direct source import is not package or RID evidence.

## Coverage and test obligations

- Repository-wide unit coverage is at least 90% for executable statements,
  runtime branch outcomes, functions/class methods, and executable lines.
- New or materially changed logic targets at least 95% changed-scope coverage.
- Every critical path requires deterministic integration evidence.
- Every exported cmdlet, parameter set, persistence mutation, error/retry state,
  and operator journey requires a fresh-process CLI E2E test.
- Runtime coverage must prove the default `PowerShell7` path, explicit
  `WindowsPowerShell51` selection, two runtime profiles for one SSH endpoint,
  mismatch/unavailability without fallback, and runtime attribution in audit
  evidence. Canonical Linux fixtures may cover only deterministic paths; the
  positive 5.1 bridge requires the explicit live Windows exact-SHA lane.
- Update `docs/testing/critical-path-inventory.md` and
  `docs/testing/e2e-workflow-inventory.md` with every affected feature.

## Security and isolation

- Run `./scripts/security/scan-secrets.sh` only through its repo-root-resolving
  wrapper. Never scan a parent workspace or broad host path.
- External services use deterministic fakes by default. The disposable SSH
  fixture is the canonical protocol integration target. WinRM is explicitly
  deferred and must fail closed in v1; mocks cannot establish a release claim.
- SSH uses PowerShell 7 as the outer runspace. `PowerShell7` is direct;
  `WindowsPowerShell51` uses a bounded local compatibility PSSession only after
  Desktop 5.1 identity proof. Never add silent runtime or transport fallback.
- Generated reports belong under `.artifacts/` and must never be committed.
- Scanner/image references and downloaded tool archives require exact version
  plus immutable digest or checksum. No floating tags are allowed.
- The dated Trivy exception is path-specific and must be removed or renewed
  through review before it expires.

## Bounded execution

Every long-running lane must use the checked-in bounded runner with hard
timeout, stall detection, heartbeat, readable logs, and machine-readable
artifacts where supported. Retries do not constitute proof.
