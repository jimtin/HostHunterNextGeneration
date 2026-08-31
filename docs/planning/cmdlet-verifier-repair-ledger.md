# Cmdlet verifier repair implementation ledger

Status: confirmed and implementation authorized  
Date: 2026-08-31

## Acceptance ledger

| ID | Requirement | Implementation surface | Focused evidence | Status | Non-goal |
| --- | --- | --- | --- | --- | --- |
| VR-01 | Use the packaged module manifest as the sole framework-command authority | package checker, controller startup, verifier receipts | manifest-derived export contract | verified | removing the intentionally ordered journey |
| VR-02 | Keep fixture and artifact permissions independent | cmdlet Compose and wrapper environment | resolved Compose configuration plus same-identity access checks | verified | weakening fixture password permissions |
| VR-03 | Run all readiness checks before the first cmdlet | cmdlet journey preflight | focused preflight success and failure tests | verified | a separate retrying verifier |
| VR-04 | Emit a precise receipt on every terminal path | journey error boundary and host fallback | phase/error/row receipt contracts | verified | exposing fixture credentials or unbounded logs |
| VR-05 | Preserve development attempts without conflating them with exact-SHA proof | development artifact layout and receipt identity | run-ID/source-fingerprint contract | verified | changing immutable release receipts |
| VR-06 | Preserve the bounded testing model | verifier wrapper and testing documentation | one Compose journey invocation; no retry or broad lanes | verified | coverage, scans, builds, or live Windows during development |
| VR-07 | Produce one authoritative 17-command SQLite verdict | synchronized controller plus cmdlet verifier | one 17-row receipt, schema v5, integrity `ok` | verified | rerunning a failed verifier in the same implementation turn |

## Test ledger

| Changed area | Focused test | Required assertion | Status |
| --- | --- | --- | --- |
| Package export validation | module/package contract | expected names derive from `FunctionsToExport`; current product count is asserted once | verified |
| Controller startup | native-client/runtime contract | no literal framework count; actual exports equal packaged manifest | verified |
| Compose groups | fast verifier contract | fixture GID 10002 and host artifact GID are both present and distinct | verified |
| Artifact preparation | fast verifier contract | exact run directory is group writable before container startup | verified |
| Journey preflight | focused verifier preflight tests | fixture read, receipt write, manifest match, migration inventory and redacted failures | verified |
| Receipt durability | receipt contract tests | source fingerprint plus unique run ID; prior attempts are not overwritten | verified |
| Final behavior | `scripts/verify-cmdlets.sh` | exactly 17 unique passed rows; SQLite schema v5 and integrity `ok` | verified |

## Execution controls

- Preserve every pre-existing dirty path and make no unrelated cleanup.
- Run a focused test only after changing its owned implementation.
- Run no coverage, dependency, image, release, or live-Windows lane.
- Synchronize the controller at most once after focused readiness is green.
- Run the authoritative cmdlet verifier once. If it fails, preserve the exact
  receipt and stop without a second verifier invocation.
- Parallel workers are not used because the manifest, package, runtime,
  Compose, journey, and receipt contracts are tightly coupled and the current
  tool policy does not authorize delegation for this request.

## Final evidence

- Focused container contracts: 83 passed, 0 failed in 3.21 seconds.
- Containerized static/governance lane: passed.
- Threat-model report contract: passed.
- Same-identity permission probe: verifier UID/GID `10001:10001`, supplementary
  groups `20` and `10002`, fixture read and artifact write both passed.
- Normal client synchronization: performed once because the controller source
  fingerprint was stale.
- Authoritative verifier: invoked once; 17 rows passed, 0 failed; five committed
  migrations; SQLite schema version 5 and integrity `ok`.
- Receipt: `.artifacts/cmdlets/5efd774c1dcb6c241a42b69b9dbcb038bc7a7f726628aec8432387efbe913510/20260830T222934Z-56202-15386/cmdlets/receipt.json`.
- Deliberately not run: coverage, dependency/image/security lanes, production
  release proof, and live-Windows qualification.
