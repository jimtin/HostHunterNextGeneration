# HostHunter production promotion ledger

Status: implementation complete; promotion in progress  
Date: 2026-08-31

## Acceptance ledger

| ID | Production requirement | Proof | Status |
| --- | --- | --- | --- |
| PROD-01 | Promote the coherent HostHunter framework, CIM collection, persistence, and verifier changes | final candidate diff and commit | pending |
| PROD-02 | Keep the producer contract byte-identical to the Visualizer mirror | `diff -qr CIM_Specification ../HostHunterVisualizer/CIM_Specification` | verified |
| PROD-03 | Build SQLite schema v5 from the five committed migrations | development cmdlet receipt plus exact-SHA persistence receipt | development verified; release pending |
| PROD-04 | Preserve the single managed-host engine and seventeen-command manifest contract | focused contracts plus exact-SHA cmdlet receipt | development verified; release pending |
| PROD-05 | Prove positive Windows behavior without retries and restore endpoint policy | exact-SHA Windows qualification receipt | pending |
| PROD-06 | Complete coverage, persistence, security, image, and production-build proof once for the final SHA | standalone exact-SHA release receipt | pending |
| PROD-07 | Run repo-scoped secret scanning and changed-scope threat review before GitHub promotion | installed hooks, security receipt, and threat-model checker | threat model verified; remaining proof pending |
| PROD-08 | Promote only the proven SHA to GitHub `main` | PR head/base verification and merge SHA | pending |
| PROD-09 | Load the merged source through the supported macOS client and leave the controller healthy | one post-merge client synchronization and runtime doctor | pending |

## Test ledger

| Layer | Required evidence | Status |
| --- | --- | --- |
| Focused unit/contracts | 83 verifier-owned contracts plus focused CIM tests | verified |
| Development service journey | one 17-row cmdlet/SQLite receipt | verified |
| Fresh migrations | schema v5 and integrity `ok` from committed migrations | verified |
| Static/governance | containerized static lane | verified |
| Security model | checked root threat model with no unresolved release blocker | verified |
| Push hook | slim pre-push lanes, including repo-scoped gitleaks | pending |
| Exact-SHA release | build, cmdlets, Windows, coverage, persistence, security, aggregation | pending |
| Production observation | remote `main`, local clean tree, healthy matching controller | pending |

## Execution controls

- The Visualizer UI worktree is outside this promotion and will not be committed,
  reset, or pushed here.
- The exact-SHA release gate runs once for the final candidate. A failure consumes
  that SHA and requires a corrective commit; it is never retried.
- No hook or release check is bypassed.
- GitHub Actions do not rerun local proof.
