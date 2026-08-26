# Critical path inventory

| Critical path | Required behavior | Focused evidence |
| --- | --- | --- |
| Export/import | Package imports with exactly eleven public cmdlets; engine stays private | module contract and cmdlet receipt |
| Target lifecycle | Empty read, validated save, persisted fresh read, revalidation, atomic removal | ordered cmdlet journey plus SQLite deltas |
| Command execution | Intent, arm, SSH dispatch, all streams, terminal outcome | Invoke-HHCommand row and authenticated audit/output reads |
| Managed-host boundary | Five host-facing cmdlets delegate once to the closed engine; no bypass | AST guard and delegation tests |
| SSH key transition | Password proof, install, key-only proof, anchored profile commit, bounded cleanup | cmdlet journey and bootstrap unit tests |
| Windows audit policy | Fixed mutation, verified outcome, exact restoration | live exact-image Windows qualification |
| Configuration | Escalation preference generation/mutation and fresh-process read | Set/Get rows and SQLite deltas |
| Evidence integrity | encrypted .hhout, anchors, tamper/rollback detection | release-only focused integration |
| Crash recovery | armed incomplete work becomes Unknown and is never redispatched | recovery integration |
| Coverage integrity | every shipped source file; genuine four-metric unit-only result; no production instrumentation | fixed two-pass release coverage receipt and packaged-image probe-token check |
| Release finality | exact SHA consumed once; component and terminal receipts immutable | receipt contract tests |

The six local-only cmdlets must have negative no-managed-host-contact coverage.
Historical unsupported transport/runtime rows remain readable/removable but fail
closed before dispatch.
