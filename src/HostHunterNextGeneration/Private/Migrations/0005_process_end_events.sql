DROP TRIGGER operation_batches_no_update;
DROP TRIGGER operation_batches_no_delete;
DROP INDEX ix_batches_operation_created;

CREATE TABLE operation_batches_v5 (
    batch_id BLOB NOT NULL PRIMARY KEY CHECK (length(batch_id) = 16),
    operation TEXT NOT NULL CHECK (operation IN (
        'ValidateTarget',
        'TestTarget',
        'InvokeCommand',
        'EnableSshKeyAuthentication',
        'SetWindowsProcessAuditPolicy',
        'GetHostDetails',
        'GetProcessStartEvents',
        'GetProcessEndEvents',
        'GetAuthenticationEvents',
        'GetProcessAccessToken',
        'GetUserEffectiveRights'
    )),
    created_at_utc TEXT NOT NULL CHECK (length(created_at_utc) >= 20),
    invocation_count INTEGER NOT NULL CHECK (invocation_count BETWEEN 1 AND 8)
) STRICT;

INSERT INTO operation_batches_v5(batch_id, operation, created_at_utc, invocation_count)
SELECT batch_id, operation, created_at_utc, invocation_count
FROM operation_batches;

DROP TABLE operation_batches;
ALTER TABLE operation_batches_v5 RENAME TO operation_batches;
CREATE INDEX ix_batches_operation_created ON operation_batches(operation, created_at_utc);
CREATE TRIGGER operation_batches_no_update BEFORE UPDATE ON operation_batches BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER operation_batches_no_delete BEFORE DELETE ON operation_batches BEGIN SELECT RAISE(ABORT, 'append-only'); END;
