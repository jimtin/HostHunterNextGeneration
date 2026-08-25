DROP TRIGGER operation_batches_no_update;
DROP TRIGGER operation_batches_no_delete;
DROP INDEX ix_batches_operation_created;

CREATE TABLE operation_batches_v2 (
    batch_id BLOB NOT NULL PRIMARY KEY CHECK (length(batch_id) = 16),
    operation TEXT NOT NULL CHECK (operation IN (
        'ValidateTarget',
        'TestTarget',
        'InvokeCommand',
        'EnableSshKeyAuthentication',
        'SetWindowsProcessAuditPolicy'
    )),
    created_at_utc TEXT NOT NULL CHECK (length(created_at_utc) >= 20),
    invocation_count INTEGER NOT NULL CHECK (invocation_count BETWEEN 1 AND 8)
) STRICT;

INSERT INTO operation_batches_v2(batch_id, operation, created_at_utc, invocation_count)
SELECT batch_id, operation, created_at_utc, invocation_count
FROM operation_batches;

DROP TABLE operation_batches;
ALTER TABLE operation_batches_v2 RENAME TO operation_batches;

CREATE INDEX ix_batches_operation_created ON operation_batches(operation, created_at_utc);
CREATE TRIGGER operation_batches_no_update BEFORE UPDATE ON operation_batches BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER operation_batches_no_delete BEFORE DELETE ON operation_batches BEGIN SELECT RAISE(ABORT, 'append-only'); END;

CREATE TABLE configuration_store_state (
    singleton_id INTEGER NOT NULL PRIMARY KEY CHECK (singleton_id = 1),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    escalation_method TEXT NULL CHECK (
        escalation_method IS NULL OR escalation_method = 'WindowsTokenPrivilege'
    ),
    state_mac BLOB NOT NULL CHECK (length(state_mac) = 32),
    prior_mutation_mac BLOB NOT NULL CHECK (length(prior_mutation_mac) = 32),
    last_mutation_id BLOB NULL CHECK (
        last_mutation_id IS NULL OR length(last_mutation_id) = 16
    )
) STRICT;

CREATE TABLE configuration_mutations (
    mutation_id BLOB NOT NULL PRIMARY KEY CHECK (length(mutation_id) = 16),
    previous_generation INTEGER NOT NULL CHECK (previous_generation >= 0),
    current_generation INTEGER NOT NULL CHECK (current_generation = previous_generation + 1),
    requested_at_utc TEXT NOT NULL CHECK (length(requested_at_utc) >= 20),
    before_method TEXT NULL CHECK (
        before_method IS NULL OR before_method = 'WindowsTokenPrivilege'
    ),
    after_method TEXT NOT NULL CHECK (after_method = 'WindowsTokenPrivilege'),
    mutation_mac BLOB NOT NULL CHECK (length(mutation_mac) = 32)
) STRICT;

CREATE TRIGGER configuration_mutations_no_update BEFORE UPDATE ON configuration_mutations BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER configuration_mutations_no_delete BEFORE DELETE ON configuration_mutations BEGIN SELECT RAISE(ABORT, 'append-only'); END;
