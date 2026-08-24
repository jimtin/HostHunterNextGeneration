PRAGMA foreign_keys = ON;

CREATE TABLE schema_migrations (
    version INTEGER NOT NULL PRIMARY KEY CHECK (version > 0),
    name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 128),
    sql_checksum BLOB NOT NULL CHECK (length(sql_checksum) = 32),
    applied_at_utc TEXT NOT NULL CHECK (length(applied_at_utc) >= 20)
) STRICT;

CREATE TABLE database_identity (
    singleton_id INTEGER NOT NULL PRIMARY KEY CHECK (singleton_id = 1),
    database_id BLOB NOT NULL UNIQUE CHECK (length(database_id) = 16),
    ledger_id BLOB NOT NULL UNIQUE CHECK (length(ledger_id) = 16),
    format_version INTEGER NOT NULL CHECK (format_version = 1),
    created_at_utc TEXT NOT NULL CHECK (length(created_at_utc) >= 20)
) STRICT;

CREATE TABLE target_store_state (
    singleton_id INTEGER NOT NULL PRIMARY KEY CHECK (singleton_id = 1),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    snapshot_hash BLOB NOT NULL CHECK (length(snapshot_hash) = 32),
    target_state_mac BLOB NOT NULL CHECK (length(target_state_mac) = 32),
    prior_mutation_mac BLOB NOT NULL CHECK (length(prior_mutation_mac) = 32),
    last_mutation_id BLOB NULL CHECK (last_mutation_id IS NULL OR length(last_mutation_id) = 16)
) STRICT;

CREATE TABLE target_profiles (
    name TEXT NOT NULL PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 128),
    name_key TEXT NOT NULL UNIQUE CHECK (length(name_key) BETWEEN 1 AND 256),
    endpoint_key TEXT NOT NULL UNIQUE CHECK (length(endpoint_key) BETWEEN 1 AND 1024),
    transport TEXT NOT NULL CHECK (transport IN ('SSH', 'WinRM')),
    host_name TEXT NOT NULL CHECK (length(host_name) BETWEEN 1 AND 253),
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    user_name TEXT NOT NULL CHECK (length(user_name) BETWEEN 1 AND 256),
    authentication TEXT NOT NULL CHECK (authentication IN ('Password', 'PublicKey', 'Kerberos', 'Certificate')),
    powershell_runtime TEXT NOT NULL CHECK (powershell_runtime IN ('PowerShell7', 'WindowsPowerShell51')),
    host_key_fingerprint TEXT NULL,
    key_path TEXT NULL,
    is_active INTEGER NOT NULL CHECK (is_active IN (0, 1)),
    last_validated_at_utc TEXT NOT NULL CHECK (length(last_validated_at_utc) >= 20),
    last_validated_ps_edition TEXT NOT NULL CHECK (last_validated_ps_edition IN ('Core', 'Desktop')),
    last_validated_powershell_version TEXT NOT NULL CHECK (length(last_validated_powershell_version) BETWEEN 1 AND 64),
    last_validated_execution_mode TEXT NOT NULL CHECK (last_validated_execution_mode IN ('Direct', 'WindowsPowerShellCompatibility')),
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE operation_batches (
    batch_id BLOB NOT NULL PRIMARY KEY CHECK (length(batch_id) = 16),
    operation TEXT NOT NULL CHECK (operation IN ('ValidateTarget', 'TestTarget', 'InvokeCommand', 'EnableSshKeyAuthentication')),
    created_at_utc TEXT NOT NULL CHECK (length(created_at_utc) >= 20),
    invocation_count INTEGER NOT NULL CHECK (invocation_count BETWEEN 1 AND 8)
) STRICT;

CREATE TABLE invocations (
    invocation_id BLOB NOT NULL PRIMARY KEY CHECK (length(invocation_id) = 16),
    sequence INTEGER NOT NULL UNIQUE CHECK (sequence > 0),
    batch_id BLOB NOT NULL REFERENCES operation_batches(batch_id),
    target_name TEXT NOT NULL CHECK (length(target_name) BETWEEN 1 AND 128),
    transport TEXT NOT NULL CHECK (transport IN ('SSH', 'WinRM')),
    host_name TEXT NOT NULL CHECK (length(host_name) BETWEEN 1 AND 253),
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    user_name TEXT NOT NULL CHECK (length(user_name) BETWEEN 1 AND 256),
    authentication TEXT NOT NULL CHECK (authentication IN ('Password', 'PublicKey', 'Kerberos', 'Certificate')),
    requested_runtime TEXT NOT NULL CHECK (requested_runtime IN ('PowerShell7', 'WindowsPowerShell51')),
    requested_execution_mode TEXT NOT NULL CHECK (requested_execution_mode IN ('Direct', 'WindowsPowerShellCompatibility')),
    intent_at_utc TEXT NOT NULL CHECK (length(intent_at_utc) >= 20),
    target_snapshot_envelope BLOB NOT NULL,
    command_envelope BLOB NOT NULL,
    reason_envelope BLOB NULL,
    case_envelope BLOB NULL,
    case_lookup BLOB NULL CHECK (case_lookup IS NULL OR length(case_lookup) = 32),
    request_envelope_hash BLOB NOT NULL CHECK (length(request_envelope_hash) = 32),
    reserved_artifact_id BLOB NOT NULL UNIQUE CHECK (length(reserved_artifact_id) = 16)
) STRICT;

CREATE TABLE remote_operations (
    invocation_id BLOB NOT NULL REFERENCES invocations(invocation_id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 64),
    phase TEXT NOT NULL CHECK (length(phase) BETWEEN 1 AND 128),
    powershell_runtime TEXT NOT NULL CHECK (powershell_runtime IN ('PowerShell7', 'WindowsPowerShell51')),
    script_envelope BLOB NOT NULL,
    arguments_envelope BLOB NOT NULL,
    conditional INTEGER NOT NULL CHECK (conditional IN (0, 1)),
    declaration_hash BLOB NOT NULL CHECK (length(declaration_hash) = 32),
    PRIMARY KEY (invocation_id, ordinal)
) STRICT;

CREATE TABLE remote_operation_events (
    invocation_id BLOB NOT NULL,
    ordinal INTEGER NOT NULL,
    event_kind TEXT NOT NULL CHECK (event_kind IN ('DispatchArmed', 'Completed', 'Skipped', 'DispatchUncertain')),
    event_at_utc TEXT NOT NULL CHECK (length(event_at_utc) >= 20),
    evidence_envelope BLOB NULL,
    evidence_hash BLOB NOT NULL CHECK (length(evidence_hash) = 32),
    FOREIGN KEY (invocation_id, ordinal) REFERENCES remote_operations(invocation_id, ordinal),
    PRIMARY KEY (invocation_id, ordinal, event_kind)
) STRICT;

CREATE TABLE invocation_outcomes (
    invocation_id BLOB NOT NULL PRIMARY KEY REFERENCES invocations(invocation_id),
    status TEXT NOT NULL CHECK (status IN ('Succeeded', 'Failed', 'Cancelled', 'Unknown')),
    failure_kind TEXT NULL,
    dispatch_state TEXT NOT NULL CHECK (dispatch_state IN ('NotDispatched', 'Dispatched', 'DispatchUncertain', 'Completed')),
    outcome_status TEXT NOT NULL CHECK (outcome_status IN ('Succeeded', 'Failed', 'Unknown')),
    completed_at_utc TEXT NOT NULL CHECK (length(completed_at_utc) >= 20),
    identity_envelope BLOB NULL,
    outcome_envelope BLOB NOT NULL,
    outcome_envelope_hash BLOB NOT NULL CHECK (length(outcome_envelope_hash) = 32),
    recovery_state TEXT NOT NULL CHECK (recovery_state IN ('None', 'RecoveredNotDispatched', 'RecoveredDispatchUncertain', 'RecoveredPartialEvidence'))
) STRICT;

CREATE TABLE output_artifacts (
    invocation_id BLOB NOT NULL PRIMARY KEY REFERENCES invocations(invocation_id),
    artifact_id BLOB NOT NULL UNIQUE CHECK (length(artifact_id) = 16),
    relative_path TEXT NOT NULL UNIQUE CHECK (length(relative_path) BETWEEN 1 AND 512),
    ciphertext_hash BLOB NOT NULL CHECK (length(ciphertext_hash) = 32),
    ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes >= 0),
    plaintext_bytes INTEGER NOT NULL CHECK (plaintext_bytes >= 0 AND plaintext_bytes <= 104857600),
    format_version INTEGER NOT NULL CHECK (format_version = 2),
    stream_event_count INTEGER NOT NULL CHECK (stream_event_count >= 0),
    published_at_utc TEXT NOT NULL CHECK (length(published_at_utc) >= 20)
) STRICT;

CREATE TABLE target_mutations (
    mutation_id BLOB NOT NULL PRIMARY KEY CHECK (length(mutation_id) = 16),
    previous_generation INTEGER NOT NULL CHECK (previous_generation >= 0),
    current_generation INTEGER NOT NULL CHECK (current_generation = previous_generation + 1),
    requested_at_utc TEXT NOT NULL CHECK (length(requested_at_utc) >= 20),
    before_envelope BLOB NOT NULL,
    after_envelope BLOB NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('Committed', 'Failed', 'Unknown')),
    mutation_mac BLOB NOT NULL CHECK (length(mutation_mac) = 32)
) STRICT;

CREATE TABLE audit_events (
    sequence INTEGER NOT NULL PRIMARY KEY CHECK (sequence > 0),
    event_id BLOB NOT NULL UNIQUE CHECK (length(event_id) = 16),
    event_kind TEXT NOT NULL CHECK (length(event_kind) BETWEEN 1 AND 128),
    event_at_utc TEXT NOT NULL CHECK (length(event_at_utc) >= 20),
    invocation_id BLOB NULL REFERENCES invocations(invocation_id),
    target_mutation_id BLOB NULL REFERENCES target_mutations(mutation_id),
    projection_hash BLOB NOT NULL CHECK (length(projection_hash) = 32),
    related_envelope_hash BLOB NOT NULL CHECK (length(related_envelope_hash) = 32),
    previous_mac BLOB NOT NULL CHECK (length(previous_mac) = 32),
    event_mac BLOB NOT NULL CHECK (length(event_mac) = 32),
    CHECK ((invocation_id IS NULL) <> (target_mutation_id IS NULL))
) STRICT;

CREATE INDEX ix_invocations_batch ON invocations(batch_id);
CREATE INDEX ix_invocations_target_sequence ON invocations(target_name, sequence DESC);
CREATE INDEX ix_invocations_case_lookup_sequence ON invocations(case_lookup, sequence DESC);
CREATE INDEX ix_batches_operation_created ON operation_batches(operation, created_at_utc);
CREATE INDEX ix_outcomes_status_completed ON invocation_outcomes(status, completed_at_utc);
CREATE INDEX ix_remote_operation_events_invocation ON remote_operation_events(invocation_id, ordinal);

CREATE TRIGGER schema_migrations_no_update BEFORE UPDATE ON schema_migrations BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER schema_migrations_no_delete BEFORE DELETE ON schema_migrations BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER database_identity_no_update BEFORE UPDATE ON database_identity BEGIN SELECT RAISE(ABORT, 'immutable'); END;
CREATE TRIGGER database_identity_no_delete BEFORE DELETE ON database_identity BEGIN SELECT RAISE(ABORT, 'immutable'); END;
CREATE TRIGGER operation_batches_no_update BEFORE UPDATE ON operation_batches BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER operation_batches_no_delete BEFORE DELETE ON operation_batches BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER invocations_no_update BEFORE UPDATE ON invocations BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER invocations_no_delete BEFORE DELETE ON invocations BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER remote_operations_no_update BEFORE UPDATE ON remote_operations BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER remote_operations_no_delete BEFORE DELETE ON remote_operations BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER remote_operation_events_no_update BEFORE UPDATE ON remote_operation_events BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER remote_operation_events_no_delete BEFORE DELETE ON remote_operation_events BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER invocation_outcomes_no_update BEFORE UPDATE ON invocation_outcomes BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER invocation_outcomes_no_delete BEFORE DELETE ON invocation_outcomes BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER output_artifacts_no_update BEFORE UPDATE ON output_artifacts BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER output_artifacts_no_delete BEFORE DELETE ON output_artifacts BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER target_mutations_no_update BEFORE UPDATE ON target_mutations BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER target_mutations_no_delete BEFORE DELETE ON target_mutations BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'append-only'); END;
