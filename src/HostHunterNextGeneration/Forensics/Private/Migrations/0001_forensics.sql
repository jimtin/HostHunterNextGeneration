PRAGMA foreign_keys = ON;

CREATE TABLE forensics_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    sql_checksum BLOB NOT NULL CHECK (length(sql_checksum) = 32),
    applied_at_utc TEXT NOT NULL
) STRICT;

CREATE TABLE forensics_database_identity (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    database_id BLOB NOT NULL CHECK (length(database_id) = 16),
    format_version INTEGER NOT NULL CHECK (format_version = 1),
    created_at_utc TEXT NOT NULL
) STRICT;

CREATE TABLE forensics_state (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    state_digest BLOB NOT NULL CHECK (length(state_digest) = 32),
    state_mac BLOB NOT NULL CHECK (length(state_mac) = 32),
    projection_digest BLOB NOT NULL CHECK (length(projection_digest) = 32),
    projection_mac BLOB NOT NULL CHECK (length(projection_mac) = 32),
    last_mutation_id TEXT NULL
) STRICT;

CREATE TABLE forensics_mutations (
    sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
    mutation_id TEXT NOT NULL UNIQUE,
    mutation_type TEXT NOT NULL,
    routing_key TEXT NOT NULL,
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    state_digest BLOB NOT NULL CHECK (length(state_digest) = 32),
    projection_digest BLOB NOT NULL CHECK (length(projection_digest) = 32),
    projection_mac BLOB NOT NULL CHECK (length(projection_mac) = 32),
    previous_mac BLOB NOT NULL CHECK (length(previous_mac) = 32),
    mutation_mac BLOB NOT NULL CHECK (length(mutation_mac) = 32),
    created_at_utc TEXT NOT NULL
) STRICT;

CREATE TABLE forensics_events (
    event_id TEXT PRIMARY KEY,
    event_digest BLOB NOT NULL CHECK (length(event_digest) = 32),
    source_key TEXT NOT NULL,
    run_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    occurred_at_utc TEXT NOT NULL,
    body_size INTEGER NOT NULL CHECK (body_size >= 0 AND body_size <= 1048576),
    event_body_envelope BLOB NOT NULL CHECK (length(event_body_envelope) >= 34),
    status TEXT NOT NULL CHECK (status IN ('STORED', 'OUTBOXED', 'ACCEPTED', 'QUARANTINED')),
    created_at_utc TEXT NOT NULL,
    UNIQUE (run_id, ordinal)
) STRICT;

CREATE TABLE forensics_outbox (
    resource_key TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    method TEXT NOT NULL CHECK (method = 'PUT'),
    resource_uri TEXT NOT NULL,
    body_digest BLOB NOT NULL CHECK (length(body_digest) = 32),
    body_size INTEGER NOT NULL CHECK (body_size >= 0 AND body_size <= 1048576),
    request_body_envelope BLOB NULL CHECK (
        request_body_envelope IS NULL OR length(request_body_envelope) >= 34
    ),
    first_ordinal INTEGER NOT NULL CHECK (first_ordinal >= 0),
    last_ordinal INTEGER NOT NULL CHECK (last_ordinal >= first_ordinal),
    event_count INTEGER NOT NULL CHECK (event_count BETWEEN 1 AND 250),
    status TEXT NOT NULL CHECK (
        status IN (
            'PREPARED', 'SENDING', 'ACCEPTED', 'RETRYABLE', 'UNKNOWN',
            'PAUSED', 'REJECTED', 'CONFLICT'
        )
    ),
    creation_order INTEGER NOT NULL UNIQUE CHECK (creation_order >= 0),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_status_code INTEGER NULL,
    last_problem_code TEXT NULL,
    receipt_digest BLOB NULL CHECK (receipt_digest IS NULL OR length(receipt_digest) = 32),
    receipt_envelope BLOB NULL CHECK (receipt_envelope IS NULL OR length(receipt_envelope) >= 34),
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL
) STRICT;

CREATE TABLE forensics_outbox_events (
    resource_key TEXT NOT NULL REFERENCES forensics_outbox(resource_key) ON DELETE RESTRICT,
    event_id TEXT NOT NULL REFERENCES forensics_events(event_id) ON DELETE RESTRICT,
    event_ordinal INTEGER NOT NULL CHECK (event_ordinal >= 0),
    PRIMARY KEY (resource_key, event_id),
    UNIQUE (resource_key, event_ordinal)
) STRICT;

CREATE TABLE forensics_outbox_dependencies (
    resource_key TEXT NOT NULL REFERENCES forensics_outbox(resource_key) ON DELETE RESTRICT,
    depends_on_resource_key TEXT NOT NULL,
    PRIMARY KEY (resource_key, depends_on_resource_key),
    CHECK (resource_key <> depends_on_resource_key)
) STRICT;

CREATE TABLE forensics_delivery_attempts (
    resource_key TEXT NOT NULL REFERENCES forensics_outbox(resource_key) ON DELETE RESTRICT,
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    attempt_id TEXT NOT NULL,
    started_at_utc TEXT NOT NULL,
    completed_at_utc TEXT NULL,
    outcome TEXT NOT NULL CHECK (
        outcome IN ('SENDING', 'ACCEPTED', 'RETRYABLE', 'UNKNOWN', 'PAUSED', 'REJECTED', 'CONFLICT')
    ),
    status_code INTEGER NULL,
    problem_code TEXT NULL,
    response_digest BLOB NULL CHECK (response_digest IS NULL OR length(response_digest) = 32),
    response_envelope BLOB NULL CHECK (response_envelope IS NULL OR length(response_envelope) >= 34),
    PRIMARY KEY (resource_key, attempt_number),
    UNIQUE (attempt_id)
) STRICT;

CREATE TABLE forensics_quarantine (
    quarantine_id TEXT PRIMARY KEY,
    conflict_kind TEXT NOT NULL,
    routing_key TEXT NOT NULL,
    expected_digest BLOB NULL CHECK (expected_digest IS NULL OR length(expected_digest) = 32),
    observed_digest BLOB NOT NULL CHECK (length(observed_digest) = 32),
    status TEXT NOT NULL CHECK (status = 'QUARANTINED'),
    created_at_utc TEXT NOT NULL
) STRICT;

CREATE INDEX ix_forensics_events_run_ordinal
    ON forensics_events(run_id, ordinal);
CREATE INDEX ix_forensics_outbox_dispatch
    ON forensics_outbox(status, creation_order);
CREATE INDEX ix_forensics_outbox_dependencies_dependency
    ON forensics_outbox_dependencies(depends_on_resource_key, resource_key);
CREATE INDEX ix_forensics_quarantine_routing
    ON forensics_quarantine(routing_key, created_at_utc);

PRAGMA user_version = 1;
