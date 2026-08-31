DROP TRIGGER operation_batches_no_update;
DROP TRIGGER operation_batches_no_delete;
DROP INDEX ix_batches_operation_created;

CREATE TABLE operation_batches_v4 (
    batch_id BLOB NOT NULL PRIMARY KEY CHECK (length(batch_id) = 16),
    operation TEXT NOT NULL CHECK (operation IN (
        'ValidateTarget',
        'TestTarget',
        'InvokeCommand',
        'EnableSshKeyAuthentication',
        'SetWindowsProcessAuditPolicy',
        'GetHostDetails',
        'GetProcessStartEvents',
        'GetAuthenticationEvents',
        'GetProcessAccessToken',
        'GetUserEffectiveRights'
    )),
    created_at_utc TEXT NOT NULL CHECK (length(created_at_utc) >= 20),
    invocation_count INTEGER NOT NULL CHECK (invocation_count BETWEEN 1 AND 8)
) STRICT;

INSERT INTO operation_batches_v4(batch_id, operation, created_at_utc, invocation_count)
SELECT batch_id, operation, created_at_utc, invocation_count
FROM operation_batches;

DROP TABLE operation_batches;
ALTER TABLE operation_batches_v4 RENAME TO operation_batches;
CREATE INDEX ix_batches_operation_created ON operation_batches(operation, created_at_utc);
CREATE TRIGGER operation_batches_no_update BEFORE UPDATE ON operation_batches BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER operation_batches_no_delete BEFORE DELETE ON operation_batches BEGIN SELECT RAISE(ABORT, 'append-only'); END;

CREATE TABLE visualizer_forensic_events (
    event_id BLOB NOT NULL PRIMARY KEY CHECK (length(event_id) = 16),
    mission_id BLOB NOT NULL REFERENCES visualizer_missions(mission_id),
    target_name_key TEXT NOT NULL,
    endpoint_id TEXT NOT NULL CHECK (length(endpoint_id) = 55),
    schema_name TEXT NOT NULL CHECK (length(schema_name) BETWEEN 3 AND 80),
    occurred_at_utc TEXT NOT NULL CHECK (length(occurred_at_utc) >= 20),
    collected_at_utc TEXT NOT NULL CHECK (length(collected_at_utc) >= 20),
    payload_envelope BLOB NOT NULL CHECK (length(payload_envelope) BETWEEN 34 AND 262176),
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    delivery_status TEXT NOT NULL CHECK (delivery_status IN ('Pending','Delivered')),
    delivery_attempts INTEGER NOT NULL CHECK (delivery_attempts BETWEEN 0 AND 1),
    last_status_code INTEGER NULL CHECK (last_status_code IS NULL OR last_status_code BETWEEN 100 AND 599),
    delivered_at_utc TEXT NULL CHECK (delivered_at_utc IS NULL OR length(delivered_at_utc) >= 20)
) STRICT;

CREATE TABLE forensic_collection_cursors (
    target_name_key TEXT NOT NULL,
    source_name TEXT NOT NULL CHECK (length(source_name) BETWEEN 3 AND 80),
    occurred_at_utc TEXT NOT NULL CHECK (length(occurred_at_utc) >= 20),
    record_id TEXT NOT NULL CHECK (length(record_id) BETWEEN 1 AND 128),
    updated_at_utc TEXT NOT NULL CHECK (length(updated_at_utc) >= 20),
    PRIMARY KEY(target_name_key, source_name)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_forensic_events_target_time
ON visualizer_forensic_events(target_name_key, occurred_at_utc DESC);
CREATE INDEX ix_forensic_events_delivery
ON visualizer_forensic_events(delivery_status, collected_at_utc);
CREATE INDEX ix_forensic_events_schema_time
ON visualizer_forensic_events(schema_name, occurred_at_utc DESC);

CREATE TRIGGER visualizer_forensic_events_no_delete BEFORE DELETE ON visualizer_forensic_events BEGIN SELECT RAISE(ABORT, 'retained evidence'); END;
CREATE TRIGGER forensic_collection_cursors_no_delete BEFORE DELETE ON forensic_collection_cursors BEGIN SELECT RAISE(ABORT, 'retained evidence'); END;
