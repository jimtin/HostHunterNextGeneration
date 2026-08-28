DROP TRIGGER operation_batches_no_update;
DROP TRIGGER operation_batches_no_delete;
DROP INDEX ix_batches_operation_created;

CREATE TABLE operation_batches_v3 (
    batch_id BLOB NOT NULL PRIMARY KEY CHECK (length(batch_id) = 16),
    operation TEXT NOT NULL CHECK (operation IN (
        'ValidateTarget',
        'TestTarget',
        'InvokeCommand',
        'EnableSshKeyAuthentication',
        'SetWindowsProcessAuditPolicy',
        'GetHostDetails'
    )),
    created_at_utc TEXT NOT NULL CHECK (length(created_at_utc) >= 20),
    invocation_count INTEGER NOT NULL CHECK (invocation_count BETWEEN 1 AND 8)
) STRICT;

INSERT INTO operation_batches_v3(batch_id, operation, created_at_utc, invocation_count)
SELECT batch_id, operation, created_at_utc, invocation_count
FROM operation_batches;

DROP TABLE operation_batches;
ALTER TABLE operation_batches_v3 RENAME TO operation_batches;
CREATE INDEX ix_batches_operation_created ON operation_batches(operation, created_at_utc);
CREATE TRIGGER operation_batches_no_update BEFORE UPDATE ON operation_batches BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER operation_batches_no_delete BEFORE DELETE ON operation_batches BEGIN SELECT RAISE(ABORT, 'append-only'); END;

CREATE TABLE visualizer_store_state (
    singleton_id INTEGER NOT NULL PRIMARY KEY CHECK (singleton_id = 1),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    current_mission_id BLOB NULL CHECK (
        current_mission_id IS NULL OR length(current_mission_id) = 16
    ),
    state_mac BLOB NOT NULL CHECK (length(state_mac) = 32)
) STRICT;

CREATE TABLE visualizer_missions (
    mission_id BLOB NOT NULL PRIMARY KEY CHECK (length(mission_id) = 16),
    activation_id TEXT NULL UNIQUE CHECK (
        activation_id IS NULL OR (length(activation_id) BETWEEN 1 AND 128)
    ),
    started_at_utc TEXT NOT NULL CHECK (length(started_at_utc) >= 20),
    payload_json BLOB NOT NULL CHECK (length(payload_json) BETWEEN 2 AND 262144),
    delivery_status TEXT NOT NULL CHECK (delivery_status IN ('Pending','Delivered','Failed')),
    delivery_attempts INTEGER NOT NULL CHECK (delivery_attempts BETWEEN 0 AND 1),
    last_status_code INTEGER NULL CHECK (last_status_code IS NULL OR last_status_code BETWEEN 100 AND 599),
    delivered_at_utc TEXT NULL CHECK (delivered_at_utc IS NULL OR length(delivered_at_utc) >= 20)
) STRICT;

CREATE TABLE visualizer_endpoint_identities (
    target_name_key TEXT NOT NULL PRIMARY KEY,
    endpoint_id TEXT NOT NULL UNIQUE CHECK (length(endpoint_id) = 55),
    identity_strategy TEXT NOT NULL CHECK (identity_strategy IN ('platform_instance_hmac_sha256','persisted_random')),
    last_seen_at_utc TEXT NOT NULL CHECK (length(last_seen_at_utc) >= 20)
) STRICT;

CREATE TABLE visualizer_host_observations (
    event_id BLOB NOT NULL PRIMARY KEY CHECK (length(event_id) = 16),
    mission_id BLOB NOT NULL REFERENCES visualizer_missions(mission_id),
    target_name_key TEXT NOT NULL,
    endpoint_id TEXT NOT NULL CHECK (length(endpoint_id) = 55),
    observed_at_utc TEXT NOT NULL CHECK (length(observed_at_utc) >= 20),
    payload_envelope BLOB NOT NULL CHECK (length(payload_envelope) BETWEEN 34 AND 262176),
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    delivery_status TEXT NOT NULL CHECK (delivery_status IN ('Pending','Delivered','Failed')),
    delivery_attempts INTEGER NOT NULL CHECK (delivery_attempts BETWEEN 0 AND 1),
    last_status_code INTEGER NULL CHECK (last_status_code IS NULL OR last_status_code BETWEEN 100 AND 599),
    delivered_at_utc TEXT NULL CHECK (delivered_at_utc IS NULL OR length(delivered_at_utc) >= 20)
) STRICT;

CREATE INDEX ix_visualizer_observations_target_time
ON visualizer_host_observations(target_name_key, observed_at_utc DESC);
CREATE INDEX ix_visualizer_observations_delivery
ON visualizer_host_observations(delivery_status, observed_at_utc);

CREATE TRIGGER visualizer_missions_no_delete BEFORE DELETE ON visualizer_missions BEGIN SELECT RAISE(ABORT, 'retained evidence'); END;
CREATE TRIGGER visualizer_endpoint_identities_no_delete BEFORE DELETE ON visualizer_endpoint_identities BEGIN SELECT RAISE(ABORT, 'retained evidence'); END;
CREATE TRIGGER visualizer_host_observations_no_delete BEFORE DELETE ON visualizer_host_observations BEGIN SELECT RAISE(ABORT, 'retained evidence'); END;
