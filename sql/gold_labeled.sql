DROP TABLE IF EXISTS gold;

CREATE TABLE gold (
    flow_id TEXT PRIMARY KEY,

    -- VOLUME (log scale)
    log_packet_count DOUBLE PRECISION,
    log_total_bytes DOUBLE PRECISION,

    -- TIME
    duration DOUBLE PRECISION,

    -- SIZE
    avg_packet_size DOUBLE PRECISION,

    -- TCP BEHAVIOR
    syn_ratio DOUBLE PRECISION,
    ack_ratio DOUBLE PRECISION,
    rst_ratio DOUBLE PRECISION,
    fin_ratio DOUBLE PRECISION,

    -- SESSION FLAGS
    handshake_complete BOOLEAN,
    proper_close BOOLEAN,

    -- NETWORK FINGERPRINT
    ttl_mean DOUBLE PRECISION,
    ttl_std DOUBLE PRECISION,
    window_mean DOUBLE PRECISION,
    window_std DOUBLE PRECISION,

    -- TCP OPTIONS PROFILE
    mss_present BOOLEAN,
    sack_present BOOLEAN,

    -- TARGET (do wypełnienia)
    label TEXT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO gold (
    flow_id,
    log_packet_count,
    log_total_bytes,
    duration,
    avg_packet_size,
    syn_ratio,
    ack_ratio,
    rst_ratio,
    fin_ratio,
    handshake_complete,
    proper_close,
    ttl_mean,
    ttl_std,
    window_mean,
    window_std,
    mss_present,
    sack_present,
    label
)
SELECT
    flow_id,

    LOG(packet_count + 1),
    LOG(total_bytes + 1),

    duration,
    avg_packet_size,

    syn_count::float / NULLIF(packet_count,0),
    ack_count::float / NULLIF(packet_count,0),
    rst_count::float / NULLIF(packet_count,0),
    fin_count::float / NULLIF(packet_count,0),

    handshake_complete,
    proper_close,

    ttl_mean,
    ttl_std,
    window_mean,
    window_std,

    mss IS NOT NULL,
    sack_permitted,

    -- AUTO LABELING (możesz zmienić)
    CASE
        WHEN handshake_complete = false AND packet_count = 1 THEN 'scan'
        WHEN rst_count > 0 AND packet_count < 5 THEN 'reset_attack'
        ELSE 'unknown'
    END

FROM silver_flows
WHERE flow_id IS NOT NULL;
