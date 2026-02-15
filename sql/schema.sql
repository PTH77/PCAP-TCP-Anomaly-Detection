-- ================================================================
-- BRONZE LAYER - Raw packets from tshark
-- ================================================================

DROP TABLE IF EXISTS bronze_packets CASCADE;

CREATE TABLE bronze_packets (
    id SERIAL PRIMARY KEY,

    -- Frame info
    frame_number BIGINT,
    frame_time_epoch DOUBLE PRECISION,
    frame_len INTEGER,

    -- IP layer
    ip_src TEXT,
    ip_dst TEXT,
    ip_ttl INTEGER,
    ip_proto INTEGER,

    -- TCP layer
    tcp_srcport INTEGER,
    tcp_dstport INTEGER,
    tcp_len INTEGER,
    tcp_flags TEXT,
    tcp_window_size INTEGER,
    tcp_seq BIGINT,
    tcp_ack BIGINT,
    tcp_options_mss_val INTEGER,
    tcp_options_sack_perm TEXT,

    -- UDP layer
    udp_srcport INTEGER,
    udp_dstport INTEGER,

    -- Metadata
    loaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE bronze_packets IS 'Raw packets from tshark - immutable bronze layer';

-- ================================================================
-- SILVER LAYER - TCP Sessions
-- ================================================================

DROP TABLE IF EXISTS silver_sessions CASCADE;

CREATE TABLE silver_sessions (
    session_id TEXT PRIMARY KEY,

    -- Session identity
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol INTEGER,

    -- Timing
    start_time DOUBLE PRECISION,
    end_time DOUBLE PRECISION,
    duration DOUBLE PRECISION,

    -- Volume
    packet_count INTEGER,
    total_bytes BIGINT,
    avg_packet_size DOUBLE PRECISION,

    -- TCP Flags
    syn_count INTEGER,
    ack_count INTEGER,
    fin_count INTEGER,
    rst_count INTEGER,
    psh_count INTEGER,

    -- Session Quality
    handshake_complete BOOLEAN,
    proper_close BOOLEAN,

    -- Network Fingerprint
    ttl_mean DOUBLE PRECISION,
    ttl_std DOUBLE PRECISION,
    window_mean DOUBLE PRECISION,
    window_std DOUBLE PRECISION,

    -- TCP Options
    mss INTEGER,
    sack_permitted BOOLEAN,

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE silver_sessions IS 'TCP sessions aggregated from bronze packets';

-- ================================================================
-- GOLD LAYER - ML Features (flow-based)
-- ================================================================

DROP TABLE IF EXISTS gold CASCADE;

CREATE TABLE gold (
    flow_id TEXT PRIMARY KEY,

    -- VOLUME (log transformed)
    log_packet_count DOUBLE PRECISION,

    -- TIME
    duration DOUBLE PRECISION,
    packets_per_second DOUBLE PRECISION,
    bytes_per_second DOUBLE PRECISION,

    -- SIZE
    avg_packet_size DOUBLE PRECISION,

    -- TCP BEHAVIOR
    syn_ratio DOUBLE PRECISION,
    ack_ratio DOUBLE PRECISION,
    rst_ratio DOUBLE PRECISION,
    fin_ratio DOUBLE PRECISION,

    -- SESSION QUALITY
    handshake_complete BOOLEAN,
    proper_close BOOLEAN,

    -- NETWORK FINGERPRINT
    ttl_mean DOUBLE PRECISION,
    ttl_std DOUBLE PRECISION,
    window_mean DOUBLE PRECISION,
    window_std DOUBLE PRECISION,

    -- TCP OPTIONS
    mss_present BOOLEAN,
    sack_present BOOLEAN,

    -- BEHAVIORAL
    is_burst BOOLEAN,

    -- TARGET
    label TEXT,

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE gold IS 'ML-ready features - one row per flow';

-- ================================================================
-- GOLD ANOMALIES - Detected anomalies
-- ================================================================

DROP TABLE IF EXISTS gold_anomalies CASCADE;

CREATE TABLE gold_anomalies (
    anomaly_id SERIAL PRIMARY KEY,
    src_ip TEXT NOT NULL,

    detection_method TEXT,
    anomaly_type TEXT,

    anomaly_score DOUBLE PRECISION,
    confidence DOUBLE PRECISION,
    evidence JSONB,

    severity TEXT CHECK (severity IN ('low', 'medium', 'high', 'critical')),

    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_anomalies_src_ip ON gold_anomalies(src_ip);

-- ================================================================
-- VERIFY
-- ================================================================

SELECT
    tablename,
    schemaname
FROM pg_tables
WHERE tablename IN ('bronze_packets', 'silver_sessions', 'gold', 'gold_anomalies')
ORDER BY tablename;