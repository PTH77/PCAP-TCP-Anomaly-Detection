-- BRONZE LAYER - Raw packets from PCAP

DROP TABLE IF EXISTS bronze_packets CASCADE;

CREATE TABLE bronze_packets (
    id BIGSERIAL PRIMARY KEY,

    pcap_source TEXT,
    frame_number INTEGER,

    timestamp DOUBLE PRECISION NOT NULL,
    inter_arrival DOUBLE PRECISION,

    packet_length INTEGER,
    payload_size INTEGER,

    src_ip TEXT,
    dst_ip TEXT,
    direction TEXT,

    protocol INTEGER,
    ttl INTEGER,

    src_port INTEGER,
    dst_port INTEGER,

    tcp_seq BIGINT,
    tcp_ack BIGINT,
    tcp_flags TEXT,
    tcp_window INTEGER,

    tcp_mss INTEGER,
    tcp_sack_permitted BOOLEAN,

    loaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_bronze_time ON bronze_packets(timestamp);
CREATE INDEX idx_bronze_ips ON bronze_packets(src_ip, dst_ip);
CREATE INDEX idx_bronze_ports ON bronze_packets(src_port, dst_port);
CREATE INDEX idx_bronze_protocol ON bronze_packets(protocol);
CREATE INDEX idx_bronze_pcap ON bronze_packets(pcap_source);


DROP TABLE IF EXISTS silver_flows CASCADE;

CREATE TABLE silver_flows (
    flow_id TEXT PRIMARY KEY,

    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol INTEGER,

    direction TEXT,

    start_time DOUBLE PRECISION,
    end_time DOUBLE PRECISION,
    duration DOUBLE PRECISION,

    packet_count INTEGER,
    total_bytes BIGINT,
    avg_packet_size DOUBLE PRECISION,
    bytes_per_second DOUBLE PRECISION,

    syn_count INTEGER,
    ack_count INTEGER,
    fin_count INTEGER,
    rst_count INTEGER,
    psh_count INTEGER,

    handshake_complete BOOLEAN,
    proper_close BOOLEAN,

    ttl_mean DOUBLE PRECISION,
    ttl_std DOUBLE PRECISION,
    window_mean DOUBLE PRECISION,
    window_std DOUBLE PRECISION,

    mss INTEGER,
    sack_permitted BOOLEAN,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- AGGREGATE (ONLY PACKETS WITH IP)

INSERT INTO silver_flows (
    flow_id,
    src_ip, dst_ip, src_port, dst_port, protocol,
    start_time, end_time, duration,
    packet_count, total_bytes, avg_packet_size, bytes_per_second,
    syn_count, ack_count, fin_count, rst_count, psh_count,
    handshake_complete, proper_close,
    ttl_mean, ttl_std, window_mean, window_std,
    mss, sack_permitted
)

SELECT
    CONCAT(
        src_ip, ':', COALESCE(src_port,0), '-',
        dst_ip, ':', COALESCE(dst_port,0), '-',
        COALESCE(protocol,0)
    ) AS flow_id,

    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol,

    MIN(timestamp),
    MAX(timestamp),
    MAX(timestamp) - MIN(timestamp),

    COUNT(*),
    SUM(packet_length),
    AVG(packet_length),
    SUM(packet_length) / NULLIF(MAX(timestamp)-MIN(timestamp),0),

    SUM(CASE WHEN tcp_flags LIKE '%S%' THEN 1 ELSE 0 END),
    SUM(CASE WHEN tcp_flags LIKE '%A%' THEN 1 ELSE 0 END),
    SUM(CASE WHEN tcp_flags LIKE '%F%' THEN 1 ELSE 0 END),
    SUM(CASE WHEN tcp_flags LIKE '%R%' THEN 1 ELSE 0 END),
    SUM(CASE WHEN tcp_flags LIKE '%P%' THEN 1 ELSE 0 END),

    CASE
        WHEN SUM(CASE WHEN tcp_flags LIKE '%S%' THEN 1 ELSE 0 END) > 0
         AND SUM(CASE WHEN tcp_flags = 'SA' THEN 1 ELSE 0 END) > 0
        THEN TRUE ELSE FALSE
    END,

    CASE
        WHEN SUM(CASE WHEN tcp_flags LIKE '%F%' THEN 1 ELSE 0 END) > 0
        THEN TRUE ELSE FALSE
    END,

    AVG(ttl),
    STDDEV(ttl),
    AVG(tcp_window),
    STDDEV(tcp_window),

    MAX(tcp_mss),
    BOOL_OR(COALESCE(tcp_sack_permitted, FALSE))

FROM bronze_packets
WHERE src_ip IS NOT NULL
  AND dst_ip IS NOT NULL
GROUP BY src_ip, dst_ip, src_port, dst_port, protocol;

-- DIRECTION

UPDATE silver_flows
SET direction =
    CASE
        WHEN src_ip LIKE '10.%' THEN 'outbound'
        WHEN src_ip LIKE '192.168.%' THEN 'outbound'
        WHEN src_ip LIKE '172.16.%' THEN 'outbound'
        ELSE 'inbound'
    END;

-- INDEXES

CREATE INDEX idx_silver_src_ip ON silver_flows(src_ip);
CREATE INDEX idx_silver_dst_ip ON silver_flows(dst_ip);
CREATE INDEX idx_silver_direction ON silver_flows(direction);
CREATE INDEX idx_silver_protocol ON silver_flows(protocol);

-- VALIDATION

SELECT COUNT(*) AS total_flows FROM silver_flows;
SELECT direction, COUNT(*) FROM silver_flows GROUP BY direction;
SELECT protocol, COUNT(*) FROM silver_flows GROUP BY protocol;

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