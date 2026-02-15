-- ================================================================
-- STRICT OPERATIONAL LABELING
-- ================================================================

TRUNCATE TABLE gold;

INSERT INTO gold (
    flow_id, log_packet_count, duration,
    packets_per_second, bytes_per_second, avg_packet_size,
    syn_ratio, ack_ratio, rst_ratio, fin_ratio,
    handshake_complete, proper_close,
    ttl_mean, ttl_std, window_mean, window_std,
    mss_present, sack_present, is_burst, label
)
SELECT
    session_id AS flow_id,
    LOG(packet_count + 1),
    duration,
    packet_count::FLOAT / NULLIF(duration, 0),
    total_bytes::FLOAT / NULLIF(duration, 0),
    avg_packet_size,
    syn_count::FLOAT / NULLIF(packet_count, 0),
    ack_count::FLOAT / NULLIF(packet_count, 0),
    rst_count::FLOAT / NULLIF(packet_count, 0),
    fin_count::FLOAT / NULLIF(packet_count, 0),
    handshake_complete,
    proper_close,
    ttl_mean, ttl_std, window_mean, window_std,
    mss IS NOT NULL,
    sack_permitted,
    (packet_count::FLOAT / NULLIF(duration, 0)) > 100,

    -- ================================================================
    -- STRICT 4-CLASS OPERATIONAL LABELING
    -- ================================================================
    CASE
        -- ============================================================
        -- MALICIOUS (high confidence threats)
        -- ============================================================

        -- Port scanning: many incomplete handshakes
        WHEN handshake_complete = FALSE
         AND syn_count > 0
         AND packet_count < 10
        THEN 'malicious'

        -- C2-like: long session without proper start
        WHEN handshake_complete = FALSE
         AND syn_count = 0
         AND packet_count > 100
         AND duration > 60
        THEN 'malicious'

        -- Data exfiltration: huge volume
        WHEN packet_count > 10000
         AND duration > 0
        THEN 'malicious'

        -- Reset attacks
        WHEN rst_count > 0
         AND packet_count < 5
        THEN 'malicious'

        -- ============================================================
        -- SUSPICIOUS (anomalies, gray area)
        -- ============================================================

        -- Long session without handshake (medium volume)
        WHEN handshake_complete = FALSE
         AND syn_count = 0
         AND packet_count BETWEEN 50 AND 100
        THEN 'suspicious'

        -- Complete handshake but very long duration (VPN? C2?)
        WHEN handshake_complete = TRUE
         AND duration > 3600  -- 1 hour
         AND packet_count > 1000
        THEN 'suspicious'

        -- High packet rate (potential DoS or legit streaming?)
        WHEN (packet_count::FLOAT / NULLIF(duration, 0)) > 500
         AND handshake_complete = TRUE
        THEN 'suspicious'

        -- Incomplete with medium activity (failed or probe?)
        WHEN handshake_complete = FALSE
         AND syn_count = 0
         AND packet_count BETWEEN 10 AND 50
        THEN 'suspicious'

        -- ============================================================
        -- BENIGN (strict criteria - typical clean traffic)
        -- ============================================================

        -- Normal clean session:
        -- - complete handshake
        -- - proper close
        -- - reasonable duration
        -- - moderate packet count
        WHEN handshake_complete = TRUE
         AND proper_close = TRUE
         AND duration BETWEEN 0.1 AND 600  -- 10 min max
         AND packet_count BETWEEN 5 AND 1000
        THEN 'benign'

        -- Short clean session
        WHEN handshake_complete = TRUE
         AND packet_count BETWEEN 3 AND 50
         AND duration < 10
        THEN 'benign'

        -- ============================================================
        -- BACKGROUND (noise, system traffic)
        -- ============================================================

        -- Single packet (probe, keepalive)
        WHEN packet_count = 1
        THEN 'background'

        -- Very short incomplete (timeout, NAT)
        WHEN handshake_complete = FALSE
         AND packet_count BETWEEN 2 AND 5
         AND duration < 1
        THEN 'background'

        -- ============================================================
        -- DEFAULT: suspicious (anything weird)
        -- ============================================================
        ELSE 'suspicious'
    END

FROM silver_sessions;

-- ================================================================
-- VERIFY STRICT LABELING (FIXED)
-- ================================================================

SELECT
    g.label,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage,
    ROUND(AVG(s.packet_count)::NUMERIC, 0) as avg_packets,
    ROUND(AVG(s.duration)::NUMERIC, 0) as avg_duration_sec,
    MIN(s.packet_count) as min_packets,
    MAX(s.packet_count) as max_packets
FROM silver_sessions s
JOIN gold g ON s.session_id = g.flow_id
GROUP BY g.label
ORDER BY
    CASE g.label
        WHEN 'malicious' THEN 1
        WHEN 'suspicious' THEN 2
        WHEN 'benign' THEN 3
        WHEN 'background' THEN 4
    END;

-- Check borderline cases
SELECT
    'benign_stats' as category,
    COUNT(*) as count,
    ROUND(AVG(s.duration)::NUMERIC, 0) as avg_duration,
    ROUND(AVG(s.packet_count)::NUMERIC, 0) as avg_packets
FROM silver_sessions s
JOIN gold g ON s.session_id = g.flow_id
WHERE g.label = 'benign'

UNION ALL

SELECT
    'suspicious_stats',
    COUNT(*),
    ROUND(AVG(s.duration)::NUMERIC, 0),
    ROUND(AVG(s.packet_count)::NUMERIC, 0)
FROM silver_sessions s
JOIN gold g ON s.session_id = g.flow_id
WHERE g.label = 'suspicious';