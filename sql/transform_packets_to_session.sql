TRUNCATE TABLE silver_sessions;

INSERT INTO silver_sessions (
    session_id,
    src_ip, dst_ip, src_port, dst_port, protocol,
    start_time, end_time, duration,
    packet_count, total_bytes, avg_packet_size,
    syn_count, ack_count, fin_count, rst_count, psh_count,
    handshake_complete, proper_close,
    ttl_mean, ttl_std, window_mean, window_std,
    mss, sack_permitted
)
SELECT
    -- Bidirectional session ID (sorted IPs/ports)
    CASE
        WHEN src_ip < dst_ip THEN
            src_ip || ':' || COALESCE(src_port::TEXT, '0') || '-' ||
            dst_ip || ':' || COALESCE(dst_port::TEXT, '0')
        ELSE
            dst_ip || ':' || COALESCE(dst_port::TEXT, '0') || '-' ||
            src_ip || ':' || COALESCE(src_port::TEXT, '0')
    END || '-' || COALESCE(protocol::TEXT, '0') AS session_id,

    -- Keep original direction (first packet's direction)
    (ARRAY_AGG(src_ip ORDER BY frame_time_epoch))[1] AS src_ip,
    (ARRAY_AGG(dst_ip ORDER BY frame_time_epoch))[1] AS dst_ip,
    (ARRAY_AGG(src_port ORDER BY frame_time_epoch))[1] AS src_port,
    (ARRAY_AGG(dst_port ORDER BY frame_time_epoch))[1] AS dst_port,
    protocol,

    -- Timing
    MIN(frame_time_epoch) AS start_time,
    MAX(frame_time_epoch) AS end_time,
    MAX(frame_time_epoch) - MIN(frame_time_epoch) AS duration,

    -- Volume
    COUNT(*) AS packet_count,
    SUM(frame_len) AS total_bytes,
    AVG(frame_len) AS avg_packet_size,

    -- TCP Flags (now includes both directions!)
    SUM(CASE WHEN tcp_flags = '0x0002' THEN 1 ELSE 0 END) AS syn_count,
    SUM(CASE WHEN tcp_flags IN ('0x0010', '0x0012', '0x0018', '0x0011', '0x0019')
        THEN 1 ELSE 0 END) AS ack_count,
    SUM(CASE WHEN tcp_flags IN ('0x0001', '0x0011', '0x0019') THEN 1 ELSE 0 END) AS fin_count,
    SUM(CASE WHEN tcp_flags IN ('0x0004', '0x0014') THEN 1 ELSE 0 END) AS rst_count,
    SUM(CASE WHEN tcp_flags IN ('0x0018', '0x0019') THEN 1 ELSE 0 END) AS psh_count,

    -- Handshake detection (NOW will work!)
    CASE
        WHEN SUM(CASE WHEN tcp_flags = '0x0002' THEN 1 ELSE 0 END) > 0  -- SYN
         AND SUM(CASE WHEN tcp_flags = '0x0012' THEN 1 ELSE 0 END) > 0  -- SYN-ACK
         AND SUM(CASE WHEN tcp_flags = '0x0010' THEN 1 ELSE 0 END) > 0  -- ACK
        THEN TRUE
        ELSE FALSE
    END AS handshake_complete,

    -- Proper close
    CASE
        WHEN SUM(CASE WHEN tcp_flags IN ('0x0001', '0x0011', '0x0019') THEN 1 ELSE 0 END) > 0
        THEN TRUE
        ELSE FALSE
    END AS proper_close,

    -- Network characteristics
    AVG(ip_ttl) AS ttl_mean,
    STDDEV(ip_ttl) AS ttl_std,
    AVG(tcp_window_size) AS window_mean,
    STDDEV(tcp_window_size) AS window_std,

    -- TCP Options
    MAX(tcp_options_mss_val) AS mss,
    BOOL_OR(tcp_options_sack_perm IS NOT NULL) AS sack_permitted

FROM (
    SELECT
        ip_src AS src_ip,
        ip_dst AS dst_ip,
        COALESCE(tcp_srcport, udp_srcport) AS src_port,
        COALESCE(tcp_dstport, udp_dstport) AS dst_port,
        ip_proto AS protocol,
        frame_time_epoch,
        frame_len,
        tcp_flags,
        ip_ttl,
        tcp_window_size,
        tcp_options_mss_val,
        tcp_options_sack_perm
    FROM bronze_packets
    WHERE ip_src IS NOT NULL
      AND ip_dst IS NOT NULL
) AS normalized

-- Group BIDIRECTIONALLY (both directions together)
GROUP BY
    CASE
        WHEN src_ip < dst_ip THEN
            src_ip || ':' || COALESCE(src_port::TEXT, '0') || '-' ||
            dst_ip || ':' || COALESCE(dst_port::TEXT, '0')
        ELSE
            dst_ip || ':' || COALESCE(dst_port::TEXT, '0') || '-' ||
            src_ip || ':' || COALESCE(src_port::TEXT, '0')
    END,
    protocol;

SELECT
    COUNT(*) AS total_sessions,
    SUM(CASE WHEN handshake_complete THEN 1 ELSE 0 END) AS complete_handshakes,
    SUM(CASE WHEN NOT handshake_complete THEN 1 ELSE 0 END) AS incomplete_handshakes,
    ROUND(SUM(CASE WHEN handshake_complete THEN 1 ELSE 0 END)::NUMERIC * 100.0 / COUNT(*), 2) AS complete_percentage
FROM silver_sessions;

-- Check sample
SELECT
    session_id,
    packet_count,
    syn_count,
    ack_count,
    handshake_complete
FROM silver_sessions
WHERE syn_count > 0
ORDER BY packet_count DESC
LIMIT 10;