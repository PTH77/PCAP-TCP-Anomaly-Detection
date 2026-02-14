INSERT INTO silver_sessions (
    session_id, src_ip, dst_ip, src_port, dst_port,
    start_time, end_time, duration,
    packet_count, total_bytes, avg_packet_size,
    syn_count, ack_count, fin_count, rst_count,
    handshake_complete, proper_close,
    ttl_mean, ttl_std, window_mean, window_std,
    mss, sack_permitted
)
SELECT 
    src_ip || ':' || src_port || '-' || dst_ip || ':' || dst_port AS session_id,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    
    MIN(timestamp) AS start_time,
    MAX(timestamp) AS end_time,
    MAX(timestamp) - MIN(timestamp) AS duration,
    
    COUNT(*) AS packet_count,
    SUM(packet_length) AS total_bytes,
    AVG(packet_length) AS avg_packet_size,
    
    SUM(CASE WHEN tcp_flags LIKE '%S%' THEN 1 ELSE 0 END) AS syn_count,
    SUM(CASE WHEN tcp_flags LIKE '%A%' THEN 1 ELSE 0 END) AS ack_count,
    SUM(CASE WHEN tcp_flags LIKE '%F%' THEN 1 ELSE 0 END) AS fin_count,
    SUM(CASE WHEN tcp_flags LIKE '%R%' THEN 1 ELSE 0 END) AS rst_count,
    
    CASE 
        WHEN SUM(CASE WHEN tcp_flags LIKE '%S%' THEN 1 ELSE 0 END) > 0
         AND SUM(CASE WHEN tcp_flags = 'SA' THEN 1 ELSE 0 END) > 0
         AND SUM(CASE WHEN tcp_flags LIKE '%A%' THEN 1 ELSE 0 END) > 1
        THEN TRUE ELSE FALSE
    END AS handshake_complete,
    
    CASE 
        WHEN SUM(CASE WHEN tcp_flags LIKE '%F%' THEN 1 ELSE 0 END) > 0
        THEN TRUE ELSE FALSE
    END AS proper_close,
    
    AVG(ttl) AS ttl_mean,
    STDDEV(ttl) AS ttl_std,
    AVG(tcp_window) AS window_mean,
    STDDEV(tcp_window) AS window_std,
    
    MAX(tcp_mss) AS mss,
    BOOL_OR(COALESCE(tcp_sack_permitted, FALSE)) AS sack_permitted  -- ← POPRAWKA

FROM bronze_packets
WHERE protocol = 6
GROUP BY src_ip, dst_ip, src_port, dst_port;