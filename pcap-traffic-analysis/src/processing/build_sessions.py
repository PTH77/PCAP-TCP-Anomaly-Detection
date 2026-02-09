"""
Session Builder - Silver Layer
"""

import pandas as pd
import numpy as np
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
INPUT_CSV = PROJECT_ROOT / "data" / "bronze" / "packets.csv"
OUTPUT_CSV = PROJECT_ROOT / "data" / "silver" / "sessions.csv"

def build_session_id(row):
    return f"{row['src_ip']}:{row['src_port']}-{row['dst_ip']}:{row['dst_port']}"

def analyze_session(group):
    session = {}
    
    session['session_id'] = build_session_id(group.iloc[0])
    session['src_ip'] = group.iloc[0]['src_ip']
    session['dst_ip'] = group.iloc[0]['dst_ip']
    session['src_port'] = group.iloc[0]['src_port']
    session['dst_port'] = group.iloc[0]['dst_port']
    
    session['start_time'] = group['timestamp'].min()
    session['end_time'] = group['timestamp'].max()
    session['duration'] = session['end_time'] - session['start_time']
    
    session['packet_count'] = len(group)
    session['total_bytes'] = group['packet_length'].sum()
    session['avg_packet_size'] = group['packet_length'].mean()
    
    flags_str = group['tcp_flags'].dropna().astype(str)
    session['syn_count'] = flags_str.str.contains('S').sum()
    session['ack_count'] = flags_str.str.contains('A').sum()
    session['fin_count'] = flags_str.str.contains('F').sum()
    session['rst_count'] = flags_str.str.contains('R').sum()
    session['psh_count'] = flags_str.str.contains('P').sum()
    
    has_syn = session['syn_count'] > 0
    has_synack = (flags_str == 'SA').any()
    has_final_ack = session['ack_count'] > 1
    session['handshake_complete'] = has_syn and has_synack and has_final_ack
    
    has_fin = session['fin_count'] > 0
    has_fin_ack = (flags_str.str.contains('F') & flags_str.str.contains('A')).any()
    session['proper_close'] = has_fin or has_fin_ack
    
    session['ttl_values'] = group['ttl'].dropna().tolist()
    session['ttl_mean'] = group['ttl'].mean()
    session['ttl_std'] = group['ttl'].std()
    session['ttl_min'] = group['ttl'].min()
    session['ttl_max'] = group['ttl'].max()
    
    session['window_mean'] = group['tcp_window'].mean()
    session['window_std'] = group['tcp_window'].std()
    session['window_min'] = group['tcp_window'].min()
    session['window_max'] = group['tcp_window'].max()
    
    mss_vals = group['tcp_mss'].dropna()
    session['mss'] = mss_vals.iloc[0] if len(mss_vals) > 0 else None
    
    wscale_vals = group['tcp_window_scale'].dropna()
    session['window_scale'] = wscale_vals.iloc[0] if len(wscale_vals) > 0 else None
    
    sack_vals = group['tcp_sack_permitted'].dropna()
    session['sack_permitted'] = sack_vals.iloc[0] if len(sack_vals) > 0 else False
    
    timestamps_vals = group['tcp_timestamps'].dropna()
    session['has_timestamps'] = len(timestamps_vals) > 0
    
    return pd.Series(session)

def main():
    print("Session Builder - Silver Layer")
    print("=" * 60)
    
    print(f"Loading: {INPUT_CSV}")
    df = pd.read_csv(INPUT_CSV)
    print(f"Loaded {len(df)} packets")
    
    tcp_packets = df[df['protocol'] == 6].copy()
    print(f"TCP packets: {len(tcp_packets)}")
    
    print("Building sessions...")
    tcp_packets['session_key'] = tcp_packets.apply(build_session_id, axis=1)
    
    sessions = tcp_packets.groupby('session_key').apply(analyze_session).reset_index(drop=True)
    
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    sessions.to_csv(OUTPUT_CSV, index=False)
    
    print(f"\nSaved {len(sessions)} sessions to: {OUTPUT_CSV}")
    print(f"Size: {OUTPUT_CSV.stat().st_size / 1024:.1f} KB")
    
    print(f"\nFirst 3 sessions:")
    print(sessions.head(3)[['session_id', 'packet_count', 'duration', 'handshake_complete']].to_string())
    
    print(f"\nStats:")
    print(f"  Total sessions: {len(sessions)}")
    print(f"  Complete handshakes: {sessions['handshake_complete'].sum()}")
    print(f"  Incomplete handshakes: {(~sessions['handshake_complete']).sum()}")
    print(f"  Proper close: {sessions['proper_close'].sum()}")
    print(f"  Average duration: {sessions['duration'].mean():.2f}s")
    print(f"  Average packets per session: {sessions['packet_count'].mean():.1f}")
    

if __name__ == "__main__":
    main()