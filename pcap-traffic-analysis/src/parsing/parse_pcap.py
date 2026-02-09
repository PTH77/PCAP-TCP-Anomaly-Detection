"""
PCAP Parser - Bronze Layer
"""

from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PCAP_FILE = PROJECT_ROOT / "data" / "raw" / "toolsmith.pcap"
OUTPUT_CSV = PROJECT_ROOT / "data" / "bronze" / "packets.csv"

def parse_packet(pkt, frame_number):
    packet_data = {
        'frame_number': frame_number,
        'timestamp': float(pkt.time),
        'packet_length': len(pkt),
    }
    
    if IP in pkt:
        packet_data.update({
            'src_ip': pkt[IP].src,
            'dst_ip': pkt[IP].dst,
            'protocol': pkt[IP].proto,
            'ttl': pkt[IP].ttl,
            'ip_len': pkt[IP].len,
        })
    else:
        packet_data.update({
            'src_ip': None,
            'dst_ip': None,
            'protocol': None,
            'ttl': None,
            'ip_len': None,
        })
    
    if TCP in pkt:
        packet_data.update({
            'src_port': pkt[TCP].sport,
            'dst_port': pkt[TCP].dport,
            'tcp_seq': pkt[TCP].seq,
            'tcp_ack': pkt[TCP].ack,
            'tcp_flags': str(pkt[TCP].flags),
            'tcp_window': pkt[TCP].window,
            'tcp_dataofs': pkt[TCP].dataofs,
        })
        
        options = pkt[TCP].options
        packet_data['tcp_options_raw'] = str(options)
        
        mss = None
        window_scale = None
        sack_permitted = False
        timestamps = None
        
        for opt in options:
            if opt[0] == 'MSS':
                mss = opt[1]
            elif opt[0] == 'WScale':
                window_scale = opt[1]
            elif opt[0] == 'SAckOK':
                sack_permitted = True
            elif opt[0] == 'Timestamp':
                timestamps = str(opt[1])
        
        packet_data.update({
            'tcp_mss': mss,
            'tcp_window_scale': window_scale,
            'tcp_sack_permitted': sack_permitted,
            'tcp_timestamps': timestamps,
        })
        
    else:
        packet_data.update({
            'src_port': None,
            'dst_port': None,
            'tcp_seq': None,
            'tcp_ack': None,
            'tcp_flags': None,
            'tcp_window': None,
            'tcp_dataofs': None,
            'tcp_options_raw': None,
            'tcp_mss': None,
            'tcp_window_scale': None,
            'tcp_sack_permitted': None,
            'tcp_timestamps': None,
        })
    
    if UDP in pkt:
        packet_data.update({
            'src_port': pkt[UDP].sport,
            'dst_port': pkt[UDP].dport,
        })
    
    return packet_data


def main():
    print("PCAP Parser - Bronze Layer")
    print("=" * 60)
    
    if not PCAP_FILE.exists():
        print(f"ERROR: File not found {PCAP_FILE}")
        sys.exit(1)
    
    print(f"Loading: {PCAP_FILE}")
    packets = rdpcap(str(PCAP_FILE))
    print(f"Loaded {len(packets)} packets")
    
    print(f"Parsing packets...")
    parsed_packets = []
    
    for i, pkt in enumerate(packets, start=1):
        packet_data = parse_packet(pkt, frame_number=i)
        parsed_packets.append(packet_data)
        
        if i % 100 == 0:
            print(f"  {i}/{len(packets)} processed")
    
    df = pd.DataFrame(parsed_packets)
    
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_CSV, index=False)
    
    print(f"\nSaved {len(df)} packets to: {OUTPUT_CSV}")
    print(f"Size: {OUTPUT_CSV.stat().st_size / 1024:.1f} KB")
    
    print(f"\nFirst 3 packets:")
    print(df.head(3).to_string())
    
    print(f"\nStats:")
    print(f"  Unique source IPs: {df['src_ip'].nunique()}")
    print(f"  Unique dest IPs: {df['dst_ip'].nunique()}")
    print(f"  TCP packets: {df['tcp_flags'].notna().sum()}")
    print(f"  Average TTL: {df['ttl'].mean():.1f}")
    print(f"  Average Window Size: {df['tcp_window'].mean():.0f}")


if __name__ == "__main__":
    main()