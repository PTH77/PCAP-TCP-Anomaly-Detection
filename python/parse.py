"""
PCAP Parser - Bronze Layer
"""

from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
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
        })
    else:
        packet_data.update({'src_ip': None, 'dst_ip': None, 'protocol': None, 'ttl': None})
    
    if TCP in pkt:
        packet_data.update({
            'src_port': pkt[TCP].sport,
            'dst_port': pkt[TCP].dport,
            'tcp_seq': pkt[TCP].seq,
            'tcp_ack': pkt[TCP].ack,
            'tcp_flags': str(pkt[TCP].flags),
            'tcp_window': pkt[TCP].window,
        })
        
        options = pkt[TCP].options
        mss = None
        sack_permitted = False
        
        for opt in options:
            if opt[0] == 'MSS':
                mss = opt[1]
            elif opt[0] == 'SAckOK':
                sack_permitted = True
        
        packet_data.update({'tcp_mss': mss, 'tcp_sack_permitted': sack_permitted})
        
    else:
        packet_data.update({
            'src_port': None, 'dst_port': None, 'tcp_seq': None,
            'tcp_ack': None, 'tcp_flags': None, 'tcp_window': None,
            'tcp_mss': None, 'tcp_sack_permitted': None
        })
    
    if UDP in pkt:
        packet_data.update({'src_port': pkt[UDP].sport, 'dst_port': pkt[UDP].dport})
    
    return packet_data

def main():
    print("PCAP Parser - Bronze Layer")
    print("=" * 60)
    
    if not PCAP_FILE.exists():
        print(f"ERROR: {PCAP_FILE} not found")
        sys.exit(1)
    
    packets = rdpcap(str(PCAP_FILE))
    print(f"Loaded {len(packets)} packets")
    
    parsed = [parse_packet(pkt, i) for i, pkt in enumerate(packets, 1)]
    df = pd.DataFrame(parsed)
    
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_CSV, index=False)
    
    print(f"Saved {len(df)} packets to {OUTPUT_CSV}")
    print(f"TCP: {df['tcp_flags'].notna().sum()}, UDP: {(df['protocol']==17).sum()}")

if __name__ == "__main__":
    main()