from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PCAP_DIR = PROJECT_ROOT / "data" / "raw"
OUTPUT_CSV = PROJECT_ROOT / "data" / "bronze" / "packets.csv"

FLOOD_SAMPLE_RATE = 100
LOCAL_IP = None


def is_flood_attack(pcap_file):
    return "flood" in pcap_file.name.lower()


def get_direction(src_ip):
    if LOCAL_IP is None:
        return None
    return "out" if src_ip == LOCAL_IP else "in"


def parse_packet(pkt, frame_number, pcap_filename, inter_arrival):
    payload_size = len(pkt.payload) if pkt.payload else 0

    data = {
        "pcap_source": pcap_filename,
        "frame_number": frame_number,
        "timestamp": float(pkt.time),
        "packet_length": len(pkt),
        "payload_size": payload_size,
        "inter_arrival": inter_arrival
    }

    if IP in pkt:
        src_ip = pkt[IP].src
        data.update({
            "src_ip": src_ip,
            "dst_ip": pkt[IP].dst,
            "protocol": pkt[IP].proto,
            "ttl": pkt[IP].ttl,
            "direction": get_direction(src_ip)
        })
    else:
        data.update({
            "src_ip": None,
            "dst_ip": None,
            "protocol": None,
            "ttl": None,
            "direction": None
        })

    if TCP in pkt:
        tcp = pkt[TCP]
        data.update({
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "tcp_seq": tcp.seq,
            "tcp_ack": tcp.ack,
            "tcp_flags": str(tcp.flags),
            "tcp_window": tcp.window
        })

        mss = None
        sack = False
        for opt in tcp.options:
            if opt[0] == "MSS":
                mss = opt[1]
            elif opt[0] == "SAckOK":
                sack = True

        data["tcp_mss"] = mss
        data["tcp_sack_permitted"] = sack

    else:
        data.update({
            "src_port": None,
            "dst_port": None,
            "tcp_seq": None,
            "tcp_ack": None,
            "tcp_flags": None,
            "tcp_window": None,
            "tcp_mss": None,
            "tcp_sack_permitted": None
        })

    if UDP in pkt:
        udp = pkt[UDP]
        data["src_port"] = udp.sport
        data["dst_port"] = udp.dport

    return data


def main():
    pcap_files = sorted(PCAP_DIR.glob("*.pcap"))

    if not pcap_files:
        print("no pcaps")
        sys.exit(1)

    all_packets = []

    for idx, pcap_file in enumerate(pcap_files, 1):
        print(f"[{idx}/{len(pcap_files)}] {pcap_file.name}")

        is_flood = is_flood_attack(pcap_file)

        packet_counter = 0
        parsed_counter = 0
        prev_time = None

        try:
            with PcapReader(str(pcap_file)) as reader:
                for pkt in reader:
                    packet_counter += 1

                    if is_flood and packet_counter % FLOOD_SAMPLE_RATE != 0:
                        continue

                    current_time = float(pkt.time)
                    inter_arrival = (
                        current_time - prev_time if prev_time else 0
                    )
                    prev_time = current_time

                    data = parse_packet(
                        pkt,
                        parsed_counter + 1,
                        pcap_file.name,
                        inter_arrival
                    )

                    all_packets.append(data)
                    parsed_counter += 1

            print(f"parsed {parsed_counter}")

        except Exception as e:
            print(f"error {e}")

    df = pd.DataFrame(all_packets)
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_CSV, index=False)

    print("done")
    print(f"rows {len(df)}")
    print(f"path {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
