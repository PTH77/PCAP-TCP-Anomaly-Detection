"""
PCAP Parser - tshark version (FIXED for Windows)
"""

import subprocess
from pathlib import Path
import pandas as pd
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]

RAW_DIRS = [
    PROJECT_ROOT / "data" / "raw",
    PROJECT_ROOT / "data" / "raw2"
]

OUTPUT_CSV = PROJECT_ROOT / "data" / "bronze" / "packets.csv"

# Windows path - use raw string
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ip.ttl",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.len",
    "tcp.flags",
    "tcp.window_size",
    "tcp.seq",
    "tcp.ack",
    "tcp.options.mss_val",
    "tcp.options.sack_perm",
    "udp.srcport",
    "udp.dstport"
]


def find_pcaps():
    pcaps = []
    for d in RAW_DIRS:
        if d.exists():
            pcaps.extend(d.glob("*.pcap"))
    return sorted(pcaps)


def verify_tshark():
    """Test if tshark works"""
    try:
        result = subprocess.run(
            [TSHARK_PATH, "-v"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print(f"✓ tshark found: {TSHARK_PATH}")
            return True
    except FileNotFoundError:
        print(f"✗ tshark NOT found at: {TSHARK_PATH}")
        print("\nTry these paths:")
        print("  1. C:\\Program Files\\Wireshark\\tshark.exe")
        print("  2. C:\\Program Files (x86)\\Wireshark\\tshark.exe")
        return False
    except Exception as e:
        print(f"✗ Error testing tshark: {e}")
        return False


def run_tshark(pcap, output_csv):
    """Run tshark on single PCAP"""
    
    # Build command - NO shell=True
    cmd = [TSHARK_PATH]
    cmd.extend(["-r", str(pcap)])
    cmd.extend(["-T", "fields"])
    cmd.extend(["-E", "header=y"])
    cmd.extend(["-E", "separator=,"])
    
    for field in TSHARK_FIELDS:
        cmd.extend(["-e", field])
    
    # Run and capture output
    try:
        with open(output_csv, "w", encoding="utf-8") as f:
            result = subprocess.run(
                cmd,
                stdout=f,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
        return True
    
    except subprocess.CalledProcessError as e:
        print(f"  ✗ tshark error: {e.stderr}")
        return False
    
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False


def main():
    # Verify tshark exists
    if not verify_tshark():
        sys.exit(1)
    
    print()
    
    # Find PCAPs
    pcaps = find_pcaps()
    
    if not pcaps:
        print("No PCAP files found in:")
        for d in RAW_DIRS:
            print(f"  {d}")
        return
    
    print(f"Found {len(pcaps)} PCAP files")
    print("="*70)
    
    temp_files = []
    success = 0
    failed = 0
    
    for i, pcap in enumerate(pcaps, 1):
        print(f"[{i}/{len(pcaps)}] {pcap.name[:50]}...")
        
        temp_csv = pcap.with_suffix(".csv")
        
        if run_tshark(pcap, temp_csv):
            temp_files.append(temp_csv)
            success += 1
            print(f"  ✓ Done")
        else:
            failed += 1
            print(f"  ✗ Failed")
    
    print("="*70)
    
    if not temp_files:
        print("No files parsed successfully")
        return
    
    print(f"Success: {success}, Failed: {failed}")
    print("\nMerging CSVs...")
    
    # Merge all CSVs
    dfs = []
    for f in temp_files:
        try:
            df = pd.read_csv(f)
            dfs.append(df)
        except Exception as e:
            print(f"Error reading {f}: {e}")
    
    if not dfs:
        print("No data to merge")
        return
    
    df_final = pd.concat(dfs, ignore_index=True)
    
    # Save
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    df_final.to_csv(OUTPUT_CSV, index=False)
    
    print(f"\n✓ Saved to: {OUTPUT_CSV}")
    print(f"  Rows: {len(df_final):,}")
    print(f"  Size: {OUTPUT_CSV.stat().st_size / (1024*1024):.1f} MB")
    
    # Cleanup temp CSVs
    print("\nCleaning up temp files...")
    for f in temp_files:
        try:
            f.unlink()
        except:
            pass


if __name__ == "__main__":
    main()