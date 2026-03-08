# src/extractor/simple_pcap_reader.py

"""
Simple PCAP to CSV converter using Scapy
No Npcap required!
"""

from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
from pathlib import Path
import sys

def pcap_to_csv(pcap_file, output_csv):
    """
    Convert PCAP to CSV with basic features.
    
    Args:
        pcap_file: Path to PCAP file
        output_csv: Path to output CSV
    """
    print(f"\n📂 Reading PCAP: {pcap_file}")
    
    try:
        # Read PCAP
        packets = rdpcap(pcap_file)
        print(f"✅ Loaded {len(packets)} packets")
        
        # Extract features
        data = []
        
        for i, pkt in enumerate(packets):
            if IP in pkt:
                row = {
                    'packet_id': i,
                    'src_ip': pkt[IP].src,
                    'dst_ip': pkt[IP].dst,
                    'protocol': pkt[IP].proto,
                    'packet_length': len(pkt),
                    'ttl': pkt[IP].ttl,
                }
                
                # TCP features
                if TCP in pkt:
                    row['src_port'] = pkt[TCP].sport
                    row['dst_port'] = pkt[TCP].dport
                    row['tcp_flags'] = pkt[TCP].flags
                    row['transport_protocol'] = 'TCP'
                
                # UDP features
                elif UDP in pkt:
                    row['src_port'] = pkt[UDP].sport
                    row['dst_port'] = pkt[UDP].dport
                    row['tcp_flags'] = 0
                    row['transport_protocol'] = 'UDP'
                
                else:
                    row['src_port'] = 0
                    row['dst_port'] = 0
                    row['tcp_flags'] = 0
                    row['transport_protocol'] = 'OTHER'
                
                data.append(row)
        
        # Create DataFrame
        df = pd.DataFrame(data)
        
        print(f"\n📊 Extracted features:")
        print(f"  Packets: {len(df)}")
        print(f"  Columns: {list(df.columns)}")
        
        # Save to CSV
        df.to_csv(output_csv, index=False)
        print(f"\n✅ CSV saved: {output_csv}")
        
        return output_csv
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return None


# Test
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUsage: python simple_pcap_reader.py <pcap_file> [output_csv]")
        print("\nExample:")
        print("  python simple_pcap_reader.py test.pcap output.csv")
    else:
        pcap_file = sys.argv[1]
        output_csv = sys.argv[2] if len(sys.argv) > 2 else "output.csv"
        
        pcap_to_csv(pcap_file, output_csv)
