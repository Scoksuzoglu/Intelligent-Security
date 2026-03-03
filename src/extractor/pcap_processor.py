# src/extractor/pcap_processor.py

"""
PCAP Processor - Network traffic file processor
Converts PCAP files to CSV using NTFlowLyzer

Author: Veysel Kan
"""

import subprocess
from pathlib import Path
import sys
sys.path.append('.')
from src.utils.logger import log_system

class PCAPProcessor:
    """
    Process PCAP files and extract features using NTFlowLyzer.
    
    Flow:
    PCAP file → NTFlowLyzer → CSV (122 features) → Preprocessor
    """
    
    def __init__(self, ntflowlyzer_path=None):
        """
        Initialize PCAP processor.
        
        Args:
            ntflowlyzer_path (str): Path to NTFlowLyzer executable
        """
        self.ntflowlyzer_path = ntflowlyzer_path or "ntflowlyzer"
        log_system("PCAPProcessor initialized", 'info')
        print(f"✅ PCAPProcessor initialized")
    
    def process_pcap(self, pcap_file, output_csv=None):
        """
        Process PCAP file with NTFlowLyzer.
        
        Args:
            pcap_file (str): Path to PCAP file
            output_csv (str): Output CSV path (optional)
        
        Returns:
            str: Path to output CSV
        """
        pcap_path = Path(pcap_file)
        
        # Check if PCAP exists
        if not pcap_path.exists():
            error_msg = f"PCAP file not found: {pcap_file}"
            log_system(error_msg, 'error')
            raise FileNotFoundError(error_msg)
        
        # Generate output path
        if output_csv is None:
            output_csv = pcap_path.with_suffix('.csv')
        
        output_path = Path(output_csv)
        
        log_system(f"Processing PCAP: {pcap_file}", 'info')
        
        print(f"\n🔄 Processing PCAP with NTFlowLyzer...")
        print(f"  Input: {pcap_file}")
        print(f"  Output: {output_csv}")
        
        # TODO: NTFlowLyzer integration
        # For now, just create a dummy CSV for testing
        print(f"\n⚠️  NTFlowLyzer not integrated yet!")
        print(f"  This is a placeholder for testing")
        
        log_system(f"PCAP processing complete: {output_csv}", 'info')
        
        return str(output_path)
    
    def process_directory(self, pcap_dir, output_dir=None):
        """
        Process all PCAP files in a directory.
        
        Args:
            pcap_dir (str): Directory containing PCAP files
            output_dir (str): Output directory for CSV files
        
        Returns:
            list: List of output CSV paths
        """
        pcap_path = Path(pcap_dir)
        
        if not pcap_path.exists():
            error_msg = f"Directory not found: {pcap_dir}"
            log_system(error_msg, 'error')
            raise FileNotFoundError(error_msg)
        
        # Find all PCAP files
        pcap_files = list(pcap_path.glob("*.pcap")) + list(pcap_path.glob("*.pcapng"))
        
        if not pcap_files:
            print(f"⚠️  No PCAP files found in {pcap_dir}")
            return []
        
        print(f"\n📂 Found {len(pcap_files)} PCAP files")
        
        output_csvs = []
        
        for pcap_file in pcap_files:
            print(f"\nProcessing: {pcap_file.name}")
            
            if output_dir:
                output_csv = Path(output_dir) / pcap_file.with_suffix('.csv').name
            else:
                output_csv = pcap_file.with_suffix('.csv')
            
            try:
                result = self.process_pcap(str(pcap_file), str(output_csv))
                output_csvs.append(result)
                print(f"✅ Done: {output_csv}")
            except Exception as e:
                print(f"❌ Error processing {pcap_file.name}: {e}")
                log_system(f"Error processing {pcap_file}: {e}", 'error')
        
        return output_csvs


# Test function
if __name__ == "__main__":
    print("\n🧪 Testing PCAPProcessor...")
    
    try:
        # Initialize processor
        processor = PCAPProcessor()
        
        print("\n✅ PCAPProcessor class created successfully!")
        print("\n📝 Next steps:")
        print("  1. Install NTFlowLyzer")
        print("  2. Get a test PCAP file")
        print("  3. Integrate NTFlowLyzer command")
        print("  4. Test with real PCAP")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()