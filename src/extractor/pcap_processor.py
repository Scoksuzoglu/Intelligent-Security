# src/extractor/pcap_processor.py

"""
PCAP Processor - Network traffic file processor
Converts PCAP files to CSV using NTFlowLyzer

Author: Veysel Kan
"""

import os
import json
import subprocess
from pathlib import Path
import sys
sys.path.append('.')
from src.utils.logger import log_system


# NTFlowLyzer features_ignore_list
# 30 feature + 7 metadata disindaki tum kolonlar cikarilir
FEATURES_IGNORE_LIST = [
    'packets_count', 'fwd_packets_count', 'bwd_packets_count',
    'total_payload_bytes', 'fwd_total_payload_bytes', 'bwd_total_payload_bytes',
    'payload_bytes_min', 'payload_bytes_mean', 'payload_bytes_std',
    'payload_bytes_median', 'payload_bytes_skewness', 'payload_bytes_cov', 'payload_bytes_mode',
    'fwd_payload_bytes_max', 'fwd_payload_bytes_min', 'fwd_payload_bytes_mean',
    'fwd_payload_bytes_variance', 'fwd_payload_bytes_median', 'fwd_payload_bytes_skewness',
    'fwd_payload_bytes_cov', 'fwd_payload_bytes_mode',
    'bwd_payload_bytes_max', 'bwd_payload_bytes_min', 'bwd_payload_bytes_std',
    'bwd_payload_bytes_median', 'bwd_payload_bytes_skewness', 'bwd_payload_bytes_cov', 'bwd_payload_bytes_mode',
    'total_header_bytes', 'std_header_bytes', 'median_header_bytes', 'skewness_header_bytes',
    'cov_header_bytes', 'mode_header_bytes', 'variance_header_bytes',
    'fwd_total_header_bytes', 'fwd_max_header_bytes', 'fwd_std_header_bytes', 'fwd_median_header_bytes',
    'fwd_skewness_header_bytes', 'fwd_cov_header_bytes', 'fwd_mode_header_bytes', 'fwd_variance_header_bytes',
    'bwd_total_header_bytes', 'bwd_max_header_bytes', 'bwd_min_header_bytes', 'bwd_mean_header_bytes',
    'bwd_std_header_bytes', 'bwd_median_header_bytes', 'bwd_skewness_header_bytes',
    'bwd_cov_header_bytes', 'bwd_mode_header_bytes', 'bwd_variance_header_bytes',
    'fwd_segment_size_mean', 'fwd_segment_size_max', 'fwd_segment_size_min', 'fwd_segment_size_std',
    'fwd_segment_size_variance', 'fwd_segment_size_median', 'fwd_segment_size_skewness',
    'fwd_segment_size_cov', 'fwd_segment_size_mode',
    'bwd_segment_size_max', 'bwd_segment_size_min', 'bwd_segment_size_std', 'bwd_segment_size_variance',
    'bwd_segment_size_median', 'bwd_segment_size_skewness', 'bwd_segment_size_cov', 'bwd_segment_size_mode',
    'segment_size_mean', 'segment_size_max', 'segment_size_min', 'segment_size_std',
    'segment_size_variance', 'segment_size_median', 'segment_size_skewness', 'segment_size_cov', 'segment_size_mode',
    'bwd_init_win_bytes',
    'active_min', 'active_max', 'active_mean', 'active_std', 'active_median',
    'active_skewness', 'active_cov', 'active_mode', 'active_variance',
    'idle_min', 'idle_max', 'idle_mean', 'idle_std', 'idle_median',
    'idle_skewness', 'idle_cov', 'idle_mode', 'idle_variance',
    'bytes_rate', 'fwd_bytes_rate', 'bwd_bytes_rate', 'down_up_rate',
    'avg_fwd_bytes_per_bulk', 'avg_fwd_packets_per_bulk', 'avg_fwd_bulk_rate',
    'avg_bwd_bytes_per_bulk', 'avg_bwd_packets_bulk_rate', 'avg_bwd_bulk_rate',
    'fwd_bulk_state_count', 'fwd_bulk_total_size', 'fwd_bulk_per_packet', 'fwd_bulk_duration',
    'bwd_bulk_state_count', 'bwd_bulk_total_size', 'bwd_bulk_per_packet', 'bwd_bulk_duration',
    'fin_flag_counts', 'psh_flag_counts', 'urg_flag_counts', 'ece_flag_counts',
    'syn_flag_counts', 'ack_flag_counts', 'cwr_flag_counts',
    'fwd_fin_flag_counts', 'fwd_psh_flag_counts', 'fwd_urg_flag_counts', 'fwd_ece_flag_counts',
    'fwd_syn_flag_counts', 'fwd_ack_flag_counts', 'fwd_cwr_flag_counts', 'fwd_rst_flag_counts',
    'bwd_fin_flag_counts', 'bwd_psh_flag_counts', 'bwd_urg_flag_counts', 'bwd_ece_flag_counts',
    'bwd_syn_flag_counts', 'bwd_ack_flag_counts', 'bwd_cwr_flag_counts', 'bwd_rst_flag_counts',
    'fin_flag_percentage_in_total', 'psh_flag_percentage_in_total', 'urg_flag_percentage_in_total',
    'ece_flag_percentage_in_total', 'syn_flag_percentage_in_total', 'ack_flag_percentage_in_total',
    'cwr_flag_percentage_in_total', 'rst_flag_percentage_in_total',
    'fwd_fin_flag_percentage_in_total', 'fwd_psh_flag_percentage_in_total', 'fwd_urg_flag_percentage_in_total',
    'fwd_ece_flag_percentage_in_total', 'fwd_syn_flag_percentage_in_total', 'fwd_ack_flag_percentage_in_total',
    'fwd_cwr_flag_percentage_in_total', 'fwd_rst_flag_percentage_in_total',
    'bwd_fin_flag_percentage_in_total', 'bwd_psh_flag_percentage_in_total', 'bwd_urg_flag_percentage_in_total',
    'bwd_ece_flag_percentage_in_total', 'bwd_syn_flag_percentage_in_total', 'bwd_ack_flag_percentage_in_total',
    'bwd_cwr_flag_percentage_in_total', 'bwd_rst_flag_percentage_in_total',
    'fwd_fin_flag_percentage_in_fwd_packets', 'fwd_psh_flag_percentage_in_fwd_packets',
    'fwd_urg_flag_percentage_in_fwd_packets', 'fwd_ece_flag_percentage_in_fwd_packets',
    'fwd_syn_flag_percentage_in_fwd_packets', 'fwd_ack_flag_percentage_in_fwd_packets',
    'fwd_cwr_flag_percentage_in_fwd_packets', 'fwd_rst_flag_percentage_in_fwd_packets',
    'bwd_fin_flag_percentage_in_bwd_packets', 'bwd_psh_flag_percentage_in_bwd_packets',
    'bwd_urg_flag_percentage_in_bwd_packets', 'bwd_ece_flag_percentage_in_bwd_packets',
    'bwd_syn_flag_percentage_in_bwd_packets', 'bwd_ack_flag_percentage_in_bwd_packets',
    'bwd_cwr_flag_percentage_in_bwd_packets', 'bwd_rst_flag_percentage_in_bwd_packets',
    'packet_IAT_std', 'packet_IAT_max', 'packets_IAT_median', 'packets_IAT_skewness',
    'packets_IAT_cov', 'packets_IAT_mode', 'packets_IAT_variance',
    'fwd_packets_IAT_std', 'fwd_packets_IAT_median', 'fwd_packets_IAT_skewness',
    'fwd_packets_IAT_cov', 'fwd_packets_IAT_mode', 'fwd_packets_IAT_variance',
    'bwd_packets_IAT_std', 'bwd_packets_IAT_median', 'bwd_packets_IAT_skewness',
    'bwd_packets_IAT_cov', 'bwd_packets_IAT_mode', 'bwd_packets_IAT_variance',
    'subflow_fwd_packets', 'subflow_bwd_packets', 'subflow_fwd_bytes', 'subflow_bwd_bytes',
    'delta_start', 'handshake_duration', 'handshake_state',
    'min_bwd_packets_delta_time', 'max_bwd_packets_delta_time', 'mean_packets_delta_time',
    'mode_packets_delta_time', 'variance_packets_delta_time', 'std_packets_delta_time',
    'median_packets_delta_time', 'skewness_packets_delta_time', 'cov_packets_delta_time',
    'mean_bwd_packets_delta_time', 'mode_bwd_packets_delta_time', 'variance_bwd_packets_delta_time',
    'std_bwd_packets_delta_time', 'median_bwd_packets_delta_time', 'skewness_bwd_packets_delta_time',
    'cov_bwd_packets_delta_time', 'min_fwd_packets_delta_time', 'max_fwd_packets_delta_time',
    'mean_fwd_packets_delta_time', 'mode_fwd_packets_delta_time', 'variance_fwd_packets_delta_time',
    'std_fwd_packets_delta_time', 'median_fwd_packets_delta_time', 'skewness_fwd_packets_delta_time',
    'cov_fwd_packets_delta_time',
    'min_packets_delta_len', 'max_packets_delta_len', 'mean_packets_delta_len',
    'mode_packets_delta_len', 'variance_packets_delta_len', 'std_packets_delta_len',
    'median_packets_delta_len', 'skewness_packets_delta_len', 'cov_packets_delta_len',
    'min_bwd_packets_delta_len', 'max_bwd_packets_delta_len', 'mean_bwd_packets_delta_len',
    'mode_bwd_packets_delta_len', 'variance_bwd_packets_delta_len', 'std_bwd_packets_delta_len',
    'median_bwd_packets_delta_len', 'skewness_bwd_packets_delta_len', 'cov_bwd_packets_delta_len',
    'min_fwd_packets_delta_len', 'max_fwd_packets_delta_len', 'mean_fwd_packets_delta_len',
    'mode_fwd_packets_delta_len', 'variance_fwd_packets_delta_len', 'std_fwd_packets_delta_len',
    'median_fwd_packets_delta_len', 'skewness_fwd_packets_delta_len', 'cov_fwd_packets_delta_len',
    'min_header_bytes_delta_len', 'max_header_bytes_delta_len', 'mean_header_bytes_delta_len',
    'mode_header_bytes_delta_len', 'variance_header_bytes_delta_len', 'std_header_bytes_delta_len',
    'median_header_bytes_delta_len', 'skewness_header_bytes_delta_len', 'cov_header_bytes_delta_len',
    'min_bwd_header_bytes_delta_len', 'max_bwd_header_bytes_delta_len', 'mean_bwd_header_bytes_delta_len',
    'mode_bwd_header_bytes_delta_len', 'variance_bwd_header_bytes_delta_len', 'std_bwd_header_bytes_delta_len',
    'median_bwd_header_bytes_delta_len', 'skewness_bwd_header_bytes_delta_len', 'cov_bwd_header_bytes_delta_len',
    'min_fwd_header_bytes_delta_len', 'max_fwd_header_bytes_delta_len', 'mean_fwd_header_bytes_delta_len',
    'mode_fwd_header_bytes_delta_len', 'variance_fwd_header_bytes_delta_len', 'std_fwd_header_bytes_delta_len',
    'median_fwd_header_bytes_delta_len', 'skewness_fwd_header_bytes_delta_len', 'cov_fwd_header_bytes_delta_len',
    'min_payload_bytes_delta_len', 'max_payload_bytes_delta_len', 'mean_payload_bytes_delta_len',
    'mode_payload_bytes_delta_len', 'variance_payload_bytes_delta_len', 'std_payload_bytes_delta_len',
    'median_payload_bytes_delta_len', 'skewness_payload_bytes_delta_len', 'cov_payload_bytes_delta_len',
    'min_bwd_payload_bytes_delta_len', 'max_bwd_payload_bytes_delta_len', 'mean_bwd_payload_bytes_delta_len',
    'mode_bwd_payload_bytes_delta_len', 'variance_bwd_payload_bytes_delta_len', 'std_bwd_payload_bytes_delta_len',
    'median_bwd_payload_bytes_delta_len', 'skewness_bwd_payload_bytes_delta_len', 'cov_bwd_payload_bytes_delta_len',
    'min_fwd_payload_bytes_delta_len', 'max_fwd_payload_bytes_delta_len', 'mean_fwd_payload_bytes_delta_len',
    'mode_fwd_payload_bytes_delta_len', 'variance_fwd_payload_bytes_delta_len', 'std_fwd_payload_bytes_delta_len',
    'median_fwd_payload_bytes_delta_len', 'skewness_fwd_payload_bytes_delta_len', 'cov_fwd_payload_bytes_delta_len',
    'label'
]


class PCAPProcessor:
    """
    Process PCAP files and extract features using NTFlowLyzer.

    Flow:
    PCAP file -> NTFlowLyzer (config JSON) -> CSV (30 features + metadata) -> Preprocessor
    """

    def __init__(self):
        log_system("PCAPProcessor initialized", 'info')
        print("PCAPProcessor initialized")

    def _build_config(self, pcap_path: str, output_path: str) -> dict:
        """Build NTFlowLyzer config dict."""
        return {
            "pcap_file_address": pcap_path,
            "output_file_address": output_path,
            "number_of_threads": 4,
            "feature_extractor_min_flows": 5,
            "writer_min_rows": 1,
            "read_packets_count_value_log_info": 1000,
            "check_flows_ending_min_flows": 10,
            "capturer_updating_flows_min_value": 50,
            "max_flow_duration": 10000,
            "activity_timeout": 5,
            "floating_point_unit": ".4f",
            "max_rows_number": 1000000,
            "features_ignore_list": FEATURES_IGNORE_LIST
        }

    def process_pcap(self, pcap_file: str, output_csv: str = None) -> str:
        """
        Process a single PCAP file with NTFlowLyzer.

        Args:
            pcap_file (str): Path to PCAP file
            output_csv (str): Output CSV path (optional)

        Returns:
            str: Path to output CSV
        """
        current_dir = os.getcwd().replace("\\", "/")
        pcap_path = str(Path(pcap_file).resolve()).replace("\\", "/")

        if not Path(pcap_path).exists():
            error_msg = f"PCAP file not found: {pcap_file}"
            log_system(error_msg, 'error')
            raise FileNotFoundError(error_msg)

        if output_csv is None:
            output_csv = f"{current_dir}/output.csv"

        output_path = str(Path(output_csv).resolve()).replace("\\", "/")

        print(f"\nProcessing PCAP with NTFlowLyzer...")
        print(f"  Input : {pcap_path}")
        print(f"  Output: {output_path}")

        log_system(f"Processing PCAP: {pcap_path}", 'info')

        # Write config JSON
        config_data = self._build_config(pcap_path, output_path)
        config_name = f"{current_dir}/run_config.json"

        with open(config_name, 'w') as f:
            json.dump(config_data, f, indent=4)

        print(f"  Config: {config_name}")

        # Run NTFlowLyzer
        try:
            result = subprocess.run(
                ["ntlflowlyzer", "-c", config_name],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode != 0:
                error_msg = f"NTFlowLyzer error: {result.stderr}"
                log_system(error_msg, 'error')
                raise RuntimeError(error_msg)

            print(f"NTFlowLyzer completed!")
            print(f"  Output: {output_path}")
            log_system(f"PCAP processing complete: {output_path}", 'info')

        except subprocess.TimeoutExpired:
            error_msg = "NTFlowLyzer timeout (>5 min)"
            log_system(error_msg, 'error')
            raise RuntimeError(error_msg)

        finally:
            if Path(config_name).exists():
                os.remove(config_name)

        return output_path

    def process_directory(self, pcap_dir: str, output_dir: str = None) -> list:
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

        pcap_files = list(pcap_path.glob("*.pcap")) + list(pcap_path.glob("*.pcapng"))

        if not pcap_files:
            print(f"No PCAP files found in {pcap_dir}")
            return []

        print(f"\nFound {len(pcap_files)} PCAP files")

        output_csvs = []

        for pcap_file in pcap_files:
            print(f"\nProcessing: {pcap_file.name}")

            if output_dir:
                out_csv = str(Path(output_dir) / pcap_file.with_suffix('.csv').name)
            else:
                out_csv = str(pcap_file.with_suffix('.csv'))

            try:
                result = self.process_pcap(str(pcap_file), out_csv)
                output_csvs.append(result)
                print(f"Done: {out_csv}")
            except Exception as e:
                print(f"Error processing {pcap_file.name}: {e}")
                log_system(f"Error processing {pcap_file}: {e}", 'error')

        return output_csvs


# Test
if __name__ == "__main__":
    print("\nTesting PCAPProcessor...")

    try:
        processor = PCAPProcessor()

        current_dir = os.getcwd().replace("\\", "/")
        test_pcap = r"C:\Users\pc\Desktop\test.pcap\capWIN-J6GMIG1DQE5-172.31.65.35"
        output_csv = f"{current_dir}/output_test.csv"

        print(f"\nGirdi Dosyasi: {test_pcap}")
        print(f"Cikti Dosyasi: {output_csv}")

        result = processor.process_pcap(test_pcap, output_csv)

        print(f"\nTest successful!")
        print(f"  Output CSV: {result}")

    except Exception as e:
        print(f"\nTest failed: {e}")
        import traceback
        traceback.print_exc()
