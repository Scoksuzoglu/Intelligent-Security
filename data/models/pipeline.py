#!/usr/bin/env python3
import subprocess, json, time, os, sys, glob
import pandas as pd
import numpy as np
import joblib
from datetime import datetime
from elasticsearch import Elasticsearch

# --- Konfigürasyon ---
ES_HOST       = "http://192.168.1.16:9200"   # Her oturumda Windows IP'sini kontrol et!
ES_INDEX      = "intsec-predictions"
MODEL_DIR     = "/home/intsec/models/multiclass_v4"
INTERFACE     = "enp0s3"
PCAP_PATH     = "/tmp/capture.pcap"
CSV_PATH      = "/tmp/capture.csv"
NTL_CONFIG    = "/home/intsec/ntl_config.json"
PACKET_COUNT  = 200          # Her turda yakalanacak paket sayısı

# NTLFlowLyzer'ın çıkarmasına gerek olmayan feature'lar (sadece 30 feature kalsın → daha hızlı)
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
    'fwd_std_header_bytes', 'fwd_median_header_bytes',
    'fwd_skewness_header_bytes', 'fwd_cov_header_bytes', 'fwd_mode_header_bytes', 'fwd_variance_header_bytes',
    'bwd_total_header_bytes', 'bwd_max_header_bytes', 'bwd_min_header_bytes',
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
    'packet_IAT_std', 'packets_IAT_median', 'packets_IAT_skewness',
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

# --- Model yükle ---
print("[*] Model yukleniyor (multiclass_v4)...")
model    = joblib.load(f"{MODEL_DIR}/model4.joblib")
scaler   = joblib.load(f"{MODEL_DIR}/scaler4.joblib")
with open(f"{MODEL_DIR}/feature_names4.json") as f:
    features = json.load(f)
with open(f"{MODEL_DIR}/metadata4.json") as f:
    metadata = json.load(f)
classes = metadata["class_names"]
es = Elasticsearch([ES_HOST])
print(f"[*] Model hazir. Siniflar: {list(classes.values())}")
print("[*] Trafik izleniyor...\n")


def capture(interface, pcap_path, count):
    print(f"[+] tcpdump basliyor ({count} paket)...")
    subprocess.run(
        ["sudo", "tcpdump", "-i", interface, "-w", pcap_path, "-c", str(count)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    print("[+] Yakalama tamamlandi.")


def extract(pcap_path, csv_path, config_path):
    print("[+] NTLFlowLyzer calistiriliyor...")
    config = {
        "pcap_file_address": pcap_path,
        "output_file_address": csv_path,
        "number_of_threads": 4,
        "features_ignore_list": FEATURES_IGNORE_LIST
    }
    with open(config_path, "w") as f:
        json.dump(config, f)
    result = subprocess.run(
        ["/home/intsec/.local/bin/ntlflowlyzer", "-c", config_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[-] NTLFlowLyzer hata: {result.stderr[:300]}")

    # NTLFlowLyzer bazen bosluklu isim olusturuyor
    if not os.path.exists(csv_path):
        found = glob.glob("/tmp/*.csv")
        if found:
            print(f"[!] CSV farkli isimde bulundu: {found[0]}")
            os.rename(found[0], csv_path)
        else:
            print("[-] Hicbir CSV bulunamadi /tmp icinde.")
    print("[+] Feature extraction tamamlandi.")


def predict_and_write(csv_path):
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"[-] CSV okunamadi: {e}")
        return

    if df.empty:
        print("[-] CSV bos, atlaniyor.")
        return

    # NTLFlowLyzer kolon adi farkliligi duzelt
    df = df.rename(columns={"bwd_segment_size_mean": "bwd_avg_segment_size"})

    # Eksik feature varsa 0 ile doldur
    for feat in features:
        if feat not in df.columns:
            df[feat] = 0

    X = df[features].fillna(0).replace([np.inf, -np.inf], 0)
    X_scaled   = scaler.transform(X)
    preds      = model.predict(X_scaled)
    probs      = model.predict_proba(X_scaled)
    confidence = probs.max(axis=1)

    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    for i, (_, row) in enumerate(df.iterrows()):
        doc = {
            "@timestamp":     ts,
            "source_ip":      str(row.get("src_ip", "unknown")),
            "destination_ip": str(row.get("dst_ip", "unknown")),
            "src_port":       int(row.get("src_port", 0)),
            "dst_port":       int(row.get("dst_port", 0)),
            "attack_type":    classes[str(preds[i])],
            "confidence":     float(confidence[i]),
            "csv_source":     "realtime"
        }
        es.index(index=ES_INDEX, document=doc)

    counts = {}
    for p in preds:
        label = classes[str(p)]
        counts[label] = counts.get(label, 0) + 1
    print(f"[+] {len(df)} kayit ES'e yazildi: {counts}")


# --- Ana dongu ---
while True:
    try:
        capture(INTERFACE, PCAP_PATH, PACKET_COUNT)
        extract(PCAP_PATH, CSV_PATH, NTL_CONFIG)
        predict_and_write(CSV_PATH)
        # Gecici dosyalari temizle
        for p in set([PCAP_PATH, CSV_PATH] + glob.glob("/tmp/*.csv")):
            if os.path.exists(p):
                os.remove(p)
        print()
    except KeyboardInterrupt:
        print("\n[*] Durduruluyor...")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Hata: {e}")
        time.sleep(5)
