#!/usr/bin/env python3
import subprocess, json, time, os, sys
import pandas as pd
import numpy as np
import joblib
from datetime import datetime
from elasticsearch import Elasticsearch

# --- Konfigürasyon ---
ES_HOST       = "http://192.168.1.16:9200"
ES_INDEX      = "intsec-predictions"
MODEL_DIR     = "/home/intsec/models/multiclass_v1"
INTERFACE     = "enp0s3"
PCAP_PATH     = "/tmp/capture.pcap"
CSV_PATH      = "/tmp/capture.csv"
NTL_CONFIG    = "/home/intsec/ntl_config.json"
PACKET_COUNT  = 100          # Her turda yakalanacak paket sayısı

# --- Model yükle ---
print("[*] Model yukleniyor...")
model    = joblib.load(f"{MODEL_DIR}/model.joblib")
scaler   = joblib.load(f"{MODEL_DIR}/scaler.joblib")
with open(f"{MODEL_DIR}/feature_names.json") as f:
    features = json.load(f)
with open(f"{MODEL_DIR}/metadata.json") as f:
    metadata = json.load(f)
classes = metadata["class_names"]
es = Elasticsearch([ES_HOST])
print("[*] Hazir. Trafik izleniyor...\n")

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
        "number_of_threads": 4
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
        import glob
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

    df["bwd_avg_segment_size"] = df.get("bwd_avg_segment_size", 0)
    X = df[features].fillna(0).replace([np.inf, -np.inf], 0)
    X_scaled = scaler.transform(X)
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
        # Temizle
        import glob as _glob
        for p in set([PCAP_PATH, CSV_PATH] + _glob.glob("/tmp/*.csv")):
            if os.path.exists(p):
                os.remove(p)
        print()
    except KeyboardInterrupt:
        print("\n[*] Durduruluyor...")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Hata: {e}")
        time.sleep(5)
