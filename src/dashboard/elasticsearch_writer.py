from elasticsearch import Elasticsearch
import pandas as pd
import numpy as np
import joblib
import json
from datetime import datetime

# Elasticsearch bağlantısı
es = Elasticsearch(['http://localhost:9200'])

# Model yükle
def load_model():
    model = joblib.load('data/models/multiclass_v2/model.joblib')
    scaler = joblib.load('data/models/multiclass_v2/scaler.joblib')
    with open('data/models/multiclass_v2/feature_names.json') as f:
        features = json.load(f)
    with open('data/models/multiclass_v2/metadata.json') as f:
        metadata = json.load(f)
    return model, scaler, features, metadata

def predict_and_index(csv_file, n_samples=500):
    model, scaler, features, metadata = load_model()
    classes = metadata['class_names']
    
    print(f"[*] {csv_file} okunuyor...")
    df = pd.read_csv(f'data/processed/{csv_file}')
    df = df.rename(columns={'bwd_segment_size_mean': 'bwd_avg_segment_size'})
    df = df.sample(min(n_samples, len(df)), random_state=42)

    X = df[features].fillna(0).replace([np.inf, -np.inf], 0)
    X_scaled = scaler.transform(X)
    
    preds = model.predict(X_scaled)
    probs = model.predict_proba(X_scaled)
    confidence = probs.max(axis=1)
    
    print(f"[+] Tahminler yapildi, Elasticsearch'e yaziliyor...")
    
    for i, (_, row) in enumerate(df.iterrows()):
        doc = {
            '@timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'source_ip': str(row.get('src_ip', 'unknown')),
            'destination_ip': str(row.get('dst_ip', 'unknown')),
            'src_port': int(row.get('src_port', 0)),
            'dst_port': int(row.get('dst_port', 0)),
            'attack_type': classes[str(preds[i])],
            'confidence': float(confidence[i]),
            'csv_source': csv_file
        }
        es.index(index='intsec-predictions', document=doc)
    
    print(f"[+] {len(df)} kayit Elasticsearch'e yazildi!")

if __name__ == "__main__":
    csv_files = [
        'ddos_flows.csv',
    ]
    for csv in csv_files:
        predict_and_index(csv, n_samples=500)