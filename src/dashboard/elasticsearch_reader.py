# src/dashboard/elasticsearch_reader.py
# Ahmet Berk Öz - Frontend Developer
# Elasticsearch'ten tahmin verisi çeker

import pandas as pd
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta

ES_HOST = 'http://localhost:9200'
ES_INDEX = 'intsec-predictions'


def _get_client():
    return Elasticsearch([ES_HOST])


def is_connected():
    """Elasticsearch bağlantısını kontrol eder."""
    try:
        return _get_client().ping()
    except Exception:
        return False


def fetch_predictions(limit=500):
    """
    Elasticsearch'ten en son tahminleri çeker.

    Returns:
        pd.DataFrame: Kolonlar — timestamp, source_ip, destination_ip,
                      src_port, dst_port, attack_type, confidence, csv_source
        None: Bağlantı hatası durumunda
    """
    try:
        es = _get_client()
        result = es.search(
            index=ES_INDEX,
            size=limit,
            sort=[{'@timestamp': {'order': 'desc'}}],
            body={'query': {'match_all': {}}}
        )
        hits = result['hits']['hits']
        if not hits:
            return pd.DataFrame()

        data = [hit['_source'] for hit in hits]
        df = pd.DataFrame(data)

        # Kolon isimlerini app.py formatına uyarla
        rename_map = {
            'source_ip':      'Source IP',
            'destination_ip': 'Dest IP',
            'src_port':       'Src Port',
            'dst_port':       'Dst Port',
            '@timestamp':     'Timestamp',
            'attack_type':    'Attack Type',
            'confidence':     'Confidence',
            'csv_source':     'Kaynak'
        }
        df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})

        # Timestamp'i okunabilir formata çevir
        if 'Timestamp' in df.columns:
            df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')

        if 'Confidence' in df.columns:
            df['Confidence'] = df['Confidence'].round(3)

        return df

    except Exception as e:
        print(f"[elasticsearch_reader] Hata: {e}")
        return None


def fetch_last_n_minutes(minutes=60, limit=1000):
    """
    Son N dakikadaki tahminleri çeker. Dashboard için.
    """
    try:
        es = _get_client()
        since = (datetime.utcnow() - timedelta(minutes=minutes)).strftime('%Y-%m-%dT%H:%M:%S.000Z')

        result = es.search(
            index=ES_INDEX,
            size=limit,
            sort=[{'@timestamp': {'order': 'desc'}}],
            body={
                'query': {
                    'range': {
                        '@timestamp': {'gte': since}
                    }
                }
            }
        )
        hits = result['hits']['hits']
        if not hits:
            return pd.DataFrame()

        data = [hit['_source'] for hit in hits]
        df = pd.DataFrame(data)

        rename_map = {
            'source_ip':      'Source IP',
            'destination_ip': 'Dest IP',
            'src_port':       'Src Port',
            'dst_port':       'Dst Port',
            '@timestamp':     'Timestamp',
            'attack_type':    'Attack Type',
            'confidence':     'Confidence',
            'csv_source':     'Kaynak'
        }
        df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})

        if 'Timestamp' in df.columns:
            df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        if 'Confidence' in df.columns:
            df['Confidence'] = df['Confidence'].round(3)

        return df

    except Exception as e:
        print(f"[elasticsearch_reader] Hata: {e}")
        return None


def get_attack_summary():
    """
    Tüm index üzerinden saldırı tipi sayılarını döner.
    Returns: dict {attack_type: count}
    """
    try:
        es = _get_client()
        result = es.search(
            index=ES_INDEX,
            size=0,
            body={
                'aggs': {
                    'by_attack': {
                        'terms': {'field': 'attack_type.keyword', 'size': 20}
                    }
                }
            }
        )
        buckets = result['aggregations']['by_attack']['buckets']
        return {b['key']: b['doc_count'] for b in buckets}
    except Exception as e:
        print(f"[elasticsearch_reader] Özet hatası: {e}")
        return {}


def get_total_count():
    """Toplam kayıt sayısını döner."""
    try:
        es = _get_client()
        result = es.count(index=ES_INDEX)
        return result['count']
    except Exception:
        return 0
