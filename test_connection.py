import json
import time
from kafka import KafkaProducer
from elasticsearch import Elasticsearch

def test_system():
    print("🚀 INTSEC Sistem Testi Başlatılıyor...")

    # 1. KAFKA TESTİ
    try:
        producer = KafkaProducer(
            bootstrap_servers=['localhost:9092'],
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )
        data = {"message": "Merhaba Kafka!", "timestamp": time.time()}
        producer.send('test-topic', value=data)
        producer.flush()
        print("✅ BAŞARILI: Kafka'ya veri gönderildi.")
    except Exception as e:
        print(f"❌ HATA: Kafka bağlantısı başarısız! \n{e}")

    # 2. ELASTICSEARCH TESTİ
    try:
        # Docker'daki Elastic 7.x sürümü genelde şifresiz çalışır
        es = Elasticsearch("http://localhost:9200")
        
        # Basit bir ping atalım
        if es.ping():
            print("✅ BAŞARILI: Elasticsearch ayakta ve cevap veriyor.")
            
            # Test verisi yazalım
            doc = {"author": "Lider", "text": "Elasticsearch testi tamam!", "timestamp": time.time()}
            resp = es.index(index="intsec-test-logs", document=doc)
            print(f"✅ BAŞARILI: Veritabanına log yazıldı. (ID: {resp['_id']})")
        else:
            print("❌ HATA: Elasticsearch 'ping' cevabı vermedi.")
    except Exception as e:
        print(f"❌ HATA: Elasticsearch bağlantısı koptu! \n{e}")

if __name__ == "__main__":
    test_system()