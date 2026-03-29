# src/watcher/file_watcher.py
# Semih İkbal - Backend Developer
# data/pcap/ klasörünü izler, yeni .pcap geldiğinde pipeline'ı otomatik tetikler

import sys
import time
import threading
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.append('.')

from src.extractor.pcap_processor import PCAPProcessor
from src.inference.preprocessor import DataPreprocessor
from src.inference.predict import ModelPredictor
from src.utils.logger import log_system, log_prediction
from elasticsearch import Elasticsearch
from datetime import datetime


PCAP_DIR = 'data/pcap'
PROCESSED_DIR = 'data/processed'
ES_INDEX = 'intsec-predictions'
ES_HOST = 'http://localhost:9200'


def run_pipeline(pcap_path: str):
    """
    Tek bir PCAP dosyası için tam pipeline'ı çalıştırır.
    PCAP → NTFlowLyzer → Preprocessing → Model → Elasticsearch
    """
    pcap_file = Path(pcap_path)
    output_csv = Path(PROCESSED_DIR) / f"{pcap_file.stem}_flow.csv"

    log_system(f"Pipeline başlatıldı: {pcap_file.name}", 'info')
    print(f"\n{'='*60}")
    print(f"🚀 Yeni PCAP tespit edildi: {pcap_file.name}")
    print(f"{'='*60}")

    try:
        # 1. PCAP → CSV
        print(f"\n📂 ADIM 1: PCAP işleniyor...")
        processor = PCAPProcessor()
        processor.process_pcap(str(pcap_file), str(output_csv))
        log_system(f"PCAP işlendi: {output_csv}", 'info')

        # 2. CSV → Temiz features
        print(f"\n🔄 ADIM 2: Preprocessing...")
        preprocessor = DataPreprocessor()
        features, metadata = preprocessor.process_csv(str(output_csv))
        log_system(f"Features hazırlandı: {features.shape}", 'info')

        # 3. Model tahmini
        print(f"\n🔮 ADIM 3: Model tahmini yapılıyor...")
        predictor = ModelPredictor()
        results = predictor.predict(features)
        log_system(f"Tahmin tamamlandı: {len(results['attack_types'])} flow", 'info')

        # 4. Loglama + Elasticsearch
        print(f"\n📝 ADIM 4: Sonuçlar kaydediliyor...")
        _save_results(results, metadata, pcap_file.name)

        # 5. Özet
        _print_summary(results, pcap_file.name)

    except Exception as e:
        log_system(f"Pipeline hatası ({pcap_file.name}): {e}", 'error')
        print(f"\n❌ Hata: {e}")


def _save_results(results, metadata, source_name):
    """Tahminleri loglar ve Elasticsearch'e yazar."""
    es = None
    try:
        es = Elasticsearch([ES_HOST])
        if not es.ping():
            log_system("Elasticsearch'e bağlanılamadı, sadece log yazılıyor.", 'warning')
            es = None
    except Exception:
        log_system("Elasticsearch bağlantısı kurulamadı.", 'warning')

    for i, (attack_type, confidence) in enumerate(
        zip(results['attack_types'], results['confidence'])
    ):
        src_ip = 'unknown'
        dst_ip = 'unknown'
        src_port = 0
        dst_port = 0

        if metadata is not None and i < len(metadata):
            row = metadata.iloc[i]
            src_ip = str(row.get('src_ip', 'unknown'))
            dst_ip = str(row.get('dst_ip', 'unknown'))
            src_port = int(row.get('src_port', 0)) if 'src_port' in row else 0
            dst_port = int(row.get('dst_port', 0)) if 'dst_port' in row else 0

        # Log dosyasına yaz
        log_prediction(
            src_ip=src_ip,
            dst_ip=dst_ip,
            attack_type=attack_type,
            confidence=confidence
        )

        # Elasticsearch'e yaz
        if es is not None:
            doc = {
                'timestamp': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'attack_type': attack_type,
                'confidence': float(confidence),
                'csv_source': source_name
            }
            try:
                es.index(index=ES_INDEX, document=doc)
            except Exception as e:
                log_system(f"ES yazma hatası: {e}", 'warning')

    if es is not None:
        print(f"✅ {len(results['attack_types'])} kayıt Elasticsearch'e yazıldı.")


def _print_summary(results, filename):
    """Pipeline sonuç özetini ekrana basar."""
    import pandas as pd
    attack_counts = pd.Series(results['attack_types']).value_counts()
    total = len(results['attack_types'])
    avg_conf = sum(results['confidence']) / total if total > 0 else 0

    print(f"\n{'='*60}")
    print(f"✅ Pipeline tamamlandı: {filename}")
    print(f"{'='*60}")
    print(f"  Toplam Flow : {total}")
    for attack, count in attack_counts.items():
        icon = "🔴" if attack != 'Benign' else "🟢"
        print(f"  {icon} {attack}: {count}")
    print(f"  Ort. Güven  : {avg_conf:.4f}")
    print(f"{'='*60}\n")


class PCAPHandler(FileSystemEventHandler):
    """
    data/pcap/ klasöründe yeni .pcap dosyası oluşturulduğunda tetiklenir.
    Büyük dosyaların tamamen yazılmasını beklemek için küçük bir gecikme ekler.
    """

    def __init__(self):
        self._processing = set()
        self._lock = threading.Lock()

    def on_created(self, event):
        if event.is_directory:
            return
        if not event.src_path.endswith('.pcap'):
            return

        path = event.src_path
        with self._lock:
            if path in self._processing:
                return
            self._processing.add(path)

        # Dosyanın tamamen yazılmasını bekle
        thread = threading.Thread(target=self._delayed_process, args=(path,), daemon=True)
        thread.start()

    def _delayed_process(self, path):
        time.sleep(2)
        try:
            run_pipeline(path)
        finally:
            with self._lock:
                self._processing.discard(path)


def start_watcher(watch_dir=PCAP_DIR):
    """File watcher'ı başlatır ve CTRL+C ile durdurana kadar çalıştırır."""
    watch_path = Path(watch_dir)
    watch_path.mkdir(parents=True, exist_ok=True)
    Path(PROCESSED_DIR).mkdir(parents=True, exist_ok=True)

    handler = PCAPHandler()
    observer = Observer()
    observer.schedule(handler, str(watch_path), recursive=False)
    observer.start()

    print(f"\n{'='*60}")
    print(f"👁  INTSEC File Watcher başlatıldı")
    print(f"   İzlenen klasör : {watch_path.resolve()}")
    print(f"   Elasticsearch  : {ES_HOST}")
    print(f"   Durdurmak için : CTRL+C")
    print(f"{'='*60}\n")

    log_system(f"File watcher başlatıldı: {watch_path.resolve()}", 'info')

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 File watcher durduruluyor...")
        observer.stop()
        log_system("File watcher durduruldu.", 'info')

    observer.join()
    print("✅ File watcher durduruldu.")


if __name__ == '__main__':
    start_watcher()
