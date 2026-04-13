# INTSEC Proje İlerleme Günlüğü

> Bu dosya Claude ile yapılan çalışmaların kaydıdır.
> Yeni bir session'da bu dosyayı Claude'a atarak kaldığınız yerden devam edebilirsiniz.

---

## Proje Özeti

**Proje:** INTSEC - AI-Enhanced Cyberattack Classifier (INTelligent SECurity)
**Üniversite:** Yaşar Üniversitesi, Bilgisayar Mühendisliği
**Ders:** COMP4910 (Fall 2025) → COMP4920 (Spring 2026)
**Danışman:** Mete Eminağaoğlu
**Amaç:** ML tabanlı gerçek zamanlı NIDS — akış bazlı trafik analizi ile saldırı sınıflandırma
**Saldırı Sınıfları:** Benign, DDoS, DoS, Botnet, Web Attack, Port Scan, Brute Force, Infiltration
**Deadline:** Mayıs 2026
**Ahmet'in rolü:** Frontend Developer (Streamlit dashboard, Elasticsearch okuma, görselleştirme, alarm sistemi)

### Ekip
| İsim | Öğrenci No | Rol |
|------|-----------|-----|
| Semih Cengiz Öksüzoğlu | 22070001005 | Proje Lideri + ML Engineer |
| Semih İkbal | 21070001025 | Backend Developer |
| Veysel Kan | 22070001062 | Network Engineer |
| Ahmet Berk Öz | 21070001050 | Frontend Developer |

---

## Sistem Mimarisi (DSD v2.0'dan)

### Pipeline Akışı
```
Kali VM (Saldırgan)
    ↓ hping3 --flood ile DDoS saldırısı
Ubuntu VM (192.168.1.24)
    → tcpdump -i enp0s3 -w /tmp/ddos_short.pcap -c 50000
    → NTLFlowLyzer: PCAP → CSV (347 feature, model 30 tanesini kullanır)
    → CSV Windows'a aktarılır (HTTP server veya SCP)
    → Preprocessor + ML Model (Random Forest): Sınıflandır
    → Elasticsearch'e yaz
        ↓
Windows Host → Kibana (5601) + Streamlit (8501)
```

### Microservices (DSD'deki hedef mimari)
| Servis | Dosya | Görev |
|--------|-------|-------|
| Ingestor | `ingestor.py` | Scapy ile NIC dinle → Kafka raw-packets topic |
| Extractor | `extractor.py` | Kafka'dan al → NTLFlowLyzer → feature vector |
| Inference | `inference.py` | Feature → ML model → ES'e yaz |
| Storage+Viz | ES + Kibana | Depolama ve görselleştirme |

**Not:** Mevcut implementasyonda Kafka henüz yok. Şu an: PCAP → NTLFlowLyzer → CSV → Model → ES doğrudan yazılıyor.

### Elasticsearch Index Schema (`intsec-predictions`)
| Field | Type | Açıklama |
|-------|------|----------|
| @timestamp | date | Tespit zamanı (dikkat: @ ile başlıyor, `timestamp` değil) |
| source_ip | keyword | Kaynak IP |
| destination_ip | keyword | Hedef IP |
| src_port | integer | Kaynak port |
| dst_port | integer | Hedef port |
| attack_type | keyword | Benign/DoS/DDoS/Botnet/Port Scan/Brute Force |
| confidence | float | Model tahmin olasılığı |
| csv_source | keyword | Hangi CSV/PCAP'ten geldiği |

---

## Tamamlanan İşler

### COMP4910 (Fall 2025) — Tamamlandı
- RSD v1.0 ve v2.0 (UML use case diyagramları ile)
- DSD v1.0 ve v2.0 (microservices mimarisi detaylandı)
- Final Report (02.01.2026)
- CIC-IDS2017 dataset ile feature extraction prototipi test edildi

### FAZ 1 — Core Pipeline
- `model` (RandomForest, 7 sınıf, CIC-IDS2017 ile eğitildi)
- `predict.py`, `preprocessor.py`, `pcap_processor.py`, `logger.py` hazır

### FAZ 2 — Veritabanı
- Elasticsearch + Kibana Docker Compose ile çalışıyor
- `src/dashboard/elasticsearch_writer.py` tamamlandı
- Veriler Kibana'da `intsec-predictions` index'inde görünüyor
- **ÖNEMLİ:** elasticsearch_writer.py'de alan adı `@timestamp` olmalı, `timestamp` değil!
  Kibana varsayılan olarak `@timestamp` arar.

### FAZ 2 — Dashboard (Ahmet)
- `src/dashboard/app.py`: Streamlit dashboard
  - CSV seçimi
  - Pie chart (saldırı dağılımı)
  - Confidence histogram
  - Alarm banner
  - CSV export

### FAZ 3 — VM Kurulumu ve Saldırı Altyapısı (2026-04-02/03)

#### VirtualBox Kurulumu
- VirtualBox 7.2.6a kuruldu (Windows host)
- **Ubuntu-INTSEC VM:**
  - ISO: ubuntu-22.04.5-live-server-amd64.iso
  - RAM: 2048MB, Disk: 25GB
  - Kullanıcı: `intsec`, Şifre: `intsec123`
  - IP: `192.168.1.24`
  - Ağ: Köprü Bağdaştırıcısı (Bridge) — internet + VM arası iletişim
  - OpenSSH kurulu
- **Kali-INTSEC VM:**
  - ISO: kali-linux-2026.1-installer-amd64.iso
  - RAM: 2048MB, Disk: 25GB
  - Kullanıcı: `kali`, Şifre: kurulum sırasında belirlendi
  - Ağ: Köprü Bağdaştırıcısı (Bridge)

#### Ubuntu'ya Kurulan Paketler
```bash
sudo apt update && sudo apt install -y python3 python3-pip tcpdump git
sudo apt install -y git
git clone https://github.com/ahlashkari/NTLFlowLyzer.git
cd /tmp/NTLFlowLyzer && pip3 install -r requirements.txt
pip3 install .
export PATH=$PATH:/home/intsec/.local/bin
```

#### İki VM'nin Birbirini Görmesi
- Kali'den Ubuntu'ya ping testi: `ping 192.168.1.24` → başarılı

#### PCAP Yakalama (Ubuntu'da)
```bash
# Kısa test (50.000 paket):
sudo tcpdump -i enp0s3 -w /tmp/ddos_short.pcap -c 50000

# Uzun test (sınırsız, Ctrl+C ile dur):
sudo tcpdump -i enp0s3 -w /tmp/ddos_test.pcap
```

#### DDoS Saldırısı (Kali'de)
```bash
# Ping testi:
ping -c 100 192.168.1.24

# DDoS flood (port 80):
sudo hping3 --flood -p 80 192.168.1.24
# NOT: hping3 saniyede 100k+ paket üretiyor. 10 sn = 1M+ paket.
# Demo için 50.000 paket sınırı yeterli (-c 50000 tcpdump tarafında)
```

#### PCAP → CSV (NTLFlowLyzer, Ubuntu'da)
```bash
# Config dosyası oluştur:
echo '{"pcap_file_address":"/tmp/ddos_short.pcap","output_file_address":"/tmp/ddos_flows.csv","number_of_threads":4}' > /tmp/ntl_config.json

# Çalıştır:
export PATH=$PATH:/home/intsec/.local/bin
ntlflowlyzer -c /tmp/ntl_config.json

# Süre ölçmek için:
time ntlflowlyzer -c /tmp/ntl_config.json
```
**NOT:** Output dosyası `/tmp/ ddos_flows.csv` (başında boşlukla) oluşabilir. Kontrol:
```bash
find /tmp -name "*.csv"
mv "/tmp/ ddos_flows.csv" /tmp/ddos_flows.csv
```

#### CSV'yi Windows'a Aktarma (Ubuntu → Windows)
```bash
# Ubuntu'da HTTP server başlat:
cd /tmp && python3 -m http.server 8888

# Windows'ta (Claude terminali veya CMD):
curl -o C:/Users/ahmet/Intelligent-Security/data/processed/ddos_flows.csv http://192.168.1.24:8888/ddos_flows.csv
```

#### SSH ile Ubuntu'ya Bağlanma (Windows CMD'den)
```bash
ssh intsec@192.168.1.24
# Şifre: intsec123
```

#### Model Tahmini + ES'e Yazma (Windows'ta)
```bash
cd C:/Users/ahmet/Intelligent-Security
python -c "
import pandas as pd, numpy as np, joblib, json
from datetime import datetime
from elasticsearch import Elasticsearch

model = joblib.load('data/models/multiclass_v2/model.joblib')
scaler = joblib.load('data/models/multiclass_v2/scaler.joblib')
with open('data/models/multiclass_v2/feature_names.json') as f:
    features = json.load(f)
with open('data/models/multiclass_v2/metadata.json') as f:
    metadata = json.load(f)
classes = metadata['class_names']

df = pd.read_csv('data/processed/ddos_flows.csv')
df['bwd_avg_segment_size'] = 0  # Bu feature NTLFlowLyzer'da eksik

X = df[features].fillna(0).replace([np.inf, -np.inf], 0)
X_scaled = scaler.transform(X)
preds = model.predict(X_scaled)
probs = model.predict_proba(X_scaled)
confidence = probs.max(axis=1)

es = Elasticsearch(['http://localhost:9200'])
for i, (_, row) in enumerate(df.iterrows()):
    doc = {
        '@timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
        'source_ip': str(row.get('src_ip', 'unknown')),
        'destination_ip': str(row.get('dst_ip', 'unknown')),
        'src_port': int(row.get('src_port', 0)),
        'dst_port': int(row.get('dst_port', 0)),
        'attack_type': classes[str(preds[i])],
        'confidence': float(confidence[i]),
        'csv_source': 'ddos_short.pcap'
    }
    es.index(index='intsec-predictions', document=doc)
print(f'[+] {len(df)} kayit ES e yazildi!')
"
```

---

## Bilinen Sorunlar ve Çözümleri

### 1. Kibana Discover'da "Today" filtresi veri göstermiyor
**Sebep:** elasticsearch_writer.py `timestamp` alanı kullanıyordu, Kibana `@timestamp` arar.
**Çözüm:** Alan adını `@timestamp` olarak düzelt (zaten düzeltildi), index'i sil ve yeniden yaz:
```bash
curl -X DELETE http://localhost:9200/intsec-predictions
python src/dashboard/elasticsearch_writer.py
```
Sonra Kibana → Stack Management → Index Patterns → `intsec-predictions`'ı sil ve yeniden oluştur, time field olarak `@timestamp` seç.

### 2. Kibana'da "Last 15 minutes" veri göstermiyor
**Sebep:** Veriler biraz önce yazılmış olsa bile UTC fark nedeniyle "Today" kaçırabilir.
**Çözüm:** "Last 24 hours" filtresi kullan.

### 3. Model hping3 DDoS trafiğini tanımıyor (Benign diyor)
**Sebep:** Model CIC-IDS2017 ile eğitildi, o veri LOIC/GoldenEye araçlarıyla üretildi. hping3 farklı pattern.
**Çözüm:** Semih modeli hping3 verisiyle yeniden eğitecek. `ddos_flows.csv` (42MB) ona gönderildi.

### 4. sklearn InconsistentVersionWarning
**Sebep:** Model sklearn 1.6.1 ile eğitildi, ortamda 1.7.2 var.
**Durum:** Warning sadece, crash yok. Demo'yu etkilemiyor.

### 5. NTLFlowLyzer output dosyası bulunamıyor
**Sebep:** Config JSON'da output path boşlukla kaydedilmiş olabilir.
**Çözüm:** `find /tmp -name "*.csv"` ile bul, gerekirse `mv` ile taşı.

---

## Devam Eden / Eksik Görevler

### Ahmet'in Görevleri
- [ ] **ÖNCELİK 4 — Kibana Donut Chart** (Donut chart var ama dashboard'a eklenmedi)
  - Kibana → Visualize Library → Create Visualization → "Pie"
  - Index: `intsec-predictions`, Slice by: `attack_type.keyword`
  - Donut modunu aç, kaydet: "Saldiri Tipi Dagilimi"

- [ ] **ÖNCELİK 5 — Streamlit Elasticsearch Entegrasyonu**
  - `src/dashboard/elasticsearch_reader.py` yazılacak
  - `fetch_predictions(limit=200)` fonksiyonu — ES'ten okuyacak
  - `app.py`'de CSV yerine bu kullanılacak
  - Eklenecek grafikler: Line chart (7 günlük trend), Bar chart (Top 10 IP)

### Semih'in Görevleri
- [ ] **KRİTİK — Modeli yeniden eğit**
  - `ddos_flows.csv` (42MB, gerçek hping3 verisi) gönderildi
  - hping3 DDoS trafiği şu an Benign olarak sınıflandırılıyor
  - Model yeniden eğitilince pipeline doğru çalışacak

### Veysel'in Görevleri
- [x] VM kurulumu tamamlandı (Ahmet yaptı)
- [ ] Port Scan testi: `nmap -sS -p 1-1000 192.168.1.24`
- [ ] Slowloris DoS testi: `python3 slowloris.py 192.168.1.24`

### Semih İkbal'ın Görevi
- [ ] **File Watcher** (`src/watcher/file_watcher.py` — dosya zaten var, test edilmedi)
  - `watchdog` kütüphanesi ile `data/pcap/` klasörünü izle
  - Yeni .pcap gelince pipeline'ı otomatik tetikle

---

## Sistem Başlatma Sırası

```bash
# Her oturumda (Windows'ta):
docker-compose up -d
python src/dashboard/elasticsearch_writer.py
streamlit run src/dashboard/app.py   # opsiyonel

# Saldırı senaryosu için:
# 1. Ubuntu VM başlat (VirtualBox)
# 2. Kali VM başlat (VirtualBox)
# 3. Ubuntu'da: sudo tcpdump -i enp0s3 -w /tmp/ddos_short.pcap -c 50000
# 4. Kali'de: sudo hping3 --flood -p 80 192.168.1.24
# 5. Ubuntu'da tcpdump durduğunda: ntlflowlyzer -c /tmp/ntl_config.json
# 6. Windows'a CSV aktar, modelden geçir, ES'e yaz
```

---

## Önemli Dosya Yolları

| Dosya | Yol |
|-------|-----|
| Dashboard | `src/dashboard/app.py` |
| ES Writer | `src/dashboard/elasticsearch_writer.py` |
| ES Reader (yapılacak) | `src/dashboard/elasticsearch_reader.py` |
| File Watcher | `src/watcher/file_watcher.py` |
| Model | `data/models/multiclass_v2/` |
| İşlenmiş CSV'ler | `data/processed/` |
| PCAP klasörü | `data/pcap/` |
| ddos_flows.csv (gerçek saldırı) | `data/processed/ddos_flows.csv` (42MB) |
| ES Index | `intsec-predictions` |
| Kibana | `localhost:5601` |
| Elasticsearch | `localhost:9200` |
| Streamlit | `localhost:8501` |
| Ubuntu VM IP | `192.168.1.24` |
| Ubuntu kullanıcı/şifre | `intsec` / `intsec123` |
| NTLFlowLyzer (Ubuntu'da) | `/tmp/NTLFlowLyzer/` |

---

## Demo Senaryosu (Final Sunum ~5 dk)

1. `docker-compose up -d` (30 sn)
2. Ubuntu VM'i başlat → `sudo tcpdump -i enp0s3 -w /tmp/attack.pcap -c 50000`
3. Kali'den DDoS: `sudo hping3 --flood -p 80 192.168.1.24`
4. tcpdump durduğunda NTLFlowLyzer ile işle
5. CSV'yi Windows'a aktar, modelden geçir
6. Kibana'da yeni kayıtların geldiğini göster
7. Streamlit alarm banner'ının kırmızıya döndüğünü göster

**NOT:** Model yeniden eğitilirse adım 6'da DDoS olarak görünecek. Eğitilmemişse Benign görünür ama pipeline çalıştığını göstermek yeterli.

---

## Risk ve Alternatifler

| Risk | Alternatif |
|------|-----------|
| NTLFlowLyzer PCAP'i yavaş işler | 50.000 paket sınırı ile kısa PCAP yakala |
| Model yanlış sınıflandırır | Semih modeli yeniden eğitecek (ddos_flows.csv gönderildi) |
| VM'ler arası ağ çalışmaz | Bridge adapter kullanıldı, çalışıyor |
| Watchdog geliştirilemez | Manuel PCAP kopyalama ile demo yap |
| sklearn version uyuşmazlığı | Warning sadece, crash yok |

---

## Son Kontrol Listesi (Teslimden 1 Hafta Önce)

- [x] VM'ler kuruldu (Ubuntu + Kali)
- [x] VM'ler arası saldırı PCAP'i alınabiliyor
- [x] Pipeline uçtan uca çalışıyor (PCAP → NTLFlowLyzer → Model → ES → Kibana)
- [x] Kibana'da veriler görünüyor
- [ ] Model gerçek PCAP'ten DDoS'u doğru tespit ediyor (Semih halledecek)
- [ ] Kibana donut chart dashboard'a eklendi
- [ ] Streamlit alarm veriyor (ES'ten okuması lazım)
- [ ] `docker-compose up -d` ile her şey ayağa kalkıyor
- [ ] Demo videosu çekiliyor
- [ ] README güncelleniyor
- [ ] PowerPoint tamamlanıyor

---

## Session Geçmişi

### 2026-04-13 (Session 8 — multiclass_v4 Deploy + Kibana Alarm Sistemi)

**Yapılanlar:**

**Model 4 Ubuntu'ya Deploy:**
- `multiclass_v4` modeli eğitildi (Semih tarafından):
  - 6 sınıf: Benign, DoS/DDoS, Web Attack, Port Scan, Brute Force, Botnet
  - Test Accuracy: **%99.85**, F1: %99.85
  - 903.622 örnek, 30 feature, RandomForest (100 estimator, max_depth=20, class_weight=balanced)
  - Gerçek Kali Brute Force verisi eklendi (1.942 flow) + Port Scan (24.887 flow)
- Model dosyaları (`model4.joblib`, `scaler4.joblib`, `feature_names4.json`, `metadata4.json`) Windows'tan SCP ile Ubuntu'ya aktarıldı:
  - Hedef: `/home/intsec/models/multiclass_v4/`
- `pipeline.py` multiclass_v4 kullanacak şekilde güncellendi:
  - `MODEL_DIR = "/home/intsec/models/multiclass_v4"`
  - ES_HOST: `192.168.1.200` (Windows Wi-Fi IP)
  - PACKET_COUNT: 200 → **50** (daha hızlı döngü)
  - ES client: `request_timeout=30, max_retries=3, retry_on_timeout=True` eklendi
  - Temp dosya silme: `os.remove()` → `subprocess.run(["sudo", "rm", "-f", p])` (root owned pcap fix)
- Ubuntu'da sudoers güncellendi: `intsec ALL=(ALL) NOPASSWD: ALL`
- Pipeline test edildi: DoS/DDoS ve Port Scan başarıyla tespit edildi

**Saldırı Testleri:**
- `sudo hping3 -S -p 80 --flood 192.168.1.203` → **DoS/DDoS** doğru tespit
- `nmap -sS -p- 192.168.1.203` → **Port Scan** doğru tespit
- `hydra -l root -P rockyou.txt ssh://192.168.1.203` → Brute Force tespiti zayıf (çoğu Benign çıktı)
  - **Sebep:** 1.942 Brute Force flow az, Hydra SSH pattern'i eğitim verisinden farklı
  - **Çözüm:** Hydra ile yeni SSH Brute Force PCAP alınıp model yeniden eğitilmeli

**Kibana Alarm Sistemi:**
- `docker-compose.yml`'e Kibana encryption key eklendi (alerting için zorunlu):
  ```
  XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY
  XPACK_REPORTING_ENCRYPTIONKEY
  XPACK_SECURITY_ENCRYPTIONKEY
  ```
- Kibana container `--force-recreate` ile yeniden oluşturuldu
- **INTSEC Attack Alert** kuralı oluşturuldu:
  - Type: Index threshold
  - Index: `intsec-predictions`
  - Condition: count > 0, grouped over `attack_type.keyword`, son 1 dakika
  - Actions: Index connector (alert doc yazar) + Server log connector
  - Test: DoS/DDoS saldırısında **Active** durumuna geçti ✓

**IP Bilgileri (2026-04-13):**
- Windows IP: `192.168.1.200` (Wi-Fi)
- Ubuntu IP: `192.168.1.203`
- Kali IP: `192.168.1.20`

**Bilinen Sorunlar:**
- Brute Force tespiti zayıf — SSH Hydra trafiği çoğunlukla Benign sınıflandırılıyor
- ES bağlantısı ara sıra timeout (büyük flood sırasında) — retry mekanizması eklendi, otomatik devam ediyor

---

### 2026-04-09 (Session 7 — multiclass_v3 Model Eğitimi)

**Yapılanlar:**
- `notebooks/05_train_multiclass_v3.ipynb` oluşturuldu ve Jupyter'da çalıştırıldı
- multiclass_v2 verisi (876.793 satır) + `portscan_flows.csv` (24.887 gerçek nmap Port Scan flow) birleştirildi
- `bwd_segment_size_mean` → `bwd_avg_segment_size` rename (NTLFlowLyzer uyumu)
- Port Scan label = 3 olarak atandı (NTLFlowLyzer 'Unknown' üretiyor)
- Aynı 30 feature, aynı RandomForest (100 estimator, max_depth=20, class_weight=balanced)
- **multiclass_v3 sonuçları:**
  - Toplam örnek: 901.680 (v2'ye +24.887)
  - Port Scan örnekleri: 186.210 (161.323 CIC + 24.887 gerçek nmap)
  - Test Accuracy: **%99.85** (v2: %99.83)
  - F1 Score: **%99.86** (v2: %99.84)
- Dosyalar: `data/models/multiclass_v3/model3.joblib`, `scaler3.joblib`, `feature_names3.json`, `metadata3.json`
- pipeline.py güncellenmedi — v3 ayrı klasörde duruyor

**Öğrenilen Dersler:**
- Gerçek nmap verisi eklemek Port Scan tespitini iyileştirdi, genel accuracy da arttı

---

### 2026-04-09 (Session 6 — Port Scan CSV Üretimi + Pipeline Sorun Giderme)

**Yapılanlar:**
- Docker compose başlatıldı (ES + Kibana + Kafka ayağa kalktı)
- Windows IP değişmişti: `192.168.1.16` → `192.168.1.198` (Wi-Fi)
- Ubuntu IP bu oturumda: `192.168.1.200`
- Ubuntu'da `pipeline.py` güncellendi: `sed -i 's/192.168.1.16/192.168.1.198/g'`
- Ubuntu'da python3 kurulu değildi (VM muhtemelen önceki snapshot'a dönmüş):
  - `sudo apt install -y python3 python3-pip`
  - `pip3 install elasticsearch pandas scikit-learn joblib numpy`
- `/home/intsec/ntl_config.json` permission hatası → `sudo chmod 666` ile düzeltildi
- `/tmp/capture.pcap` permission hatası → `sudo chmod 777 /tmp` veya `setcap` ile düzeltildi
- Pipeline başlatıldı → Kali saldırmadan bile DoS/DDoS trafik Kibana'ya düşmeye başladı (pipeline çalışıyor)
- **Port Scan CSV üretimi:**
  - Ubuntu'da: `sudo tcpdump -i enp0s3 -w /tmp/portscan.pcap -c 50000`
  - Kali'den: `sudo nmap -sS -p 1-65535 --min-rate 5000 192.168.1.200`
  - NTLFlowLyzer: 50.000 paket → **24.887 flow** → `portscan_flows.csv`
  - Windows'a SCP ile indirildi: `C:/Users/ahmet/Desktop/portscan_flows.csv`
  - `portscan_flows.csv` Semih'e gönderildi → model v3 eğitimi için

**Öğrenilen Dersler:**
- VM yeniden başlatıldığında python3 kurulumu gidebilir (snapshot sorunu) — kurulumu tekrarlamak gerekiyor
- `ntl_config.json` ve `/tmp` dizini için sudo gerekebilir
- NTLFlowLyzer 50.000 paket için ~5 dakika sürüyor (131k'ya kıyasla makul)

**Semih'e Gönderilen Dosyalar:**
- `ddos_flows.csv` (42MB, hping3 DDoS — Session 3'te)
- `portscan_flows.csv` (24.887 flow, nmap Port Scan — bu session)

**Ubuntu IP (2026-04-09):** `192.168.1.200`
**Windows IP (2026-04-09):** `192.168.1.198`

---

### 2026-04-06 (Session 5 — multiclass_v2 Test + Kibana Dashboard)

**Yapılanlar:**
- `oksuzoglu_04_04` branch'ine geçildi — Semih'in multiclass_v2 modeli incelendi
- multiclass_v2 model bilgileri:
  - RandomForestClassifier, 100 estimator, max_depth=20
  - Test accuracy: %99.83, F1: 0.9984
  - 6 sınıf: Benign, DoS/DDoS, Web Attack, Port Scan, Brute Force, Botnet
  - 116 feature → 30 feature seçimi
- `data/models/pipeline.py` güncellendi:
  - `multiclass_v1` → `multiclass_v2`
  - NTLFlowLyzer config'e `features_ignore_list` eklendi (daha hızlı çalışması için)
  - `bwd_segment_size_mean → bwd_avg_segment_size` rename düzeltildi
  - PACKET_COUNT 200'e ayarlandı
- multiclass_v2 model dosyaları Ubuntu'ya aktarıldı (`/home/intsec/models/multiclass_v2/`)
- pipeline.py Ubuntu'ya aktarıldı (`/home/intsec/pipeline.py`)
- Windows Firewall'a ES-9200 kuralı eklendi (admin terminal ile)
- Kali'den hping3 flood saldırısı yapıldı → pipeline **DoS/DDoS doğru tespit etti** (~%90+)
- Kali'den nping ile farklı tool testi yapıldı → yine DoS/DDoS tespit edildi
- Port Scan (nmap -sS -p 1-1000) → çoğunlukla DoS/DDoS, 1 adet Port Scan (confidence 0.5)
- Kibana'da pie chart oluşturuldu: Aggregation based → Pie → attack_type.keyword
- Dashboard oluşturuldu, pie chart + discover yan yana
- Port Scan için büyük PCAP (131k paket) alındı ama NTLFlowLyzer CPU soft lockup yaptı — iptal edildi

**Öğrenilen Dersler:**
- hping3 flood Ubuntu'nun ağını kilitleyebiliyor → kısa tutmak lazım (5-10 sn)
- NTLFlowLyzer 131k paket için 20+ dakika sürüyor ve CPU'yu kilitledi → PCAP küçük tutulmalı
- Ping (ICMP) Windows Firewall tarafından bloke ediliyor ama TCP 9200 çalışıyor

**Yapılacaklar (Semih için):**
- Port Scan, Brute Force, Web Attack, Botnet için ayrı CSV'ler üretilecek
- Bu CSV'lerle model yeniden eğitilecek
- Bunun için küçük PCAP alınıp NTLFlowLyzer ile işlenecek

**Ubuntu IP (2026-04-06):** `192.168.1.17`
**Windows IP (2026-04-06):** `192.168.1.16`

---

### 2026-04-02/03 (Session 3 — Büyük Sprint)
**Yapılanlar:**
- Kibana `@timestamp` sorunu çözüldü (alan adı `timestamp`→`@timestamp` düzeltildi, index pattern yeniden oluşturuldu)
- VirtualBox 7.2.6a kuruldu
- Ubuntu-INTSEC VM kuruldu (22.04.5, kullanıcı: intsec/intsec123, IP: 192.168.1.24)
- Kali-INTSEC VM kuruldu (2026.1)
- İki VM bridge adapter ile birbirini görüyor
- Ubuntu'ya python3, pip3, tcpdump, git, NTLFlowLyzer kuruldu
- Kali'den hping3 ile DDoS flood saldırısı yapıldı
- tcpdump ile 50.000 paketlik PCAP yakalandı
- NTLFlowLyzer ile PCAP → 24.992 flow → 347 feature CSV oluşturuldu
- CSV Windows'a HTTP server ile aktarıldı (42MB)
- Model tahmin yaptı (sorun: hping3 trafiği Benign çıktı, model tanımıyor)
- 24.992 kayıt ES'e yazıldı, Kibana'da görünüyor
- ddos_flows.csv Semih'e gönderildi, model yeniden eğitilecek

**Kalan tek kritik görev:** Semih'in modeli yeniden eğitmesi

### 2026-04-02 (Session 2)
- RSD v2.0, DSD v2.0, Final Report (Rescued document 1) ve Yol Haritası okundu
- PROGRESS_LOG.md oluşturuldu ve tüm belgelerden özet çıkarıldı

### 2026-04-02 (Session 1)
- Kali Linux ve Ubuntu VM kurulum planı konuşuldu (session kapandığı için kayıp)

---

## Kaynaklar

- **RSD v2.0:** `C:\Users\ahmet\Desktop\INTSEC_RSD_V2.pdf`
- **DSD v2.0:** `C:\Users\ahmet\Desktop\INTSEC-DSD-Rev-2.0.pdf`
- **Final Report:** `C:\Users\ahmet\Desktop\Rescued document 1.pdf`
- **Yol Haritası:** `C:\Users\ahmet\Desktop\INTSEC_Yol_Haritasi.md`
- **Dataset:** CIC-IDS2017 (Canadian Institute for Cybersecurity)
- **Feature Tool:** NTLFlowLyzer (347 feature çıkarır, model 30 tanesini kullanır)
- **NTLFlowLyzer GitHub:** https://github.com/ahlashkari/NTLFlowLyzer

---

*Son güncelleme: 2026-04-13*
