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
- [ ] **ÖNCELİK 1 — Scapy Tabanlı Real-Time Pipeline**
  - `data/models/pipeline.py` tamamen yeniden yazılacak
  - NTLFlowLyzer kaldırılacak, Scapy ile canlı paket yakalanacak
  - 30 feature Scapy ile hesaplanacak (IAT, packet rate, header bytes vs.)
  - Her 5-10 saniyede ES'e yazılacak
  - Semih modeli yeniden eğitince feature uyumu test edilmeli

- [ ] **ÖNCELİK 2 — Kibana Donut Chart** (Donut chart var ama dashboard'a eklenmedi)
  - Kibana → Visualize Library → Create Visualization → "Pie"
  - Index: `intsec-predictions`, Slice by: `attack_type.keyword`
  - Donut modunu aç, kaydet: "Saldiri Tipi Dagilimi"

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
- [x] Model gerçek PCAP'ten DDoS'u doğru tespit ediyor
- [x] Brute Force verisi üretildi (50k flow, Hydra SSH)
- [x] Web Attack verisi üretildi (17k flow, Nikto)
- [x] multiclass_v5 eğitildi (Brute Force iyileşti: F1 0.89→1.00)
- [x] multiclass_v6 eğitildi (Web Attack iyileşti: F1 0.89→0.98)
- [ ] multiclass_v6 Ubuntu'ya deploy edildi
- [ ] Kibana donut chart dashboard'a eklendi
- [ ] Streamlit alarm veriyor (ES'ten okuması lazım)
- [ ] `docker-compose up -d` ile her şey ayağa kalkıyor
- [ ] Demo videosu çekiliyor
- [ ] README güncelleniyor
- [ ] PowerPoint tamamlanıyor

---

## Session Geçmişi

### 2026-04-17/18 (Session 9 — VM Kurulumu + Saldırı Verisi Üretimi + multiclass_v5/v6)

**Yapılanlar:**

**VM Kurulumu (Semih'in Makinesinde Sıfırdan):**
- VirtualBox zaten kuruluydu
- **Ubuntu-INTSEC VM** kuruldu: ubuntu-22.04.5-live-server-amd64.iso
  - RAM: 2048MB, Disk: 25GB, Bridge Adapter (MediaTek MT7921 Wi-Fi)
  - Kullanıcı: `intsec` / `intsec123`, OpenSSH kurulu
  - IP: `192.168.1.36`
- **Kali-INTSEC VM** kuruldu: kali-linux-2025.1a-installer-amd64.iso
  - RAM: 2048MB, Disk: 25GB, Bridge Adapter
  - Kullanıcı: `kali` / `kali123`
  - IP: `192.168.1.40`
  - NOT: Kurulumda Güvenli Önyükleme kapalı olmalı, GRUB → /dev/sda seçilmeli

**Ubuntu'ya Kurulan Araçlar:**
```bash
sudo apt update && sudo apt install -y python3 python3-pip tcpdump git apache2
cd /tmp && git clone https://github.com/ahlashkari/NTLFlowLyzer.git
cd /tmp/NTLFlowLyzer && pip3 install -r requirements.txt && pip3 install .
echo 'export PATH=$PATH:/home/intsec/.local/bin' >> ~/.bashrc && source ~/.bashrc
pip3 install elasticsearch pandas scikit-learn joblib numpy
sudo dpkg-reconfigure keyboard-configuration  # Türkçe Q klavye
```

**Kali'ye Kurulan Araçlar:**
```bash
sudo apt install -y openssh-server
sudo systemctl start ssh && sudo systemctl enable ssh
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

**Pipeline Kurulumu:**
- multiclass_v4 dosyaları SCP ile Ubuntu'ya aktarıldı: `/home/intsec/models/multiclass_v4/`
- `pipeline.py` Ubuntu'ya aktarıldı: `/home/intsec/pipeline.py`
- `PACKET_COUNT` 50 → **500** yapıldı (daha iyi tespit için)
- ES_HOST = Windows Wi-Fi IP (her oturumda değişiyor, kontrol et!)
- sudoers: `intsec ALL=(ALL) NOPASSWD: ALL`
- Windows Firewall'a 9200 portu açıldı

**IP Bilgileri (2026-04-17/18):**
- Windows IP: `192.168.1.38` (Wi-Fi, her oturumda değişebilir!)
- Ubuntu IP: `192.168.1.36`
- Kali IP: `192.168.1.40`

**Brute Force Verisi Üretimi:**
- Ubuntu'da otomatik kayıt scripti: `/home/intsec/capture_loop.sh`
  - Her 120 saniyede Kali'den gelen paketleri yakalar → NTLFlowLyzer → CSV
  - `nohup bash /home/intsec/capture_loop.sh > /home/intsec/capture.log 2>&1 &`
- Kali'den Hydra SSH Brute Force:
  - `hydra -l root -P /usr/share/wordlists/rockyou.txt -t 64 ssh://192.168.1.36`
- Gece boyunca çalıştı → 1406 CSV, ~2M flow üretildi
- Windows'a SCP ile indirildi, 50.000 satır alındı: `data/processed/bruteforce_50k.csv`
- **NOT:** `/tmp` reboot'ta temizlenir, PCAP'leri `/home/intsec/` altına kaydet!

**Web Attack Verisi Üretimi:**
- Ubuntu'da Apache kuruldu (port 80)
- Kali'den Nikto ile Web Attack: `nikto -h http://192.168.1.36` (16 kez çalıştırıldı)
- NTLFlowLyzer ile işlendi → `webattack_all.csv` (~17k flow)
- Windows'a aktarıldı: `data/processed/webattack_all.csv`

**Model Eğitimleri:**
- **multiclass_v5** (`notebooks/07_train_multiclass_v5.ipynb`):
  - v4 verisi + `bruteforce_50k.csv` (50k Hydra SSH flow)
  - Accuracy: %99.86, F1: %99.87
  - Brute Force: precision 1.00, recall 1.00 (v4'te zayıftı)
  - Kaydedildi: `data/models/multiclass_v5/`

- **multiclass_v6** (`notebooks/08_train_multiclass_v6.ipynb`):
  - v5 verisi + `webattack_all.csv` (17k Nikto flow)
  - Accuracy: %99.87, F1: %99.87
  - Web Attack: F1 0.89 → **0.98** (büyük iyileşme!)
  - Kaydedildi: `data/models/multiclass_v6/`

**Bilinen Sorunlar:**
- Ubuntu disk dolabilir (12GB) — `df -h` ile kontrol et, gerekirse `/home/intsec/datasets/` sil
- Brute Force (SSH yönetim trafiği) pipeline'da Brute Force olarak görünebilir — SSH bağlantısı olduğunda normal
- Windows IP her oturumda değişiyor — `ipconfig` ile kontrol et, `sed -i` ile pipeline.py'yi güncelle

**v6 Deploy ve Test Sonuçları (2026-04-18):**
- Ubuntu statik IP: `192.168.1.100` (artık değişmiyor)
- multiclass_v6 Ubuntu'ya deploy edildi: `/home/intsec/models/multiclass_v6/`
- pipeline.py güncellendi: Windows IP otomatik bulma + v6 model dosyaları
- ES_HOST Windows IP'si manuel güncellenmeli: `sed -i 's|eski_ip:9200|yeni_ip:9200|' /home/intsec/pipeline.py`

**Gerçek Saldırı Test Sonuçları (multiclass_v6):**

| Saldırı | Araç | Pipeline Sonucu | Başarı |
|---------|------|----------------|--------|
| DDoS | hping3 --faster | Çoğunlukla Benign | ✗ Başarısız |
| Port Scan | nmap -sS -p 1-65535 | Port Scan: 163, Benign: 59 | ✓ Başarılı |
| Brute Force | hydra -t 16 | DoS/DDoS: 5, Benign: 163, Port Scan: 1 | ✗ Başarısız |
| Web Attack | nikto | Benign: 141, DoS/DDoS: 6, Port Scan: 3 | ✗ Başarısız |

**Sorun Analizi:**
- Port Scan dışında tüm saldırılar çoğunlukla Benign olarak sınıflandırılıyor
- Sebep: Model CIC-IDS2017 verisiyle eğitildi, o dataset farklı araçlar kullandı (LOIC, GoldenEye vs.)
- Gerçek araç trafiği (hping3, hydra, nikto) eğitim verisindeki pattern'lerden farklı
- Pipeline 500 paket yakalıyor, saldırı paketleri normal trafik ile karışıyor
- **Çözüm:** Gerçek saldırı verileriyle modeli yeniden eğitmek gerekiyor (ddos_flows.csv, bruteforce_50k.csv, webattack_all.csv daha iyi entegre edilmeli)

**Yapılacaklar:**
- [ ] DDoS tespitini iyileştir — hping3 PCAP'lerinden yeni veri üret, modele ekle
- [ ] Brute Force tespitini iyileştir — pipeline SSH yönetim trafiğini filtrele
- [ ] Web Attack tespitini iyileştir — nikto verisi daha fazla çeşitlendirilmeli
- [ ] Kibana donut chart dashboard'a eklendi
- [ ] Streamlit alarm veriyor (ES'ten okuması lazım)

---

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

*Son güncelleme: 2026-04-20*

---

### 2026-04-19/20 (Session 10 — Domain Shift Çözümü + Model v7–v12)

**Ana Problem:** Model CIC-IDS2017 verisiyle eğitilmişti ama gerçek araç trafiği (hping3, hydra, nikto) tamamen farklı feature pattern'leri üretiyor. Bu "domain shift" problemi nedeniyle model gerçek saldırıları tanıyamıyordu.

**Çözüm Stratejisi:** Her saldırı türü için pipeline'dan gerçek veri topla, CIC verisini çıkar, kendi verini koy.

---

**Feature Analizi (`notebooks/09_feature_analysis.ipynb`):**
- Gerçek Hydra BF: `bwd_*` featurelar tümü 0 (tek yönlü SSH), CIC BF'de çift yönlü
- Gerçek Nikto WA: `packets_rate` 1838x daha yüksek CIC WA'ya göre
- Gerçek hping3 DDoS: farklı paket boyutu ve IAT dağılımı
- **Sonuç:** CIC verisi gerçek araçlarla eğitim için kullanılamaz

---

**Veri Toplama — Pipeline Capture Scriptleri:**

Ubuntu'da çalışan veri toplama scriptleri oluşturuldu. Her script `/tmp/capture.csv` dosyasının değiştiğini `stat -c %Y` ile izleyip kopyasını alıyor:

```bash
# Örnek: collect_bf_data.sh (aynı mantık ddos ve wa için)
while true; do
    if [ -f /tmp/capture.csv ]; then
        CURRENT_MOD=$(stat -c %Y /tmp/capture.csv)
        if [ "$CURRENT_MOD" != "$LAST_MODIFIED" ]; then
            cp /tmp/capture.csv "$OUTPUT_DIR/xxx_$COUNTER.csv"
            COUNTER=$((COUNTER + 1))
            LAST_MODIFIED=$CURRENT_MOD
        fi
    fi
    sleep 0.5
done
```

**Toplanan veri:**
| Saldırı | Script | Dosya Sayısı | Flow Sayısı | Klasör |
|---------|--------|-------------|-------------|--------|
| Brute Force (Hydra SSH) | collect_bf_data.sh | 574 | 5.568 | data/processed/bf_captures/ |
| Web Attack (Nikto) | collect_wa_data.sh | ~200+ | 5.105 | data/processed/wa_captures/ |
| DDoS (hping3) | collect_ddos_data.sh | 652 | ~110.000 | data/processed/ddos_captures/ |

**Not:** DDoS verisi çok fazla toplandı (110k), bu imbalance problemi yarattı (v11'de her şeyi DDoS dedi).

---

**Model Geliştirme Serisi:**

**multiclass_v7** (`notebooks/10_train_multiclass_v7_xgboost.ipynb`):
- v6 ile aynı veri, RandomForest → **XGBoost** geçiş
- Accuracy: %99.87 — gerçek zamanlı tespit iyileşmedi
- Kaydedildi: `data/models/multiclass_v7/`

**multiclass_v8** (`notebooks/11_train_multiclass_v8.ipynb`):
- CIC Brute Force (label=4, ~15k) kaldırıldı
- `bf_captures/` (5.568 gerçek Hydra flow) eklendi
- Accuracy: %99.87
- **Gerçek zamanlı Brute Force: %100 tespit! (SÜPER)**
- Kaydedildi: `data/models/multiclass_v8/`

**multiclass_v9** (`notebooks/12_train_multiclass_v9.ipynb`):
- CIC BF + CIC WA kaldırıldı
- `wa_captures/` (5.105 gerçek Nikto flow) eklendi
- Web Attack: **%100 tespit**
- Brute Force: %75 (kısmen Web Attack ile karışıyor)
- Kaydedildi: `data/models/multiclass_v9/`

**multiclass_v10** (`notebooks/13_train_multiclass_v10.ipynb`):
- CIC DDoS + BF + WA kaldırıldı
- `ddos_flows.csv` (önceden toplanan 25k hping3 flow) eklendi
- DDoS gerçek zamanlı hâlâ zayıf
- Kaydedildi: `data/models/multiclass_v10/`

**multiclass_v11** (`notebooks/14_train_multiclass_v11.ipynb`):
- **Botnet sınıfı tamamen kaldırıldı** (gerçek botnet üretemiyoruz, 5 sınıfa düşüldü)
- `ddos_captures/` (652 dosya, ~110k flow) eklendi
- **Sorun:** Her şeyi DDoS tahmin etti — 110k DDoS vs 5k diğerleri, aşırı imbalance
- Kaydedildi: `data/models/multiclass_v11/`

**multiclass_v12** (`notebooks/15_train_multiclass_v12.ipynb`):
- ddos_captures'dan sadece **10.000 satır** rastgele örneklendi (`DDOS_CAP = 10000`)
- DDoS tespiti düzeldi
- **Kalan sorun:** Web Attack saldırısının ~%50'si DDoS, ~%50'si Web Attack tahmin ediliyor
- Kaydedildi: `data/models/multiclass_v12/`

**multiclass_v13 (PLANLI):**
- `DDOS_CAP = 5000` yapılacak (WA ~5k ile eşitlenecek)
- Henüz eğitilmedi

---

**Pipeline Değişiklikleri:**
- Ubuntu statik IP: `192.168.1.100`
- Windows IP: `192.168.1.114` (her oturumda kontrol et!)
- `timeout=30` subprocess call'a eklendi (NTLFlowLyzer takılması için)
- `PACKET_COUNT = 500`
- Şu an aktif model: `multiclass_v12`

**Pipeline Başlatma:**
```bash
# Ubuntu SSH'da:
python3 ~/pipeline.py

# Windows'ta Docker (Kibana/ES):
cd C:\Users\semih\Desktop\Git_projects\Intelligent-Security
docker-compose up -d
```

---

**Medusa Testi:**
- Kali'den Medusa ile SSH Brute Force → **%100 Brute Force tespit** (Hydra gibi çalışıyor)

**Güncel Gerçek Zamanlı Tespit Sonuçları (v12 ile):**
| Saldırı | Araç | Sonuç |
|---------|------|-------|
| DDoS | hping3 --flood | ✓ DDoS tespit |
| Port Scan | nmap -sS | ✓ Port Scan tespit |
| Brute Force | Hydra / Medusa | ✓ %100 tespit |
| Web Attack | Nikto | ~%50 Web Attack, ~%50 DDoS (imbalance sorunu devam ediyor) |

---

**IP Bilgileri (2026-04-20):**
- Windows IP: `192.168.1.114`
- Ubuntu IP: `192.168.1.100` (statik)
- Kali IP: değişkenAktif

**Yapılacaklar (Session 10 sonu):**
- [x] v13 eğitildi ve deploy edildi
- [x] v14, v15 denendi (benign sorunu çözülemedi, v13'e dönüldü)
- [x] Host-Only network kuruldu (internet bağımsız demo)
- [ ] Kibana donut chart dashboard'a ekle
- [ ] Streamlit alarm ES'ten okusun
- [ ] Demo videosu
- [ ] README güncelle
- [ ] PowerPoint tamamla

---

### 2026-04-21 (Session 11 — Model v13–v15 + Host-Only Network)

**Model Geliştirme:**

**multiclass_v13** (`notebooks/16_train_multiclass_v13.ipynb`):
- DDoS cap 5.000'e düşürüldü (v12'de 10k vardı, WA hâlâ DDoS ile karışıyordu)
- Accuracy: %100 (offline)
- Gerçek zamanlı: DDoS ✓, Port Scan ✓, Web Attack ✓, Brute Force ~%75-80
- Kaydedildi: `data/models/multiclass_v13/`
- **Aktif model — bu modelle devam ediliyor**

**multiclass_v14** (`notebooks/17_train_multiclass_v14.ipynb`):
- CIC Benign 20k'ya indirildi + `benign_captures/` (gerçek pipeline benign, ~7.4k) eklendi
- **Sorun:** Her şeyi Benign tahmin etti (27k Benign vs 5k diğerleri)
- Terk edildi

**multiclass_v15** (`notebooks/18_train_multiclass_v15.ipynb`):
- CIC Benign tamamen kaldırıldı, sadece `benign_captures/` 5k cap
- CIC Port Scan kaldı, diğer tüm veriler pipeline capture'dan
- **Sorun:** Pipeline Host-Only'e geçince interface sorunu nedeniyle test edilemedi tam
- Kaydedildi: `data/models/multiclass_v15/`

**Benign Veri Toplama:**
- `collect_benign_data.sh` scripti oluşturuldu
- Ubuntu'da curl/wget/apt döngüsüyle ~106 dosya, 7.826 flow toplandı
- `data/processed/benign_captures/` klasörüne Windows'a SCP ile indirildi
- Sonuç: Benign tespiti hâlâ sorunlu — domain shift problemi devam ediyor

---

**Host-Only Network Kurulumu (Okul Sunumu İçin):**

Amaç: Okul internetine bağımlılığı kaldırmak. VirtualBox Host-Only ile internet olmadan demo yapılabilir.

**Adımlar:**
1. VirtualBox → Network Manager → Host-Only Adapter zaten mevcut: `192.168.56.1/24`
2. Ubuntu VM → Adapter 2 → Host-Only Adapter eklendi
3. Kali VM → Adapter 2 → Host-Only Adapter eklendi
4. Ubuntu `/etc/netplan/00-installer-config.yaml` güncellendi:
```yaml
enp0s8:
  dhcp4: no
  addresses:
    - 192.168.56.100/24
```
5. `sudo netplan apply` çalıştırıldı
6. Kali DHCP ile `192.168.56.101` aldı (otomatik)
7. pipeline.py INTERFACE `enp0s3` → `enp0s8` güncellendi
8. ES_HOST fallback: `192.168.56.1:9200` (Windows Host-Only IP)

**Host-Only IP Adresleri:**
- Windows (host): `192.168.56.1`
- Ubuntu: `192.168.56.100`
- Kali: `192.168.56.101`

**Bağlantı Komutları (internet olmadan):**
```bash
ssh intsec@192.168.56.100   # Ubuntu
ssh kali@192.168.56.101     # Kali
```

**Saldırı Komutları (Host-Only IP ile):**
```bash
sudo hping3 --flood -S -p 80 192.168.56.100   # DDoS
nmap -sS -p- 192.168.56.100                   # Port Scan
nikto -h http://192.168.56.100                # Web Attack
hydra -l root -P /usr/share/wordlists/rockyou.txt -t 16 -w 3 192.168.56.100 ssh  # BF
```

**Test Sonuçları (v13, Host-Only):**
| Saldırı | Araç | Sonuç |
|---------|------|-------|
| DDoS | hping3 --flood -S | ✓ DoS/DDoS |
| Port Scan | nmap -sS | ✓ Port Scan |
| Web Attack | nikto | ✓ Web Attack |
| Brute Force | hydra -t 16 | ~%75-80 Brute Force |

**Sistem Başlatma (Sunum için):**
```bash
# Windows'ta:
cd C:\Users\semih\Desktop\Git_projects\Intelligent-Security
docker-compose up -d

# Ubuntu SSH (Host-Only):
ssh intsec@192.168.56.100
python3 ~/pipeline.py

# Kibana: http://localhost:5601
```

**Yapılacaklar (Session 11 sonu):**
- [x] Kibana donut chart dashboard'a ekle
- [ ] Streamlit alarm ES'ten okusun
- [ ] Demo videosu
- [ ] README güncelle
- [ ] PowerPoint tamamla
- [ ] (Opsiyonel) Daha fazla/çeşitli BF verisi toplayıp v16 eğit

---

### 2026-04-21 (Session 12 — Kibana Dashboard + Alert + Host-Only Network Fix)

**Kibana Donut Chart:**
- Kibana → Dashboard → "INTSEC Güvenlik Paneli" oluşturuldu
- Aggregation based → Pie chart → `attack_type.keyword` Terms aggregation
- Donut modu açıldı → "Saldırı Tipi Dağılımı" olarak kaydedildi
- Dashboard'a eklendi, DDoS saldırısında %100 DoS/DDoS gösterdi ✓

**Kibana Alert Kuralları (4 adet):**
- Stack Management → Rules and Connectors → 4 Elasticsearch query rule oluşturuldu:
  - `Ddos_query`: `{"query": {"term": {"attack_type.keyword": "DoS/DDoS"}}}`
  - `Web_Attack_query`: `{"query": {"term": {"attack_type.keyword": "Web Attack"}}}`
  - `Portscan_query`: `{"query": {"term": {"attack_type.keyword": "Port Scan"}}}`
  - `Brute_Force_query`: `{"query": {"term": {"attack_type.keyword": "Brute Force"}}}`
- Her biri 1 dakikada bir çalışıyor, Server log connector ile tetikleniyor
- DDoS saldırısı sırasında `Ddos_query` **Active** durumuna geçti ✓
- Diğerleri saldırı olmadığında **Ok** durumunda

**Host-Only Network Yeniden Yapılandırma:**
- Eski Host-Only adapter DHCP server adresi (192.168.56.100) Ubuntu IP'siyle çakışıyordu
- SSH 192.168.56.100'e Windows'tan bağlanamıyordu (ping gidiyordu ama TCP timeout)
- Çözüm: Yeni VirtualBox Host-Only Adapter oluşturuldu
  - Windows adapter IP: `192.168.27.1`
  - Ubuntu netplan güncellendi: `192.168.27.100/24`
  - Kali `/etc/network/interfaces` güncellendi: `192.168.27.101/24` (statik)
- SSH artık Wi-Fi IP'si üzerinden çalışıyor: `ssh intsec@192.168.1.100`
- Host-Only SSH hâlâ sorunlu — Wi-Fi ile devam kararı alındı

**Pipeline Güncellemesi:**
- ES_HOST `192.168.56.1` → `192.168.27.1` güncellendi:
  ```bash
  sed -i 's|192.168.56.1|192.168.27.1|g' ~/pipeline.py
  ```

**Güncel IP Adresleri:**
- Windows (host): `192.168.1.126` (Wi-Fi), `192.168.27.1` (Host-Only)
- Ubuntu: `192.168.1.100` (Wi-Fi), `192.168.27.100` (Host-Only)
- Kali: `192.168.1.101` (Wi-Fi), `192.168.27.101` (Host-Only)
- SSH bağlantısı: `ssh intsec@192.168.1.100` (Wi-Fi üzerinden)

**Sistem Başlatma (Güncel):**
```bash
# Windows'ta:
docker-compose up -d

# Ubuntu SSH:
ssh intsec@192.168.1.100
sed -i 's|eski_windows_ip:9200|yeni_windows_ip:9200|g' ~/pipeline.py  # IP değiştiyse
python3 ~/pipeline.py

# Kibana: http://localhost:5601
# Streamlit: streamlit run src/dashboard/app.py
```

**Yapılacaklar:**
- [ ] Demo videosu
- [ ] README güncelle
- [ ] PowerPoint tamamla
- [ ] (Opsiyonel) v16: daha fazla/çeşitli BF verisi toplayıp eğit