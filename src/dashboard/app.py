import streamlit as st
import pandas as pd
import plotly.express as px
import joblib
import json
import numpy as np

from src.dashboard.elasticsearch_reader import (
    fetch_predictions, fetch_last_n_minutes,
    get_attack_summary, get_total_count, is_connected
)

# Sayfa ayarları
st.set_page_config(
    page_title="INTSEC - Cyberattack Classifier",
    page_icon="🛡️",
    layout="wide"
)

# Model ve feature bilgilerini yükle
@st.cache_resource
def load_model():
    model = joblib.load('data/models/multiclass_v1/model.joblib')
    scaler = joblib.load('data/models/multiclass_v1/scaler.joblib')
    with open('data/models/multiclass_v1/feature_names.json') as f:
        features = json.load(f)
    with open('data/models/multiclass_v1/metadata.json') as f:
        metadata = json.load(f)
    return model, scaler, features, metadata

@st.cache_data
def load_and_predict(csv_file, n_samples=500):
    model, scaler, features, metadata = load_model()
    df = pd.read_csv(f'data/processed/{csv_file}')
    df = df.sample(min(n_samples, len(df)), random_state=42)

    real_labels = df['label'].copy() if 'label' in df.columns else None

    X = df[features].fillna(0).replace([np.inf, -np.inf], 0)
    X_scaled = scaler.transform(X)

    preds = model.predict(X_scaled)
    probs = model.predict_proba(X_scaled)
    confidence = probs.max(axis=1)

    classes = metadata.get('class_names', {})
    if isinstance(list(classes.keys())[0], str):
        attack_types = [classes[str(p)] for p in preds]
    else:
        attack_types = [classes[p] for p in preds]

    result = df[['src_ip', 'dst_ip', 'src_port', 'dst_port', 'timestamp']].copy()
    result['Attack Type'] = attack_types
    result['Confidence'] = confidence.round(3)
    result.columns = ['Source IP', 'Dest IP', 'Src Port', 'Dst Port', 'Timestamp', 'Attack Type', 'Confidence']
    return result


def render_dashboard(df, source_label=""):
    """Ortak dashboard bileşenlerini render eder."""
    attacks = df[df['Attack Type'] != 'Benign']

    # Alarm banner
    if not attacks.empty:
        st.error(f"🚨 {len(attacks)} SALDIRI TESPİT EDİLDİ! {source_label}")
    else:
        st.success("✅ Sistem normal, saldırı tespit edilmedi.")

    # Metrikler
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Toplam Trafik", len(df))
    with col2:
        st.metric("Saldırı Sayısı", len(attacks))
    with col3:
        st.metric("Benign Trafik", len(df[df['Attack Type'] == 'Benign']))
    with col4:
        avg_conf = df['Confidence'].mean() if 'Confidence' in df.columns else 0
        st.metric("Ort. Güven", f"{avg_conf:.0%}")

    st.markdown("---")

    # Tablo + Pie Chart
    col_left, col_right = st.columns(2)
    with col_left:
        st.subheader("📋 Son Tahminler")
        def highlight_attacks(row):
            if row['Attack Type'] != 'Benign':
                return ['background-color: #ffcccc'] * len(row)
            return [''] * len(row)
        st.dataframe(df.style.apply(highlight_attacks, axis=1), use_container_width=True)

    with col_right:
        st.subheader("📊 Saldırı Tipi Dağılımı")
        attack_counts = df['Attack Type'].value_counts().reset_index()
        attack_counts.columns = ['Attack Type', 'Count']
        fig = px.pie(attack_counts, values='Count', names='Attack Type',
                     hole=0.4,
                     color_discrete_sequence=px.colors.qualitative.Set3)
        fig.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")

    # Güven skoru histogramı
    st.subheader("📈 Güven Skoru Dağılımı")
    fig2 = px.histogram(df, x='Confidence', color='Attack Type', nbins=20,
                        color_discrete_sequence=px.colors.qualitative.Set3)
    st.plotly_chart(fig2, use_container_width=True)

    # CSV export
    st.download_button(
        label="📥 CSV İndir",
        data=df.to_csv(index=False),
        file_name="intsec_predictions.csv",
        mime="text/csv"
    )


# ── Başlık ──────────────────────────────────────────────────────────────────
st.title("🛡️ INTSEC - AI-Enhanced Cyberattack Classifier")
st.markdown("---")

# ── Sidebar ─────────────────────────────────────────────────────────────────
st.sidebar.title("⚙️ Ayarlar")

es_ok = is_connected()
es_status = "🟢 Bağlı" if es_ok else "🔴 Bağlı Değil"
st.sidebar.markdown(f"**Elasticsearch:** {es_status}")
st.sidebar.markdown("---")

mode = st.sidebar.radio(
    "📡 Mod Seç",
    ["🔴 Canlı (Elasticsearch)", "📂 CSV Analiz"],
    index=0 if es_ok else 1
)

# ── Canlı Mod ────────────────────────────────────────────────────────────────
if mode == "🔴 Canlı (Elasticsearch)":
    st.sidebar.markdown("---")
    time_window = st.sidebar.selectbox(
        "⏱️ Zaman Aralığı",
        ["Son 15 dk", "Son 1 saat", "Son 6 saat", "Tümü"],
        index=1
    )
    limit = st.sidebar.slider("Maksimum Kayıt", 100, 2000, 500)

    if st.sidebar.button("🔄 Yenile"):
        st.cache_data.clear()

    st.subheader("🔴 Canlı Trafik İzleme")

    if not es_ok:
        st.warning("⚠️ Elasticsearch'e bağlanılamadı. Docker çalışıyor mu?\n\n`docker-compose up -d`")
    else:
        total_in_es = get_total_count()
        st.caption(f"Elasticsearch'te toplam {total_in_es:,} kayıt var.")

        with st.spinner("Elasticsearch'ten veri çekiliyor..."):
            if time_window == "Tümü":
                df = fetch_predictions(limit=limit)
            elif time_window == "Son 15 dk":
                df = fetch_last_n_minutes(minutes=15, limit=limit)
            elif time_window == "Son 1 saat":
                df = fetch_last_n_minutes(minutes=60, limit=limit)
            else:
                df = fetch_last_n_minutes(minutes=360, limit=limit)

        if df is None:
            st.error("Elasticsearch'ten veri çekilemedi.")
        elif df.empty:
            st.info("Seçilen zaman aralığında kayıt yok. File watcher çalışıyor mu?")
        else:
            render_dashboard(df, source_label=f"({time_window})")

# ── CSV Analiz Modu ──────────────────────────────────────────────────────────
else:
    st.sidebar.markdown("---")
    csv_files = [
        'botnet_ares.csv', 'ddos_loit.csv', 'dos_golden_eye.csv',
        'dos_hulk.csv', 'portscan.csv', 'web_brute_force.csv',
        'friday_benign.csv'
    ]
    selected_file = st.sidebar.selectbox("📂 Veri Seti Seç", csv_files)
    n_samples = st.sidebar.slider("Örnek Sayısı", 100, 1000, 300)

    st.subheader(f"📂 CSV Analiz: {selected_file}")

    with st.spinner("Model tahmin yapıyor..."):
        try:
            df = load_and_predict(selected_file, n_samples)
            render_dashboard(df, source_label=f"({selected_file})")
        except Exception as e:
            st.error(f"Hata: {e}")