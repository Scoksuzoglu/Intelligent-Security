import streamlit as st
import pandas as pd
import plotly.express as px
import joblib
import json
import numpy as np

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
    
    # Gerçek label'ı sakla
    real_labels = df['label'].copy() if 'label' in df.columns else None
    
    # Feature'ları seç
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

# Başlık
st.title("🛡️ INTSEC - AI-Enhanced Cyberattack Classifier")
st.markdown("---")

# Sidebar - CSV seçimi
st.sidebar.title("⚙️ Ayarlar")
csv_files = [
    'botnet_ares.csv', 'ddos_loit.csv', 'dos_golden_eye.csv',
    'dos_hulk.csv', 'portscan.csv', 'web_brute_force.csv',
    'friday_benign.csv'
]
selected_file = st.sidebar.selectbox("📂 Veri Seti Seç", csv_files)
n_samples = st.sidebar.slider("Örnek Sayısı", 100, 1000, 300)

# Veriyi yükle ve tahmin yap
with st.spinner("Model tahmin yapıyor..."):
    try:
        df = load_and_predict(selected_file, n_samples)
        
        # Alarm
        attacks = df[df['Attack Type'] != 'Benign']
        if not attacks.empty:
            st.error(f"🚨 {len(attacks)} SALDIRI TESPİT EDİLDİ! ({selected_file})")
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
            st.metric("Ort. Güven", f"{df['Confidence'].mean():.0%}")

        st.markdown("---")

        # Tablo + Grafik
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
                        color_discrete_sequence=px.colors.qualitative.Set3)
            st.plotly_chart(fig, use_container_width=True)

        st.markdown("---")

        # İstatistik grafiği
        st.subheader("📈 Güven Skoru Dağılımı")
        fig2 = px.histogram(df, x='Confidence', color='Attack Type', nbins=20,
                           color_discrete_sequence=px.colors.qualitative.Set3)
        st.plotly_chart(fig2, use_container_width=True)

        # Export
        st.download_button(
            label="📥 CSV İndir",
            data=df.to_csv(index=False),
            file_name=f"intsec_{selected_file}",
            mime="text/csv"
        )

    except Exception as e:
        st.error(f"Hata: {e}")