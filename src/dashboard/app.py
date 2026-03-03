import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

# Sayfa ayarları
st.set_page_config(
    page_title="INTSEC - Cyberattack Classifier",
    page_icon="🛡️",
    layout="wide"
)

# Başlık
st.title("🛡️ INTSEC - AI-Enhanced Cyberattack Classifier")
st.markdown("---")

# Mock data
mock_data = {
    'Timestamp': [
        '2026-03-03 10:00:01',
        '2026-03-03 10:00:15',
        '2026-03-03 10:00:32',
        '2026-03-03 10:01:05',
        '2026-03-03 10:01:22',
        '2026-03-03 10:02:00',
        '2026-03-03 10:02:45',
        '2026-03-03 10:03:10',
    ],
    'Source IP': [
        '192.168.1.100',
        '10.0.0.50',
        '172.16.0.25',
        '192.168.1.200',
        '10.0.0.75',
        '192.168.2.10',
        '10.0.0.99',
        '172.16.0.50',
    ],
    'Destination IP': [
        '8.8.8.8',
        '192.168.1.1',
        '8.8.4.4',
        '192.168.1.1',
        '8.8.8.8',
        '192.168.1.1',
        '8.8.4.4',
        '192.168.1.1',
    ],
    'Attack Type': [
        'DDoS',
        'Benign',
        'Port Scan',
        'Brute Force',
        'Benign',
        'DoS',
        'Benign',
        'Botnet',
    ],
    'Confidence': [0.95, 0.99, 0.87, 0.91, 0.98, 0.88, 0.97, 0.93]
}

df = pd.DataFrame(mock_data)

# Alarm sistemi
attacks = df[df['Attack Type'] != 'Benign']
if not attacks.empty:
    st.error(f"🚨 {len(attacks)} SALDIRI TESPİT EDİLDİ!")
else:
    st.success("✅ Sistem normal, saldırı yok.")

st.markdown("---")

# Üst metrikler
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Toplam Trafik", len(df))
with col2:
    st.metric("Saldırı Sayısı", len(attacks))
with col3:
    st.metric("Benign Trafik", len(df[df['Attack Type'] == 'Benign']))
with col4:
    avg_conf = df['Confidence'].mean()
    st.metric("Ort. Güven", f"{avg_conf:.0%}")

st.markdown("---")

# İki kolon: tablo + grafik
col_left, col_right = st.columns(2)

with col_left:
    st.subheader("📋 Son Tahminler")
    # Saldırıları kırmızı göster
    def highlight_attacks(row):
        if row['Attack Type'] != 'Benign':
            return ['background-color: #ffcccc'] * len(row)
        return [''] * len(row)
    
    st.dataframe(
        df.style.apply(highlight_attacks, axis=1),
        use_container_width=True
    )

with col_right:
    st.subheader("📊 Saldırı Tipi Dağılımı")
    attack_counts = df['Attack Type'].value_counts().reset_index()
    attack_counts.columns = ['Attack Type', 'Count']
    fig = px.pie(
        attack_counts,
        values='Count',
        names='Attack Type',
        color_discrete_sequence=px.colors.qualitative.Set3
    )
    st.plotly_chart(fig, use_container_width=True)

# CSV export
st.markdown("---")
st.download_button(
    label="📥 CSV İndir",
    data=df.to_csv(index=False),
    file_name="intsec_predictions.csv",
    mime="text/csv"
)