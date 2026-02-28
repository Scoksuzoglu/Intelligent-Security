# src/inference/preprocessor.py

import pandas as pd
import numpy as np
from pathlib import Path
import json
import sys
sys.path.append('.')
from src.utils.logger import log_system

class DataPreprocessor:
    """
    Preprocess NTFlowLyzer CSV output for model inference.
    """
    
    def __init__(self, model_dir='models/multiclass_v1'):
        """Load feature names and metadata columns."""
        self.model_dir = Path(model_dir)
        
        # Load feature names (top 30)
        feature_path = self.model_dir / 'feature_names.json'
        if not feature_path.exists():
            raise FileNotFoundError(f"Feature names not found: {feature_path}")
        
        with open(feature_path, 'r') as f:
            self.feature_names = json.load(f)
        
        log_system(f"Feature names loaded: {len(self.feature_names)} features", 'info')
        
        # Load metadata columns
        metadata_path = self.model_dir / 'metadata_columns.json'
        if not metadata_path.exists():
            raise FileNotFoundError(f"Metadata columns not found: {metadata_path}")
        
        with open(metadata_path, 'r') as f:
            self.metadata_cols = json.load(f)
        
        log_system(f"Metadata columns loaded: {self.metadata_cols}", 'info')
        
        print(f"✅ DataPreprocessor initialized")
        print(f"   Feature count: {len(self.feature_names)}")
        print(f"   Metadata columns: {self.metadata_cols}")
    
    def process(self, df):
        """Process NTFlowLyzer CSV output."""
        log_system(f"Preprocessing started - Input shape: {df.shape}", 'info')
        
        print(f"\n🔄 Preprocessing data...")
        print(f"  Input shape: {df.shape}")
        
        # 1. Separate metadata
        metadata_df = None
        if all(col in df.columns for col in self.metadata_cols):
            metadata_df = df[self.metadata_cols].copy()
            log_system(f"Metadata extracted: {metadata_df.shape}", 'info')
        else:
            log_system("Some metadata columns missing, metadata will be None", 'warning')
        
        # 2. Drop metadata columns
        df_clean = df.drop(columns=self.metadata_cols, errors='ignore')
        
        # 3. Handle missing values
        missing_count = df_clean.isnull().sum().sum()
        if missing_count > 0:
            print(f"  ⚠️  Found {missing_count} missing values, filling with 0")
            log_system(f"Missing values found: {missing_count}, filling with 0", 'warning')
            df_clean = df_clean.fillna(0)
        
        # 4. Handle infinite values
        numeric_cols = df_clean.select_dtypes(include=[np.number]).columns
        inf_count = np.isinf(df_clean[numeric_cols]).sum().sum()
        if inf_count > 0:
            print(f"  ⚠️  Found {inf_count} infinite values, replacing with 0")
            log_system(f"Infinite values found: {inf_count}, replacing with 0", 'warning')
            df_clean = df_clean.replace([np.inf, -np.inf], 0)
        
        # 5. Check if all required features are present
        missing_features = set(self.feature_names) - set(df_clean.columns)
        if missing_features:
            error_msg = f"Missing required features: {missing_features}"
            log_system(error_msg, 'error')
            raise ValueError(error_msg)
        
        # 6. Select top 30 features
        df_features = df_clean[self.feature_names].copy()
        
        log_system(f"Preprocessing complete - Output shape: {df_features.shape}", 'info')
        
        print(f"✅ Preprocessing complete!")
        print(f"  Output shape: {df_features.shape}")
        
        return df_features, metadata_df
    
    def process_csv(self, csv_path):
        """Process CSV file directly."""
        log_system(f"Loading CSV: {csv_path}", 'info')
        
        print(f"\n📂 Loading CSV: {csv_path}")
        
        csv_path = Path(csv_path)
        if not csv_path.exists():
            raise FileNotFoundError(f"CSV not found: {csv_path}")
        
        df = pd.read_csv(csv_path)
        
        return self.process(df)


# Test function
if __name__ == "__main__":
    print("\n🧪 Testing DataPreprocessor...")
    
    try:
        preprocessor = DataPreprocessor()
        
        # Create dummy data
        print("\n📝 Creating dummy data...")
        
        dummy_cols = preprocessor.metadata_cols + preprocessor.feature_names + ['extra_col1', 'extra_col2']
        
        dummy_data = pd.DataFrame(
            np.random.rand(5, len(dummy_cols)),
            columns=dummy_cols
        )
        
        # Add string data to metadata columns
        dummy_data['flow_id'] = [f'flow_{i}' for i in range(5)]
        dummy_data['src_ip'] = ['192.168.1.100', '192.168.1.101', '192.168.1.102', '10.0.0.5', '172.16.0.1']
        dummy_data['dst_ip'] = ['8.8.8.8', '1.1.1.1', '8.8.4.4', '192.168.1.1', '10.0.0.1']
        dummy_data['timestamp'] = [f'2026-02-28 10:0{i}:00' for i in range(5)]
        dummy_data['protocol'] = ['TCP', 'UDP', 'TCP', 'TCP', 'UDP']
        
        print(f"  Dummy data shape: {dummy_data.shape}")
        
        # Process
        features, metadata = preprocessor.process(dummy_data)
        
        print(f"\n✅ Test successful!")
        print(f"  Features shape: {features.shape}")
        print(f"  Metadata shape: {metadata.shape if metadata is not None else 'None'}")
        print(f"\n📊 Sample output:")
        print(f"  Features (first 3 columns):")
        print(features.iloc[:, :3])
        print(f"\n  Metadata:")
        print(metadata)
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
