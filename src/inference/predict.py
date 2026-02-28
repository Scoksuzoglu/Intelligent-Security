# src/inference/predict.py

import joblib
import pandas as pd
import numpy as np
from pathlib import Path
import json

class ModelPredictor:
    """
    Multi-class cyberattack prediction model.
    Uses top 30 features selected from Random Forest feature importance.
    """
    
    def __init__(self, model_dir='models/multiclass_v1'):
        """
        Load model, scaler, and metadata.
        
        Args:
            model_dir (str): Path to model directory
        """
        self.model_dir = Path(model_dir)
        
        # Load model
        model_path = self.model_dir / 'model.joblib'
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        self.model = joblib.load(model_path)
        print(f"✅ Model loaded: {model_path}")
        
        # Load scaler
        scaler_path = self.model_dir / 'scaler.joblib'
        if not scaler_path.exists():
            raise FileNotFoundError(f"Scaler not found: {scaler_path}")
        
        self.scaler = joblib.load(scaler_path)
        print(f"✅ Scaler loaded: {scaler_path}")
        
        # Load feature names
        feature_path = self.model_dir / 'feature_names.json'
        if not feature_path.exists():
            raise FileNotFoundError(f"Feature names not found: {feature_path}")
        
        with open(feature_path, 'r') as f:
            self.feature_names = json.load(f)
        print(f"✅ Feature names loaded: {len(self.feature_names)} features")
        
        # Load metadata
        metadata_path = self.model_dir / 'metadata.json'
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                self.metadata = json.load(f)
        else:
            self.metadata = {}
        
        # Class names
        self.class_names = {
            0: 'Benign',
            1: 'DoS/DDoS',
            2: 'Web Attack',
            3: 'Port Scan',
            4: 'Brute Force',
            5: 'Botnet'
        }
        
        print(f"✅ ModelPredictor initialized")
        print(f"   Model version: {self.metadata.get('version', 'unknown')}")
        print(f"   Accuracy: {self.metadata.get('test_accuracy_selected', 0):.4f}")
    
    def predict(self, df):
        """
        Predict attack types from preprocessed features.
        
        Args:
            df (pd.DataFrame): Preprocessed features (30 columns)
        
        Returns:
            dict: Predictions with attack types and confidence scores
        """
        # Validate input
        if not isinstance(df, pd.DataFrame):
            raise ValueError("Input must be a pandas DataFrame")
        
        # Check feature count
        if df.shape[1] != len(self.feature_names):
            raise ValueError(f"Expected {len(self.feature_names)} features, got {df.shape[1]}")
        
        # Ensure correct feature order
        df = df[self.feature_names]
        
        # Scale features
        X_scaled = self.scaler.transform(df)
        
        # Predict
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        # Get confidence (max probability)
        confidence = probabilities.max(axis=1)
        
        # Convert to attack types
        attack_types = [self.class_names[pred] for pred in predictions]
        
        return {
            'predictions': predictions.tolist(),
            'attack_types': attack_types,
            'confidence': confidence.tolist(),
            'probabilities': probabilities.tolist()
        }
    
    def predict_single(self, features_dict):
        """
        Predict single sample from feature dictionary.
        
        Args:
            features_dict (dict): Feature dictionary
        
        Returns:
            dict: Single prediction result
        """
        # Convert to DataFrame
        df = pd.DataFrame([features_dict])
        
        # Predict
        result = self.predict(df)
        
        # Return single result
        return {
            'prediction': result['predictions'][0],
            'attack_type': result['attack_types'][0],
            'confidence': result['confidence'][0],
            'probabilities': result['probabilities'][0]
        }


# Test function
if __name__ == "__main__":
    print("\n🧪 Testing ModelPredictor...")
    
    try:
        # Initialize predictor
        predictor = ModelPredictor()
        
        # Create dummy data (30 features)
        print("\n📝 Creating dummy data...")
        dummy_data = pd.DataFrame(
            np.random.rand(5, 30),
            columns=predictor.feature_names
        )
        
        print(f"  Dummy data shape: {dummy_data.shape}")
        
        # Predict
        print("\n🔮 Making predictions...")
        results = predictor.predict(dummy_data)
        
        print(f"\n✅ Predictions successful!")
        print(f"\n📊 Results:")
        for i in range(len(results['attack_types'])):
            print(f"  Sample {i+1}: {results['attack_types'][i]} (confidence: {results['confidence'][i]:.4f})")
        
        # Test single prediction
        print(f"\n🔮 Testing single prediction...")
        single_features = {col: np.random.rand() for col in predictor.feature_names}
        single_result = predictor.predict_single(single_features)
        
        print(f"  ✅ Single prediction: {single_result['attack_type']} (confidence: {single_result['confidence']:.4f})")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
