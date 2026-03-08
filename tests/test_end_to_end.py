import sys
sys.path.append('.')

from src.extractor.pcap_processor import PCAPProcessor
from src.inference.preprocessor import DataPreprocessor
from src.inference.predict import ModelPredictor
from src.utils.logger import log_system, log_prediction
import pandas as pd

def test_full_pipeline(pcap_file):
    """
    Test complete pipeline:
    PCAP → CSV → Preprocess → Predict → Log
    """
    print("\n" + "="*60)
    print("🧪 INTSEC END-TO-END TEST")
    print("="*60)
    
    # Step 1: PCAP → CSV (Veysel)
    print("\n📂 STEP 1: PCAP Processing (Veysel Kan)")
    csv_file = "data/processed/test_flow.csv"
    processor = PCAPProcessor()
    processor.process_pcap(pcap_file, csv_file)
    log_system(f"PCAP processed: {csv_file}", 'info')
    
    # Step 2: CSV → Preprocessed Features (Semih İkbal)
    print("\n🔄 STEP 2: Data Preprocessing (Semih İkbal)")
    preprocessor = DataPreprocessor()
    features, metadata = preprocessor.process_csv(csv_file)
    log_system(f"Features extracted: {features.shape}", 'info')
    
    # Step 3: Features → Predictions (Semih İkbal + Semih Öksüzoğlu)
    print("\n🔮 STEP 3: Model Prediction (Semih Öksüzoğlu)")
    predictor = ModelPredictor()
    results = predictor.predict(features)
    log_system(f"Predictions made: {len(results['attack_types'])}", 'info')
    
    # Step 4: Log Results (Semih İkbal)
    print("\n📝 STEP 4: Logging Results")
    
    for i in range(min(len(results['attack_types']), len(metadata) if metadata is not None else 0)):
        if metadata is not None:
            log_prediction(
                src_ip=metadata.iloc[i]['src_ip'],
                dst_ip=metadata.iloc[i]['dst_ip'],
                attack_type=results['attack_types'][i],
                confidence=results['confidence'][i]
            )
    
    # Summary
    print("\n" + "="*60)
    print("✅ END-TO-END TEST COMPLETE!")
    print("="*60)
    print(f"\n📊 RESULTS SUMMARY:")
    print(f"  Total Flows: {len(results['attack_types'])}")
    print(f"  Attack Types Detected:")
    
    attack_counts = pd.Series(results['attack_types']).value_counts()
    for attack, count in attack_counts.items():
        print(f"    - {attack}: {count}")
    
    avg_conf = sum(results['confidence'])/len(results['confidence'])
    print(f"\n  Average Confidence: {avg_conf:.4f}")
    print(f"  Logs saved: logs/predictions.log")
    print("\n✅ ALL MODULES WORKING TOGETHER!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUsage: python tests/test_end_to_end.py <pcap_file>")
        print("\nExample:")
        print("  python tests/test_end_to_end.py data/pcap/test.pcap")
    else:
        test_full_pipeline(sys.argv[1])
