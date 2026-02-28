# src/utils/logger.py

import logging
from pathlib import Path
from datetime import datetime

def setup_logger(name, log_file, level=logging.INFO):
    """Setup a logger with file handler."""
    log_path = Path('logs')
    log_path.mkdir(exist_ok=True)
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if logger.handlers:
        return logger
    
    handler = logging.FileHandler(log_path / log_file)
    handler.setLevel(level)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger

# Main system logger
main_logger = setup_logger('main', 'main.log')

# Prediction logger
prediction_logger = setup_logger('predictions', 'predictions.log')

def log_prediction(src_ip, dst_ip, attack_type, confidence, metadata=None):
    """Log a prediction with metadata."""
    log_msg = f"SRC: {src_ip} | DST: {dst_ip} | PRED: {attack_type} | CONF: {confidence:.4f}"
    
    if metadata:
        log_msg += f" | META: {metadata}"
    
    prediction_logger.info(log_msg)
    
    if attack_type != 'Benign':
        print(f"⚠️  ATTACK DETECTED: {log_msg}")

def log_system(message, level='info'):
    """Log a system message."""
    if level == 'info':
        main_logger.info(message)
    elif level == 'warning':
        main_logger.warning(message)
    elif level == 'error':
        main_logger.error(message)

if __name__ == "__main__":
    print("\n🧪 Testing Logger...")
    log_system("System started", 'info')
    log_prediction('192.168.1.100', '8.8.8.8', 'DoS/DDoS', 0.9245)
    print(f"\n✅ Test successful!")
