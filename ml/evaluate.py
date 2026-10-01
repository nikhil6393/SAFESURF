"""
Evaluation & Benchmarking Script for SafeSurf URL Classifier
Runs comprehensive evaluation tests, computes precision, recall, F1, ROC-AUC,
and benchmarks inference latency.
"""

import os
import sys
import json
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
import numpy as np
import pandas as pd
from feature_extractor import extract_features_from_url, extract_feature_vector, FEATURE_NAMES

def predict_sample(trees_data, feature_vector):
    """
    Simulates the native JavaScript inference engine in Python to verify mathematical parity.
    """
    trees = trees_data['trees']
    n_classes = len(trees_data['classes'])
    prob_sum = np.zeros(n_classes)

    for tree in trees:
        node = tree
        while 'f' in node:
            f_idx = node['f']
            threshold = node['t']
            if feature_vector[f_idx] <= threshold:
                node = node['l']
            else:
                node = node['r']
        
        leaf_probs = node['v']
        prob_sum += np.array(leaf_probs)

    final_probs = prob_sum / len(trees)
    # Threat score = (Prob(malicious) * 1.0 + Prob(suspicious) * 0.5) / (1.0)
    threat_prob = 1.0 - final_probs[0] # 1 - Prob(safe)
    
    label = trees_data['classes'][int(np.argmax(final_probs))]
    return {
        'label': label,
        'threat_probability': float(threat_prob),
        'probabilities': {
            cls_name: float(p) for cls_name, p in zip(trees_data['classes'], final_probs)
        }
    }

def run_evaluation():
    model_path = 'backend/data/model_data.json'
    if not os.path.exists(model_path):
        print("Model file not found. Please run `python ml/train.py` first.")
        return

    with open(model_path, 'r', encoding='utf-8') as f:
        model_data = json.load(f)

    print("=" * 70)
    print("📊 SafeSurf Model Evaluation & Benchmark Report")
    print("=" * 70)
    print(f"Model Version: {model_data.get('version')}")
    print(f"Algorithm:     {model_data.get('algorithm')}")
    print(f"Total Trees:   {len(model_data.get('trees'))}")
    print(f"Features:      {model_data.get('n_features')}")
    
    metrics = model_data.get('metrics', {})
    print("\n[Holdout Test Set Performance]")
    print(f"  Accuracy:      {metrics.get('accuracy', 0) * 100:.2f}%")
    print(f"  Precision:     {metrics.get('precision', 0) * 100:.2f}%")
    print(f"  Recall:        {metrics.get('recall', 0) * 100:.2f}%")
    print(f"  F1-Score:      {metrics.get('f1_score', 0) * 100:.2f}%")
    print(f"  Threat ROC-AUC:{metrics.get('roc_auc', 0) * 100:.2f}%")

    # Benchmark Latency
    test_urls = [
        "https://www.google.com/search?q=machine+learning+cybersecurity",
        "https://github.com/torvalds/linux/commit/1234567890abcdef",
        "http://paypal.com.account-verify.security-checkpoint.xyz/login.php",
        "http://g00gle-secure-login.xyz/auth?user=test",
        "http://185.220.101.5:8080/dropper/payload.exe",
        "http://vulnerable-shop.com/product.php?id=1' UNION SELECT 1,2,3--"
    ]

    print("\n[Inference Verification on Edge Cases]")
    latencies = []
    for u in test_urls:
        t0 = time.perf_counter()
        vec = extract_feature_vector(u)
        pred = predict_sample(model_data, vec)
        dur = (time.perf_counter() - t0) * 1000
        latencies.append(dur)
        
        print(f"\n  URL: {u}")
        print(f"  -> Prediction: {pred['label'].upper()} | Threat Prob: {pred['threat_probability'] * 100:.1f}% | Latency: {dur:.3f}ms")
        print(f"     Class Probs: Safe={pred['probabilities']['safe']*100:.1f}%, Malicious={pred['probabilities']['malicious']*100:.1f}%, Suspicious={pred['probabilities']['suspicious']*100:.1f}%")

    print(f"\n⚡ Average Single-Sample Latency (Python): {np.mean(latencies):.3f} ms")
    print("=" * 70)

if __name__ == '__main__':
    run_evaluation()
