"""
Training Pipeline for SafeSurf Machine Learning Engine
Trains high-accuracy Random Forest, Extra Trees, and Gradient Boosting models,
evaluates cross-validation, and serializes the model into a zero-dependency JSON format.
"""

import os
import sys
import json
import csv
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, train_test_split, cross_validate
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report

from feature_extractor import extract_feature_vector, FEATURE_NAMES
from dataset_builder import build_dataset

def export_random_forest_to_json(rf_model, feature_names, metrics, output_path):
    """
    Serializes a scikit-learn RandomForestClassifier into an ultra-compact,
    human-readable JSON file for zero-latency JavaScript inference.
    """
    trees_json = []
    
    for estimator in rf_model.estimators_:
        tree_ = estimator.tree_
        
        def recurse(node_id):
            if tree_.feature[node_id] != -2:  # Not a leaf
                feature_idx = int(tree_.feature[node_id])
                threshold = float(tree_.threshold[node_id])
                left_child = recurse(int(tree_.children_left[node_id]))
                right_child = recurse(int(tree_.children_right[node_id]))
                return {
                    'f': feature_idx,
                    't': round(threshold, 6),
                    'l': left_child,
                    'r': right_child
                }
            else:
                # Leaf node: value distribution
                values = [float(v) for v in tree_.value[node_id][0]]
                total = sum(values)
                probs = [round(v / max(1e-9, total), 6) for v in values]
                return {'v': probs}
                
        trees_json.append(recurse(0))

    feature_importances = {
        name: round(float(imp), 6)
        for name, imp in zip(feature_names, rf_model.feature_importances_)
    }
    # Sort by importance
    sorted_importances = dict(sorted(feature_importances.items(), key=lambda item: item[1], reverse=True))

    model_payload = {
        'version': '3.0.0',
        'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'algorithm': 'RandomForestClassifier (Ensemble Decision Trees)',
        'classes': ['safe', 'malicious', 'suspicious'],
        'n_features': len(feature_names),
        'feature_names': feature_names,
        'feature_importances': sorted_importances,
        'metrics': metrics,
        'trees': trees_json
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(model_payload, f, separators=(',', ':'))

    print(f"Exported serialized model with {len(trees_json)} decision trees to {output_path}")
    return model_payload

def run_training():
    print("=" * 70)
    print("🚀 SafeSurf Machine Learning Model Training & Optimization Pipeline")
    print("=" * 70)

    dataset_path = 'ml/data/training_dataset.csv'
    if not os.path.exists(dataset_path):
        build_dataset(dataset_path)

    print(f"\n📂 Loading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)
    print(f"Total dataset records: {len(df)}")
    print(df['label'].value_counts())

    print("\n🔍 Extracting 40 multi-dimensional feature vectors...")
    start_feat = time.time()
    X = []
    y = []
    
    # Mapping: 0: safe, 1: malicious, 2: suspicious
    label_map = {'safe': 0, 'malicious': 1, 'suspicious': 2}

    for idx, row in df.iterrows():
        url = str(row['url'])
        label_str = str(row['label']).strip().lower()
        if label_str not in label_map:
            continue
        vec = extract_feature_vector(url)
        X.append(vec)
        y.append(label_map[label_str])

    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int32)
    feat_time = time.time() - start_feat
    print(f"Feature extraction completed in {feat_time:.2f}s ({len(X)} samples, {X.shape[1]} features)")

    # 1. Stratified Train/Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"\nTrain set: {len(X_train)} samples | Test set: {len(X_test)} samples")

    # 2. Cross-Validation Comparison
    print("\n📊 Performing 5-Fold Stratified Cross-Validation on Candidate Models...")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )

    et = ExtraTreesClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=4,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )

    gb = GradientBoostingClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=6,
        random_state=42
    )

    models = {
        'Random Forest': rf,
        'Extra Trees': et,
        'Gradient Boosting': gb
    }

    scoring = ['accuracy', 'precision_macro', 'recall_macro', 'f1_macro']

    for name, model in models.items():
        cv_res = cross_validate(model, X_train, y_train, cv=skf, scoring=scoring, n_jobs=-1)
        print(f"\nModel: {name}")
        print(f"  CV Accuracy:  {cv_res['test_accuracy'].mean() * 100:.2f}% (± {cv_res['test_accuracy'].std() * 100:.2f}%)")
        print(f"  CV Precision: {cv_res['test_precision_macro'].mean() * 100:.2f}%")
        print(f"  CV Recall:    {cv_res['test_recall_macro'].mean() * 100:.2f}%")
        print(f"  CV F1-Score:  {cv_res['test_f1_macro'].mean() * 100:.2f}%")

    # 3. Fit Best Final Model (Random Forest for robust zero-latency tree compilation)
    print("\n🎯 Training Production Ensemble Random Forest Model...")
    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    y_prob = rf.predict_proba(X_test)

    # Compute comprehensive test metrics
    acc = accuracy_score(y_test, y_pred)
    prec_macro = precision_score(y_test, y_pred, average='macro')
    rec_macro = recall_score(y_test, y_pred, average='macro')
    f1_macro = f1_score(y_test, y_pred, average='macro')
    
    # Binary threat vs safe ROC-AUC (Safe=0, Threat={1,2})
    y_test_binary = (y_test != 0).astype(int)
    prob_threat = 1.0 - y_prob[:, 0]
    roc_auc = roc_auc_score(y_test_binary, prob_threat)
    cm = confusion_matrix(y_test, y_pred).tolist()

    print("\n" + "=" * 70)
    print("📈 FINAL HOLDOUT TEST EVALUATION RESULTS:")
    print("=" * 70)
    print(f"  Accuracy:      {acc * 100:.2f}%")
    print(f"  Precision:     {prec_macro * 100:.2f}%")
    print(f"  Recall:        {rec_macro * 100:.2f}%")
    print(f"  F1-Score:      {f1_macro * 100:.2f}%")
    print(f"  Threat ROC-AUC:{roc_auc * 100:.2f}%")
    print("\nConfusion Matrix [Safe, Malicious, Suspicious]:")
    for row in cm:
        print(f"  {row}")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Malicious', 'Suspicious']))

    metrics = {
        'accuracy': round(float(acc), 4),
        'precision': round(float(prec_macro), 4),
        'recall': round(float(rec_macro), 4),
        'f1_score': round(float(f1_macro), 4),
        'roc_auc': round(float(roc_auc), 4),
        'confusion_matrix': cm,
        'test_samples': len(y_test),
        'train_samples': len(y_train)
    }

    # 4. Serialize to backend and extension
    backend_model_path = 'backend/data/model_data.json'
    export_random_forest_to_json(rf, FEATURE_NAMES, metrics, backend_model_path)

    extension_model_path = 'extension/model_data.json'
    export_random_forest_to_json(rf, FEATURE_NAMES, metrics, extension_model_path)

    print("\n✅ Training and JSON compilation complete! All targets achieved.")
    return metrics

if __name__ == '__main__':
    # Ensure current directory in sys.path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    run_training()
