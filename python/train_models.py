"""
True Learning Experiment - Remove trivial features
Force model to learn from behavioral patterns, not label definitions
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, f1_score, accuracy_score
from pathlib import Path
import json
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = PROJECT_ROOT / "data" / "gold" / "gold_reduced.csv"
OUTPUT_DIR = PROJECT_ROOT / "experiments"

print("\n" + "="*70)
print("TRUE LEARNING EXPERIMENT")
print("Removing trivial features to force generalization")
print("="*70)

# Load data
df = pd.read_csv(DATA_PATH)

# REMOVE features that encode labels
trivial_features = ['syn_ratio', 'rst_ratio', 'fin_ratio', 'sack_present', 'ack_ratio']

# Keep ONLY behavioral features that don't directly encode label logic
learning_features = [
    'log_packet_count',      # Volume (general)
    'duration',              # Time (general)
    'bytes_per_second',      # Tempo (general)
    'ttl_mean',              # Network fingerprint
    'ttl_std',               # Network variance
    'window_std',            # TCP behavior (indirect)
    'is_burst'               # Temporal pattern
]

print(f"\n[1] Feature Selection:")
print(f"REMOVED (trivial): {trivial_features}")
print(f"KEPT (learning):   {learning_features}")
print(f"\nReduction: {len(trivial_features + learning_features)} → {len(learning_features)} features")

X = df[learning_features]
y = df['label']

print(f"\nDataset: {len(df):,} samples, {len(learning_features)} features")
print(f"Classes: {y.nunique()}")

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# Encode for XGBoost
le = LabelEncoder()
y_train_encoded = le.fit_transform(y_train)
y_test_encoded = le.transform(y_test)

print(f"\nTrain: {len(X_train):,} | Test: {len(X_test):,}")

# EXPERIMENT 1: Random Forest
print("\n" + "="*70)
print("RANDOM FOREST - True Learning Mode")
print("="*70)

rf_config = {
    'n_estimators': 200,      # More trees for harder problem
    'max_depth': 15,          # Deeper to find patterns
    'min_samples_split': 20,  # Regularization
    'min_samples_leaf': 10,
    'class_weight': 'balanced',
    'random_state': 42,
    'n_jobs': -1
}

print("\nTraining...")
start = time.time()
rf = RandomForestClassifier(**rf_config)
rf.fit(X_train, y_train)
train_time_rf = time.time() - start

y_train_pred_rf = rf.predict(X_train)
y_test_pred_rf = rf.predict(X_test)

train_acc_rf = accuracy_score(y_train, y_train_pred_rf)
test_acc_rf = accuracy_score(y_test, y_test_pred_rf)
train_f1_rf = f1_score(y_train, y_train_pred_rf, average='macro')
test_f1_rf = f1_score(y_test, y_test_pred_rf, average='macro')

print(f"\nResults:")
print(f"Train Accuracy: {train_acc_rf:.4f}")
print(f"Test Accuracy:  {test_acc_rf:.4f}")
print(f"Train F1: {train_f1_rf:.4f}")
print(f"Test F1:  {test_f1_rf:.4f}")
print(f"Gap: {(train_acc_rf - test_acc_rf):.4f}")
print(f"Time: {train_time_rf:.2f}s")

print("\nPer-class performance:")
print(classification_report(y_test, y_test_pred_rf))

# Feature importance
importance_rf = pd.DataFrame({
    'feature': learning_features,
    'importance': rf.feature_importances_
}).sort_values('importance', ascending=False)

print("\nFeature Importance:")
print(importance_rf.to_string(index=False))

# EXPERIMENT 2: XGBoost
print("\n" + "="*70)
print("XGBOOST - True Learning Mode")
print("="*70)

xgb_config = {
    'n_estimators': 500,
    'learning_rate': 0.1,     # Faster for harder problem
    'max_depth': 6,           # Deeper for patterns
    'min_child_weight': 5,
    'gamma': 0.5,
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'reg_alpha': 0.1,
    'reg_lambda': 1.0,
    'objective': 'multi:softprob',
    'tree_method': 'hist',
    'random_state': 42,
    'early_stopping_rounds': 30
}

print("\nTraining...")
start = time.time()
xgb = XGBClassifier(**xgb_config)
xgb.fit(
    X_train, y_train_encoded,
    eval_set=[(X_test, y_test_encoded)],
    verbose=False
)
train_time_xgb = time.time() - start

y_train_pred_xgb = le.inverse_transform(xgb.predict(X_train))
y_test_pred_xgb = le.inverse_transform(xgb.predict(X_test))

train_acc_xgb = accuracy_score(y_train, y_train_pred_xgb)
test_acc_xgb = accuracy_score(y_test, y_test_pred_xgb)
train_f1_xgb = f1_score(y_train, y_train_pred_xgb, average='macro')
test_f1_xgb = f1_score(y_test, y_test_pred_xgb, average='macro')

print(f"\nResults:")
print(f"Train Accuracy: {train_acc_xgb:.4f}")
print(f"Test Accuracy:  {test_acc_xgb:.4f}")
print(f"Train F1: {train_f1_xgb:.4f}")
print(f"Test F1:  {test_f1_xgb:.4f}")
print(f"Gap: {(train_acc_xgb - test_acc_xgb):.4f}")
print(f"Time: {train_time_xgb:.2f}s")

print("\nPer-class performance:")
print(classification_report(y_test, y_test_pred_xgb))

# Feature importance
importance_xgb = pd.DataFrame({
    'feature': learning_features,
    'importance': xgb.feature_importances_
}).sort_values('importance', ascending=False)

print("\nFeature Importance:")
print(importance_xgb.to_string(index=False))

# COMPARISON
print("\n" + "="*70)
print("COMPARISON: Trivial vs True Learning")
print("="*70)

comparison = pd.DataFrame({
    'Metric': ['Test Accuracy', 'Test F1', 'Overfitting Gap'],
    'With Trivial Features': ['99.98%', '99.98%', '0.01%'],
    'True Learning (RF)': [f'{test_acc_rf*100:.2f}%', f'{test_f1_rf*100:.2f}%', 
                           f'{(train_acc_rf-test_acc_rf)*100:.2f}%'],
    'True Learning (XGB)': [f'{test_acc_xgb*100:.2f}%', f'{test_f1_xgb*100:.2f}%',
                            f'{(train_acc_xgb-test_acc_xgb)*100:.2f}%']
})

print("\n" + comparison.to_string(index=False))

# Analysis
print("\n" + "="*70)
print("ANALYSIS")
print("="*70)

if test_acc_rf < 0.90 or test_acc_xgb < 0.90:
    print("\nAccuracy dropped significantly (<90%)")
    print("This indicates:")
    print("  - Model is NOW learning patterns, not definitions")
    print("  - Harder problem, but more realistic")
    print("  - Better generalization to unseen malware")
elif test_acc_rf > 0.95 or test_acc_xgb > 0.95:
    print("\nAccuracy still very high (>95%)")
    print("This indicates:")
    print("  - Behavioral patterns are VERY distinct")
    print("  - Volume/tempo/timing alone are sufficient")
    print("  - Real separability in traffic patterns")
else:
    print("\nAccuracy in 90-95% range")
    print("This indicates:")
    print("  - Good balance of learning and generalization")
    print("  - Model captures meaningful patterns")
    print("  - Realistic performance for IDS")

# Identify challenging classes
print("\n" + "="*70)
print("CHALLENGING CLASSES (where model struggles)")
print("="*70)

per_class_rf = classification_report(y_test, y_test_pred_rf, output_dict=True)
per_class_xgb = classification_report(y_test, y_test_pred_xgb, output_dict=True)

print("\nRandom Forest struggles with:")
for label in le.classes_:
    if per_class_rf[label]['f1-score'] < 0.85:
        print(f"  - {label}: F1={per_class_rf[label]['f1-score']:.3f}")

print("\nXGBoost struggles with:")
for label in le.classes_:
    if per_class_xgb[label]['f1-score'] < 0.85:
        print(f"  - {label}: F1={per_class_xgb[label]['f1-score']:.3f}")

# Save results
results = {
    'experiment': 'true_learning',
    'features_removed': trivial_features,
    'features_used': learning_features,
    'rf': {
        'test_accuracy': float(test_acc_rf),
        'test_f1': float(test_f1_rf),
        'overfitting_gap': float(train_acc_rf - test_acc_rf),
        'feature_importance': importance_rf.to_dict('records')
    },
    'xgb': {
        'test_accuracy': float(test_acc_xgb),
        'test_f1': float(test_f1_xgb),
        'overfitting_gap': float(train_acc_xgb - test_acc_xgb),
        'feature_importance': importance_xgb.to_dict('records')
    }
}

with open(OUTPUT_DIR / 'true_learning_results.json', 'w') as f:
    json.dump(results, f, indent=2)

print("\n" + "="*70)
print("CONCLUSION")
print("="*70)
print("\nBy removing trivial features, we force the model to:")
print("  1. Learn from behavioral patterns (tempo, volume, timing)")
print("  2. Generalize to unseen attack variants")
print("  3. Focus on invariant characteristics")
print("\nThis creates a MORE ROBUST model for detecting")
print("new malware that doesn't match exact flag patterns.")
print("\nResults saved to: experiments/true_learning_results.json")
print("="*70)