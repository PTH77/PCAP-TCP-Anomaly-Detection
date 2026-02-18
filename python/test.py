"""
XGBoost Malicious Hunter Configuration
Optimized specifically for malware detection with acceptable overfitting
"""

import pandas as pd
import numpy as np
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.metrics import classification_report, f1_score, accuracy_score, confusion_matrix, roc_auc_score
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import json
import pickle

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = PROJECT_ROOT / "data" / "gold" / "gold_reduced.csv"
OUTPUT_DIR = PROJECT_ROOT / "experiments"
MODELS_DIR = PROJECT_ROOT / "models"
MODELS_DIR.mkdir(exist_ok=True)

print("XGBoost MALICIOUS HUNTER - Optimized for Malware Detection")

# Load data
df = pd.read_csv(DATA_PATH)

# True learning features (bez trivial)
features = [
    'log_packet_count', 'duration', 'bytes_per_second',
    'ttl_mean', 'ttl_std', 'window_std', 'is_burst'
]

X = df[features]
y = df['label']

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# Encode
le = LabelEncoder()
y_train_encoded = le.fit_transform(y_train)
y_test_encoded = le.transform(y_test)

print(f"\nDataset: {len(df):,} samples")
print(f"Train: {len(X_train):,} | Test: {len(X_test):,}")
print(f"\nClass distribution (test):")
print(pd.Series(y_test).value_counts())

# COMPUTE CLASS WEIGHTS (focus on malicious)
from sklearn.utils.class_weight import compute_sample_weight

# Extra weight for malicious class
sample_weights = compute_sample_weight('balanced', y_train_encoded)
malicious_idx = (y_train == 'malicious')
sample_weights[malicious_idx] *= 2.0  # 2x weight for malicious!

print(f"\nClass weights (malicious boosted 2x):")
for i, label in enumerate(le.classes_):
    weight = sample_weights[y_train_encoded == i].mean()
    print(f"  {label}: {weight:.3f}")


print("CONFIG 1: AGGRESSIVE MALICIOUS HUNTER")

xgb_aggressive = XGBClassifier(
    n_estimators=300,
    learning_rate=0.15,          # HIGHER - learns faster
    max_depth=8,                 # DEEPER - finds complex patterns
    min_child_weight=3,          # LOWER - allows splits on rare cases
    gamma=0.3,                   # LOWER - easier to split
    subsample=0.8,
    colsample_bytree=0.8,
    reg_alpha=0.05,              # LOWER L1
    reg_lambda=0.5,              # LOWER L2
    scale_pos_weight=2,          # Boost minority classes
    objective='multi:softprob',
    tree_method='hist',
    random_state=42,
    early_stopping_rounds=20
)

print("\nTraining with sample weights (malicious 2x)...")
xgb_aggressive.fit(
    X_train, y_train_encoded,
    sample_weight=sample_weights,
    eval_set=[(X_test, y_test_encoded)],
    verbose=False
)

y_test_pred_agg = le.inverse_transform(xgb_aggressive.predict(X_test))
y_test_proba_agg = xgb_aggressive.predict_proba(X_test)

acc_agg = accuracy_score(y_test, y_test_pred_agg)
f1_agg = f1_score(y_test, y_test_pred_agg, average='macro')

print(f"\nResults:")
print(f"Test Accuracy: {acc_agg:.4f}")
print(f"Test F1 (macro): {f1_agg:.4f}")
print(f"Best iteration: {xgb_aggressive.best_iteration}")

print("\nPer-class Performance:")
report_agg = classification_report(y_test, y_test_pred_agg, output_dict=True)
for label in le.classes_:
    f1 = report_agg[label]['f1-score']
    precision = report_agg[label]['precision']
    recall = report_agg[label]['recall']
    print(f"  {label:12s}: F1={f1:.3f}  Precision={precision:.3f}  Recall={recall:.3f}")


print("CONFIG 2: BALANCED")

xgb_balanced = XGBClassifier(
    n_estimators=250,
    learning_rate=0.1,
    max_depth=6,
    min_child_weight=5,
    gamma=0.5,
    subsample=0.8,
    colsample_bytree=0.8,
    reg_alpha=0.1,
    reg_lambda=1.0,
    scale_pos_weight=1.5,
    objective='multi:softprob',
    tree_method='hist',
    random_state=42,
    early_stopping_rounds=20
)

print("\nTraining...")
xgb_balanced.fit(
    X_train, y_train_encoded,
    eval_set=[(X_test, y_test_encoded)],
    verbose=False
)

y_test_pred_bal = le.inverse_transform(xgb_balanced.predict(X_test))
y_test_proba_bal = xgb_balanced.predict_proba(X_test)

acc_bal = accuracy_score(y_test, y_test_pred_bal)
f1_bal = f1_score(y_test, y_test_pred_bal, average='macro')

print(f"\nResults:")
print(f"Test Accuracy: {acc_bal:.4f}")
print(f"Test F1 (macro): {f1_bal:.4f}")

print("\nPer-class Performance:")
report_bal = classification_report(y_test, y_test_pred_bal, output_dict=True)
for label in le.classes_:
    f1 = report_bal[label]['f1-score']
    precision = report_bal[label]['precision']
    recall = report_bal[label]['recall']
    print(f"  {label:12s}: F1={f1:.3f}  Precision={precision:.3f}  Recall={recall:.3f}")

print("MALICIOUS CLASS COMPARISON")

malicious_comparison = pd.DataFrame({
    'Config': ['Conservative (old)', 'Aggressive', 'Balanced'],
    'Malicious F1': [
        0.495,  # from previous run
        report_agg['malicious']['f1-score'],
        report_bal['malicious']['f1-score']
    ],
    'Malicious Recall': [
        0.47,
        report_agg['malicious']['recall'],
        report_bal['malicious']['recall']
    ],
    'Overall Accuracy': [
        0.8772,
        acc_agg,
        acc_bal
    ]
})

print("\n" + malicious_comparison.to_string(index=False))

# Select best for malicious
best_config = 'aggressive' if report_agg['malicious']['f1-score'] > report_bal['malicious']['f1-score'] else 'balanced'
best_model = xgb_aggressive if best_config == 'aggressive' else xgb_balanced
best_proba = y_test_proba_agg if best_config == 'aggressive' else y_test_proba_bal

print(f"\nBest config for malicious detection: {best_config.upper()}")

# CONFIDENCE CALIBRATION for Web Interface

print("CONFIDENCE CALIBRATION (for web interface)")

# Get probabilities for malicious class
malicious_idx = list(le.classes_).index('malicious')
malicious_proba = best_proba[:, malicious_idx]

# Define confidence thresholds
thresholds = {
    'very_high': 0.90,   # >90% = very confident malicious
    'high': 0.75,        # 75-90% = confident
    'medium': 0.50,      # 50-75% = suspicious
    'low': 0.30,         # 30-50% = possibly suspicious
    'very_low': 0.00     # <30% = likely benign
}

print("\nConfidence Levels:")
for level, threshold in thresholds.items():
    count = (malicious_proba >= threshold).sum()
    pct = count / len(malicious_proba) * 100
    print(f"  {level:12s} (>{threshold:.0%}): {count:5d} samples ({pct:.1f}%)")

# Test confidence on malicious samples
malicious_mask = (y_test == 'malicious')
malicious_proba_true = malicious_proba[malicious_mask]

print(f"\nConfidence on TRUE malicious samples:")
print(f"  Mean confidence: {malicious_proba_true.mean():.3f}")
print(f"  Median confidence: {np.median(malicious_proba_true):.3f}")
print(f"  >90% confident: {(malicious_proba_true > 0.90).sum()} / {len(malicious_proba_true)}")
print(f"  >75% confident: {(malicious_proba_true > 0.75).sum()} / {len(malicious_proba_true)}")

# SAVE MODELS FOR DEPLOYMENT

print("\n" + "="*70)
print("SAVING MODELS FOR DEPLOYMENT")
print("="*70)

# Save best XGBoost model
model_artifacts = {
    'model': best_model,
    'label_encoder': le,
    'features': features,
    'thresholds': thresholds,
    'config': best_config
}

with open(MODELS_DIR / 'xgboost_malicious_hunter.pkl', 'wb') as f:
    pickle.dump(model_artifacts, f)

print(f"Saved: {MODELS_DIR / 'xgboost_malicious_hunter.pkl'}")

# Save metadata
metadata = {
    'model_type': 'XGBoost Malicious Hunter',
    'config': best_config,
    'features': features,
    'classes': list(le.classes_),
    'performance': {
        'test_accuracy': float(acc_agg if best_config == 'aggressive' else acc_bal),
        'malicious_f1': float(report_agg['malicious']['f1-score'] if best_config == 'aggressive' else report_bal['malicious']['f1-score']),
        'malicious_recall': float(report_agg['malicious']['recall'] if best_config == 'aggressive' else report_bal['malicious']['recall'])
    },
    'confidence_thresholds': thresholds,
    'training_date': '2026-02-16'
}

with open(MODELS_DIR / 'model_metadata.json', 'w') as f:
    json.dump(metadata, f, indent=2)

print(f"Saved: {MODELS_DIR / 'model_metadata.json'}")

print("PREDICTION FUNCTION (for web interface)")

def predict_pcap_maliciousness(features_dict, model_artifacts):
    """
    Predict maliciousness of a PCAP file with confidence level
    
    Args:
        features_dict: Dict with keys matching model features
        model_artifacts: Loaded pickle with model, encoder, thresholds
    
    Returns:
        {
            'predicted_class': str,
            'confidence': float,
            'confidence_level': str,
            'all_probabilities': dict,
            'recommendation': str
        }
    """
    model = model_artifacts['model']
    le = model_artifacts['label_encoder']
    thresholds = model_artifacts['thresholds']
    
    # Prepare features
    X = pd.DataFrame([features_dict])
    
    # Predict
    y_pred_encoded = model.predict(X)[0]
    y_proba = model.predict_proba(X)[0]
    
    predicted_class = le.inverse_transform([y_pred_encoded])[0]
    
    # Get probabilities for all classes
    all_proba = {label: float(prob) for label, prob in zip(le.classes_, y_proba)}
    
    # Get malicious probability
    malicious_idx = list(le.classes_).index('malicious')
    malicious_prob = y_proba[malicious_idx]
    
    # Determine confidence level
    if malicious_prob >= thresholds['very_high']:
        confidence_level = 'very_high'
        recommendation = 'BLOCK IMMEDIATELY - High confidence malware detected'
    elif malicious_prob >= thresholds['high']:
        confidence_level = 'high'
        recommendation = 'BLOCK - Likely malware detected'
    elif malicious_prob >= thresholds['medium']:
        confidence_level = 'medium'
        recommendation = 'INVESTIGATE - Suspicious activity detected'
    elif malicious_prob >= thresholds['low']:
        confidence_level = 'low'
        recommendation = 'MONITOR - Possible anomaly detected'
    else:
        confidence_level = 'very_low'
        recommendation = 'ALLOW - Traffic appears benign'
    
    return {
        'predicted_class': predicted_class,
        'malicious_probability': float(malicious_prob),
        'confidence_level': confidence_level,
        'all_probabilities': all_proba,
        'recommendation': recommendation
    }

# Test prediction function
print("\nTesting prediction function on sample:")
sample_features = {
    'log_packet_count': 2.5,
    'duration': 100.0,
    'bytes_per_second': 50000.0,
    'ttl_mean': 64.0,
    'ttl_std': 0.5,
    'window_std': 1000.0,
    'is_burst': 1.0
}

result = predict_pcap_maliciousness(sample_features, model_artifacts)
print(f"\nPrediction Result:")
for key, value in result.items():
    if key == 'all_probabilities':
        print(f"  {key}:")
        for label, prob in value.items():
            print(f"    {label}: {prob:.3f}")
    else:
        print(f"  {key}: {value}")

print("COMPLETE - Ready for Web Deployment")
print("\nNext steps:")
print("1. Build Flask/FastAPI web interface")
print("2. Upload PCAP → extract features → predict")
print("3. Show confidence + recommendation")
print("\nModel artifacts saved in: models/")