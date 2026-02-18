"""
Statistical Analysis for Model Selection
Comprehensive mathematical analysis of the dataset
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from scipy.stats import shapiro
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = PROJECT_ROOT / "data" / "gold" / "gold_reduced.csv"
OUTPUT_DIR = PROJECT_ROOT / "analysis"
OUTPUT_DIR.mkdir(exist_ok=True)

plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")

print("\nCOMPREHENSIVE STATISTICAL ANALYSIS\n")

# Load data
print("[1] Loading data...")
df = pd.read_csv(DATA_PATH)

print(f"Total samples: {len(df):,}")
print(f"Features: {len(df.columns)-2}")
print(f"Classes: {df['label'].nunique()}")
print("\nClass distribution:")
print(df['label'].value_counts())

feature_cols = [col for col in df.columns if col not in ['label', 'flow_id', 'created_at']]
X = df[feature_cols]
y = df['label']

# Descriptive Statistics
print("\n[2] DESCRIPTIVE STATISTICS\n")

desc_stats = X.describe().T
desc_stats['skewness'] = X.skew()
desc_stats['kurtosis'] = X.kurtosis()
desc_stats['zeros'] = (X == 0).sum()
desc_stats['nulls'] = X.isnull().sum()

print("Summary Statistics:")
print(desc_stats.round(3))

desc_stats.to_csv(OUTPUT_DIR / "01_descriptive_statistics.csv")
print("\nSaved: 01_descriptive_statistics.csv")

print("\nKey Observations:")
high_skew = desc_stats[abs(desc_stats['skewness']) > 2]
if not high_skew.empty:
    print(f"High skewness (>2): {list(high_skew.index)}")
    print("Heavy-tailed distributions detected")

high_kurt = desc_stats[desc_stats['kurtosis'] > 5]
if not high_kurt.empty:
    print(f"High kurtosis (>5): {list(high_kurt.index)}")
    print("Presence of outliers detected")

# Correlation Analysis
print("\n[3] CORRELATION ANALYSIS\n")

corr_matrix = X.corr()

high_corr_pairs = []
for i in range(len(corr_matrix.columns)):
    for j in range(i+1, len(corr_matrix.columns)):
        if abs(corr_matrix.iloc[i, j]) > 0.8:
            high_corr_pairs.append({
                'feature1': corr_matrix.columns[i],
                'feature2': corr_matrix.columns[j],
                'correlation': corr_matrix.iloc[i, j]
            })

print("High Correlation Pairs (|r| > 0.8):")
if high_corr_pairs:
    for pair in high_corr_pairs:
        print(f"{pair['feature1']} <-> {pair['feature2']}: {pair['correlation']:.3f}")
    print("\nConsider removing one from each pair")
else:
    print("None found - features are independent")

plt.figure(figsize=(14, 12))
sns.heatmap(corr_matrix, annot=False, cmap='coolwarm', center=0, 
            square=True, linewidths=0.5)
plt.title('Feature Correlation Matrix', fontsize=16, pad=20)
plt.tight_layout()
plt.savefig(OUTPUT_DIR / "02_correlation_heatmap.png", dpi=300)
plt.close()
print("\nSaved: 02_correlation_heatmap.png")

# Class Separability
# Class Separability
print("\n[4] CLASS SEPARABILITY ANALYSIS\n")

separability_results = []

for feature in feature_cols:
    groups = [df[df['label'] == label][feature].dropna() for label in df['label'].unique()]
    
    # Filter out empty groups
    groups = [g for g in groups if len(g) > 0]
    
    if len(groups) < 2:
        continue
    
    try:
        h_stat, p_value = stats.kruskal(*groups)
        
        n = len(df)
        k = len(groups)
        eta_squared = (h_stat - k + 1) / (n - k) if (n - k) > 0 else 0
        
        separability_results.append({
            'feature': feature,
            'h_statistic': h_stat,
            'p_value': p_value,
            'eta_squared': max(0, eta_squared),
            'separable': p_value < 0.01
        })
    except Exception as e:
        print(f"Skipping {feature}: {e}")
        continue

sep_df = pd.DataFrame(separability_results).sort_values('eta_squared', ascending=False)

print("Feature Separability (sorted by effect size):")
print(sep_df.to_string(index=False))

sep_df.to_csv(OUTPUT_DIR / "03_class_separability.csv", index=False)
print("\nSaved: 03_class_separability.csv")

print("\nInterpretation:")
strong_sep = sep_df[sep_df['eta_squared'] > 0.14]
print(f"Strong separability (eta^2 > 0.14): {len(strong_sep)} features")
if not strong_sep.empty:
    print(f"Top features: {list(strong_sep['feature'].head(5))}")

weak_sep = sep_df[sep_df['p_value'] > 0.01]
if not weak_sep.empty:
    print(f"Weak separability: {list(weak_sep['feature'])}")

# Distribution Analysis
print("\n[5] DISTRIBUTION ANALYSIS\n")

normality_results = []

for feature in feature_cols:
    data = df[feature].dropna()
    
    if len(data) > 5000:
        sample = data.sample(5000, random_state=42)
    else:
        sample = data
    
    stat, p_value = shapiro(sample)
    
    normality_results.append({
        'feature': feature,
        'shapiro_statistic': stat,
        'p_value': p_value,
        'is_normal': p_value > 0.05
    })

norm_df = pd.DataFrame(normality_results)

print("Normality Tests (Shapiro-Wilk):")
print(norm_df.to_string(index=False))

normal_count = norm_df['is_normal'].sum()
print(f"\nFeatures with normal distribution: {normal_count}/{len(feature_cols)}")

if normal_count < len(feature_cols) * 0.3:
    print("Majority are NON-NORMAL distributions")
    print("Linear models will struggle")
    print("Tree-based models recommended")
else:
    print("Mixed distributions")
    print("Both linear and non-linear models viable")

norm_df.to_csv(OUTPUT_DIR / "04_normality_tests.csv", index=False)
print("\nSaved: 04_normality_tests.csv")

# Outlier Analysis
print("\n[6] OUTLIER ANALYSIS\n")

outlier_results = []

for feature in feature_cols:
    data = df[feature].dropna()
    
    # Skip boolean columns
    if data.dtype == 'bool' or data.nunique() <= 2:
        continue
    
    Q1 = data.quantile(0.25)
    Q3 = data.quantile(0.75)
    IQR = Q3 - Q1
    
    lower_bound = Q1 - 1.5 * IQR
    upper_bound = Q3 + 1.5 * IQR
    
    outliers = ((data < lower_bound) | (data > upper_bound)).sum()
    outlier_pct = (outliers / len(data)) * 100
    
    outlier_results.append({
        'feature': feature,
        'outlier_count': outliers,
        'outlier_percentage': outlier_pct,
        'Q1': Q1,
        'Q3': Q3,
        'IQR': IQR
    })

outlier_df = pd.DataFrame(outlier_results).sort_values('outlier_percentage', ascending=False)

print("Outlier Analysis (IQR method):")
print(outlier_df[['feature', 'outlier_count', 'outlier_percentage']].to_string(index=False))

high_outliers = outlier_df[outlier_df['outlier_percentage'] > 10]
if not high_outliers.empty:
    print(f"\nHigh outlier presence (>10%): {list(high_outliers['feature'])}")
    print("Robust models needed (Random Forest, XGBoost)")

outlier_df.to_csv(OUTPUT_DIR / "05_outlier_analysis.csv", index=False)
print("\nSaved: 05_outlier_analysis.csv")

# PCA
print("\n[7] DIMENSIONALITY ANALYSIS (PCA)\n")

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X.fillna(0))

pca = PCA()
pca.fit(X_scaled)

variance_explained = pca.explained_variance_ratio_
cumulative_variance = np.cumsum(variance_explained)

print("Principal Components:")
for i in range(min(10, len(variance_explained))):
    print(f"PC{i+1}: {variance_explained[i]*100:.2f}% "
          f"(cumulative: {cumulative_variance[i]*100:.2f}%)")

n_components_95 = np.argmax(cumulative_variance >= 0.95) + 1
print(f"\nComponents for 95% variance: {n_components_95}/{len(feature_cols)}")

if n_components_95 < len(feature_cols) * 0.7:
    print("High redundancy detected")
else:
    print("Most features contribute unique information")

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

ax1.bar(range(1, len(variance_explained)+1), variance_explained*100)
ax1.set_xlabel('Principal Component')
ax1.set_ylabel('Variance Explained (%)')
ax1.set_title('Scree Plot')
ax1.grid(True, alpha=0.3)

ax2.plot(range(1, len(cumulative_variance)+1), cumulative_variance*100, 'o-')
ax2.axhline(y=95, color='r', linestyle='--', label='95% threshold')
ax2.set_xlabel('Number of Components')
ax2.set_ylabel('Cumulative Variance Explained (%)')
ax2.set_title('Cumulative Variance')
ax2.legend()
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig(OUTPUT_DIR / "06_pca_analysis.png", dpi=300)
plt.close()
print("\nSaved: 06_pca_analysis.png")

# Model Selection
print("\n[8] MODEL SELECTION - MATHEMATICAL JUSTIFICATION\n")

decisions = {
    'Linearity': 'NON-LINEAR' if normal_count < len(feature_cols) * 0.3 else 'MIXED',
    'Outliers': 'HIGH' if (outlier_df['outlier_percentage'] > 10).sum() > 3 else 'MODERATE',
    'Feature_Redundancy': 'LOW' if len(high_corr_pairs) < 3 else 'HIGH',
    'Separability': 'GOOD' if (sep_df['eta_squared'] > 0.10).sum() > 5 else 'MODERATE',
    'Sample_Size': 'LARGE' if len(df) > 10000 else 'MEDIUM',
    'Class_Balance': 'IMBALANCED' if df['label'].value_counts().max() / len(df) > 0.5 else 'BALANCED'
}

print("Dataset Characteristics:")
for key, value in decisions.items():
    print(f"{key:20s}: {value}")

print("\nRECOMMENDED MODELS (Ranked)\n")

recommendations = []

rf_score = 0
rf_score += 30 if decisions['Linearity'] == 'NON-LINEAR' else 10
rf_score += 25 if decisions['Outliers'] in ['HIGH', 'MODERATE'] else 10
rf_score += 20 if decisions['Sample_Size'] == 'LARGE' else 10
rf_score += 15 if decisions['Class_Balance'] == 'IMBALANCED' else 10
rf_score += 10
recommendations.append(('Random Forest', rf_score, 
    "Handles non-linearity, outliers, imbalance. Interpretable."))

xgb_score = 0
xgb_score += 30 if decisions['Linearity'] == 'NON-LINEAR' else 10
xgb_score += 25 if decisions['Outliers'] in ['HIGH', 'MODERATE'] else 10
xgb_score += 25 if decisions['Class_Balance'] == 'IMBALANCED' else 10
xgb_score += 15 if decisions['Sample_Size'] == 'LARGE' else 10
xgb_score += 5
recommendations.append(('XGBoost', xgb_score,
    "Best for imbalanced data. Built-in regularization."))

lr_score = 0
lr_score += 20 if decisions['Linearity'] == 'MIXED' else 5
lr_score -= 20 if decisions['Outliers'] == 'HIGH' else 0
lr_score += 15 if decisions['Feature_Redundancy'] == 'LOW' else 5
lr_score += 10
recommendations.append(('Logistic Regression', max(lr_score, 0),
    "Simple baseline. Only if data is linear."))

svm_score = 0
svm_score += 25 if decisions['Linearity'] == 'NON-LINEAR' else 10
svm_score -= 20 if decisions['Outliers'] == 'HIGH' else 0
svm_score -= 15 if decisions['Sample_Size'] == 'LARGE' else 0
svm_score += 10 if decisions['Separability'] == 'GOOD' else 5
recommendations.append(('SVM (RBF)', max(svm_score, 0),
    "Good for non-linear. Slow on large datasets."))

recommendations.sort(key=lambda x: x[1], reverse=True)

print("Rank | Model                 | Score | Justification")
print("-" * 70)
for i, (model, score, reason) in enumerate(recommendations, 1):
    print(f"{i:4d} | {model:20s} | {score:5d} | {reason}")

print("\nFINAL RECOMMENDATION\n")

top_model = recommendations[0][0]
print(f"PRIMARY MODEL: {top_model}")
print(f"\nReasoning:")
print(f"- Dataset is {decisions['Linearity']} -> needs non-linear model")
print(f"- Outliers are {decisions['Outliers']} -> needs robust model")
print(f"- Sample size is {decisions['Sample_Size']} -> can train complex model")
print(f"- Classes are {decisions['Class_Balance']} -> needs handling")
print(f"\n{top_model} satisfies all requirements")

print(f"\nSECONDARY MODEL: {recommendations[1][0]}")
print(f"Use for comparison and validation")

print("\nANALYSIS COMPLETE\n")
print(f"Results saved to: {OUTPUT_DIR}")
print("\nNext steps:")
print("1. Review generated plots and CSV files")
print("2. Train recommended models")
print("3. Compare performance metrics")