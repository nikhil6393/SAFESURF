import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Simulate 10,000 URLs (5000 Benign, 5000 Malicious)
np.random.seed(42)
N_BENIGN = 5000
N_MALICIOUS = 5000

# Blacklist catches 80% of malicious URLs with 0 false positives
blacklist_caught = np.random.choice([1, 0], size=N_MALICIOUS, p=[0.8, 0.2])
blacklist_benign = np.zeros(N_BENIGN)

# Generate Structural Scores (H, S, T)
def clip(val):
    return np.clip(val, 0, 1)

# Benign URLs generally have low scores
H_benign = clip(np.random.normal(0.15, 0.1, N_BENIGN))
S_benign = clip(np.random.normal(0.1, 0.1, N_BENIGN))
T_benign = clip(np.random.normal(0.1, 0.1, N_BENIGN))

# Malicious URLs (the remaining 20% zero-days) have higher scores
H_mal = clip(np.random.normal(0.65, 0.2, N_MALICIOUS))
S_mal = clip(np.random.normal(0.55, 0.2, N_MALICIOUS))
T_mal = clip(np.random.normal(0.7, 0.2, N_MALICIOUS))

# Task 1: Ablation Study
def calc_metrics(y_true, y_pred):
    tp = np.sum((y_true == 1) & (y_pred == 1))
    fp = np.sum((y_true == 0) & (y_pred == 1))
    fn = np.sum((y_true == 1) & (y_pred == 0))
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    return precision * 100, recall * 100, f1 * 100

y_true = np.concatenate([np.ones(N_MALICIOUS), np.zeros(N_BENIGN)])
blacklist = np.concatenate([blacklist_caught, blacklist_benign])
H_all = np.concatenate([H_mal, H_benign])
S_all = np.concatenate([S_mal, S_benign])
T_all = np.concatenate([T_mal, T_benign])

# Models
# a) Blacklist only
y_pred_bl = blacklist

# b) Blacklist + H only (Score = H, Thresh = 0.4)
y_pred_h = np.where((blacklist == 1) | (H_all >= 0.4), 1, 0)

# c) Blacklist + H + S (Score = (0.4H + 0.3S)/0.7)
score_hs = (0.4 * H_all + 0.3 * S_all) / 0.7
y_pred_hs = np.where((blacklist == 1) | (score_hs >= 0.4), 1, 0)

# d) Blacklist + H + S + T (Score = 0.4H + 0.3S + 0.3T)
score_hst = (0.4 * H_all + 0.3 * S_all + 0.3 * T_all)
y_pred_hst = np.where((blacklist == 1) | (score_hst >= 0.4), 1, 0)

ablation_results = []
models = ["Blacklist Only", "Blacklist + H", "Blacklist + H + S", "Full System (BL + H + S + T)"]
preds = [y_pred_bl, y_pred_h, y_pred_hs, y_pred_hst]

for name, p in zip(models, preds):
    prec, rec, f1 = calc_metrics(y_true, p)
    ablation_results.append({"Method": name, "Precision (%)": round(prec, 1), "Recall (%)": round(rec, 1), "F1 Score (%)": round(f1, 1)})

df_ablation = pd.DataFrame(ablation_results)
df_ablation.to_csv("ablation_study.csv", index=False)

# Task 2: Adversarial Robustness
# 50 Synthetic domains with Low H (0.15), Low S (0.1), Low T (0)
adv_H = np.random.normal(0.15, 0.05, 50)
adv_S = np.random.normal(0.1, 0.05, 50)
adv_T = np.zeros(50)

adv_scores = 0.4 * adv_H + 0.3 * adv_S + 0.3 * adv_T
adv_pred = np.where(adv_scores >= 0.4, 1, 0)
false_negatives = np.sum(adv_pred == 0)

adv_results = pd.DataFrame([{
    "Test": "Adversarial Robustness (Low H/S/T)",
    "Total Injected": 50,
    "Bypassed System (False Negatives)": false_negatives,
    "Flagged Correctly": 50 - false_negatives,
    "Bypass Rate (%)": (false_negatives / 50) * 100
}])
adv_results.to_csv("adversarial_robustness.csv", index=False)

# Task 3: Threshold Sensitivity Analysis
thresholds = np.arange(0.3, 0.81, 0.02)
f1_scores = []
precisions = []
recalls = []

for t in thresholds:
    y_p = np.where((blacklist == 1) | (score_hst >= t), 1, 0)
    p, r, f = calc_metrics(y_true, y_p)
    f1_scores.append(f)
    precisions.append(p)
    recalls.append(r)

# Plot F1 Score vs Threshold
plt.figure(figsize=(10, 6))
plt.plot(thresholds, f1_scores, marker='o', linestyle='-', color='purple', label='F1 Score')
plt.plot(thresholds, precisions, linestyle='--', color='blue', label='Precision', alpha=0.6)
plt.plot(thresholds, recalls, linestyle='--', color='red', label='Recall', alpha=0.6)
plt.axvline(x=0.4, color='green', linestyle=':', label='Current Thresh (0.4)')
plt.title("Sensitivity Analysis: Detection Threshold vs. F1 Score")
plt.xlabel("Threshold Parameter (T)")
plt.ylabel("Score (%)")
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig("threshold_sensitivity.png", dpi=300)

best_idx = np.argmax(f1_scores)
print(f"DONE. Generated 2 CSVs and 1 PNG.")
print(f"Optimal Threshold: {thresholds[best_idx]:.2f} with F1: {f1_scores[best_idx]:.1f}%")
