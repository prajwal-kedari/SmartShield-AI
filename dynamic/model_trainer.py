# ─────────────────────────────────────────────────────────────────────────────
# train_behavioral.py
# Trains the CIC-MalMem-2022 XGBoost behavioral model.
# Run on Kaggle or locally with the CSV downloaded.
# Output: dynamic/model.pkl  +  dynamic/feature_names.json
# ─────────────────────────────────────────────────────────────────────────────

import os, json
import pandas as pd
import numpy as np
import xgboost as xgb
import joblib

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

# ── 0. Output directory ───────────────────────────────────────────────────────
os.makedirs("dynamic", exist_ok=True)

# ── 1. Load ───────────────────────────────────────────────────────────────────
print("=" * 60)
print("STEP 1 — Loading dataset")
print("=" * 60)

df = pd.read_csv(
    "/kaggle/input/datasets/luccagodoy/obfuscated-malware-memory-2022-cic/Obfuscated-MalMem2022.csv"
)
print(f"Raw shape       : {df.shape}")
print(f"Label column    : 'Class'")
print(f"Label counts    :\n{df['Class'].value_counts()}\n")

# ── 2. Drop leaky columns BEFORE separating X and y ──────────────────────────
# 'Category' names the malware family — pure information leak.
# It must be dropped before anything else, including get_dummies,
# because one-hot encoding it would still leak the label.
print("=" * 60)
print("STEP 2 — Dropping leaky columns")
print("=" * 60)

LEAKY = ["Category"]
df = df.drop(columns=LEAKY, errors="ignore")
print(f"Dropped : {LEAKY}\n")

# ── 3. Separate features and label ───────────────────────────────────────────
print("=" * 60)
print("STEP 3 — Separating features and label")
print("=" * 60)

# 'Class' is the last column after dropping 'Category'
X = df.drop(columns=["Class"])
y = df["Class"].apply(lambda v: 0 if v == "Benign" else 1)

print(f"Feature matrix  : {X.shape}")
print(f"Malware samples : {y.sum()}")
print(f"Benign  samples : {(y == 0).sum()}\n")

# ── 4. Clean infinities and NaN ───────────────────────────────────────────────
print("=" * 60)
print("STEP 4 — Cleaning infinities and NaN")
print("=" * 60)

X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)
print(f"Remaining NaN   : {X.isna().sum().sum()}\n")

# ── 5. Drop zero-variance columns ─────────────────────────────────────────────
# These three columns are always 0 in this dataset — they carry no signal
# and would confuse cross-validation if left in.
print("=" * 60)
print("STEP 5 — Removing zero-variance columns")
print("=" * 60)

ZERO_VAR = [
    "pslist.nprocs64bit",
    "handles.nport",
    "svcscan.interactive_process_services",
]
X = X.drop(columns=ZERO_VAR, errors="ignore")
print(f"Dropped         : {ZERO_VAR}")
print(f"Shape after     : {X.shape}\n")

# ── 6. Confirm no remaining object columns ────────────────────────────────────
# After dropping Category the only object column is gone.
# If any sneak through, cast them now so XGBoost doesn't crash.
print("=" * 60)
print("STEP 6 — Checking for leftover object columns")
print("=" * 60)

obj_cols = X.select_dtypes(include="object").columns.tolist()
if obj_cols:
    print(f"Casting to numeric: {obj_cols}")
    X[obj_cols] = X[obj_cols].apply(pd.to_numeric, errors="coerce").fillna(0)
else:
    print("None found — all columns are numeric. Good.\n")

# ── 7. Save the exact feature list NOW (before any split) ─────────────────────
# The inference code must use this list in this exact order.
FEATURE_NAMES = X.columns.tolist()
json.dump(FEATURE_NAMES, open("dynamic/feature_names.json", "w"), indent=2)
print(f"Feature names saved → dynamic/feature_names.json ({len(FEATURE_NAMES)} features)\n")

# ── 8. Train / test split ─────────────────────────────────────────────────────
print("=" * 60)
print("STEP 7 — Train / test split (80 / 20, stratified)")
print("=" * 60)

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=42
)
print(f"Train : {X_train.shape}  |  Test : {X_test.shape}\n")

# ── 9. Train XGBoost with early stopping ─────────────────────────────────────
print("=" * 60)
print("STEP 8 — Training XGBoost")
print("=" * 60)

# scale_pos_weight handles class imbalance automatically.
# With a balanced dataset it evaluates to 1.0 — harmless to include.
scale = (y_train == 0).sum() / (y_train == 1).sum()
print(f"Class scale ratio : {scale:.2f}")

model = xgb.XGBClassifier(
    n_estimators        = 500,      # high ceiling — early stopping cuts this down
    max_depth           = 6,
    learning_rate       = 0.05,
    subsample           = 0.8,
    colsample_bytree    = 0.8,
    scale_pos_weight    = scale,
    eval_metric         = "auc",
    early_stopping_rounds = 30,
    random_state        = 42,
    n_jobs              = -1,
)

model.fit(
    X_train, y_train,
    eval_set            = [(X_train, y_train), (X_test, y_test)],
    verbose             = 50,
)

print(f"\nBest iteration : {model.best_iteration}")
print(f"Best AUC score : {model.best_score:.4f}\n")

# ── 10. Evaluate ──────────────────────────────────────────────────────────────
print("=" * 60)
print("STEP 9 — Evaluation")
print("=" * 60)

y_pred      = model.predict(X_test)
y_prob      = model.predict_proba(X_test)[:, 1]
auc         = roc_auc_score(y_test, y_prob)
cm          = confusion_matrix(y_test, y_pred)

print("\n── Classification Report ──────────────────")
print(classification_report(y_test, y_pred, target_names=["Benign", "Malware"]))

print("── Confusion Matrix ───────────────────────")
print(f"  TN={cm[0,0]}  FP={cm[0,1]}")
print(f"  FN={cm[1,0]}  TP={cm[1,1]}")
print(f"\n── ROC-AUC on test set : {auc:.4f}\n")

# ── 11. 5-fold cross-validation ───────────────────────────────────────────────
print("=" * 60)
print("STEP 10 — 5-Fold Cross Validation")
print("=" * 60)

# Use a fresh model for CV so early stopping doesn't interfere
cv_model = xgb.XGBClassifier(
    n_estimators     = model.best_iteration + 1,  # frozen at best iteration
    max_depth        = 6,
    learning_rate    = 0.05,
    subsample        = 0.8,
    colsample_bytree = 0.8,
    scale_pos_weight = scale,
    eval_metric      = "auc",
    random_state     = 42,
    n_jobs           = -1,
)

cv_scores = cross_val_score(
    cv_model, X, y,
    cv      = StratifiedKFold(n_splits=5, shuffle=True, random_state=42),
    scoring = "roc_auc",
    n_jobs  = -1,
)
print(f"AUC per fold : {np.round(cv_scores, 4)}")
print(f"Mean AUC     : {cv_scores.mean():.4f}")
print(f"Std  AUC     : {cv_scores.std():.4f}\n")

if cv_scores.mean() > 0.999:
    print("⚠️  Perfect CV — double-check no leaky feature snuck through.\n")

# ── 12. Feature importance ────────────────────────────────────────────────────
print("=" * 60)
print("STEP 11 — Top 20 Features by Importance")
print("=" * 60)

importance = pd.Series(
    model.feature_importances_,
    index=FEATURE_NAMES
).sort_values(ascending=False)

print(importance.head(20).to_string())
importance.to_csv("dynamic/feature_importance.csv", header=["importance"])
print("\nSaved → dynamic/feature_importance.csv")

top_feat, top_imp = importance.index[0], importance.iloc[0]
if top_imp > 0.4:
    print(f"\n⚠️  Top feature '{top_feat}' has importance {top_imp:.2f} — verify it is not a leak.\n")

# ── 13. Save model and metadata ───────────────────────────────────────────────
print("=" * 60)
print("STEP 12 — Saving model and metadata")
print("=" * 60)

joblib.dump(model, "dynamic/model.pkl")

meta = {
    "model_type"        : "XGBClassifier",
    "n_features"        : len(FEATURE_NAMES),
    "best_iteration"    : int(model.best_iteration),
    "best_auc"          : float(model.best_score),
    "test_auc"          : float(auc),
    "cv_mean_auc"       : float(cv_scores.mean()),
    "cv_std_auc"        : float(cv_scores.std()),
    "threshold_malware" : 0.55,
    "threshold_watchlist": 0.35,
    "dropped_leaky"     : LEAKY,
    "dropped_zero_var"  : ZERO_VAR,
}
json.dump(meta, open("dynamic/model_meta.json", "w"), indent=2)

print("Model saved      → dynamic/model.pkl")
print("Feature names    → dynamic/feature_names.json")
print("Model metadata   → dynamic/model_meta.json")
print("Feature importance → dynamic/feature_importance.csv")
print("\nDone.")