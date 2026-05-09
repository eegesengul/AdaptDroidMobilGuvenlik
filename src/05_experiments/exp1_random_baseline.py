"""
Deney 1 — Random Split Baseline
Klasik %80/%20 random split ile baseline performans.
Amaç: Temporal split ile karşılaştırma referansı oluşturmak.

Kullanım:
    python exp1_random_baseline.py
"""
import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score,
    recall_score, roc_auc_score, classification_report
)

from config import METADATA_CSV, STATIC_PARQUET, TABLES_DIR, LGBM_PARAMS, RANDOM_SEED


def main():
    meta  = pd.read_csv(METADATA_CSV)[["sha256", "label"]]
    feats = pd.read_parquet(STATIC_PARQUET)
    df    = feats.merge(meta, on="sha256", how="inner")

    feat_cols = [c for c in df.columns if c not in ("sha256", "label")]
    X = df[feat_cols]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )

    print(f"Train: {len(X_train):,} | Test: {len(X_test):,}")

    model = lgb.LGBMClassifier(**LGBM_PARAMS)
    model.fit(X_train, y_train,
              eval_set=[(X_test, y_test)],
              callbacks=[lgb.early_stopping(50), lgb.log_evaluation(100)])

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    results = {
        "experiment":  "E1_Random_Baseline",
        "split":       "random_80_20",
        "accuracy":    round(accuracy_score(y_test, y_pred), 4),
        "precision":   round(precision_score(y_test, y_pred), 4),
        "recall":      round(recall_score(y_test, y_pred), 4),
        "f1":          round(f1_score(y_test, y_pred), 4),
        "roc_auc":     round(roc_auc_score(y_test, y_prob), 4),
    }

    print("\n── E1: Random Split Baseline ──")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malware"]))
    for k, v in results.items():
        print(f"  {k:12} : {v}")

    # Kaydet
    TABLES_DIR.mkdir(parents=True, exist_ok=True)
    pd.DataFrame([results]).to_csv(TABLES_DIR / "exp1_results.csv", index=False)
    print(f"\nSonuçlar kaydedildi -> {TABLES_DIR / 'exp1_results.csv'}")


if __name__ == "__main__":
    main()
