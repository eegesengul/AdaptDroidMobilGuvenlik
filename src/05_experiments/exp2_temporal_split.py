"""
Deney 2 — Temporal Split
Model 2019-2022 ile eğitilir, 2023/2024/2025/2026 ile test edilir.
Amaç: Random split'in gerçek dünyayı nasıl yanılttığını göstermek.

Kullanım:
    python exp2_temporal_split.py
"""
import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

import pandas as pd
import lightgbm as lgb
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score,
    recall_score, roc_auc_score
)

from config import METADATA_CSV, STATIC_PARQUET, TABLES_DIR, LGBM_PARAMS

TEST_SPLITS = {
    "val":   2023,
    "test1": 2024,
    "test2": 2025,
    "test3": 2026,
}


def main():
    meta  = pd.read_csv(METADATA_CSV)[["sha256", "label", "split"]]
    feats = pd.read_parquet(STATIC_PARQUET)
    df    = feats.merge(meta, on="sha256", how="inner")

    feat_cols = [c for c in df.columns if c not in ("sha256", "label", "split")]

    X_train = df.loc[df.split == "train", feat_cols]
    y_train = df.loc[df.split == "train", "label"]
    X_val   = df.loc[df.split == "val",   feat_cols]
    y_val   = df.loc[df.split == "val",   "label"]

    print(f"Train (2019-2022): {len(X_train):,}")

    model = lgb.LGBMClassifier(**LGBM_PARAMS)
    model.fit(X_train, y_train,
              eval_set=[(X_val, y_val)],
              callbacks=[lgb.early_stopping(50), lgb.log_evaluation(100)])

    all_results = []
    print("\n── E2: Temporal Split Sonuçları ──")

    for split_name, year in TEST_SPLITS.items():
        mask = df.split == split_name
        if mask.sum() == 0:
            print(f"  [{year}] veri yok, atlanıyor.")
            continue

        X_t = df.loc[mask, feat_cols]
        y_t = df.loc[mask, "label"]

        y_pred = model.predict(X_t)
        y_prob = model.predict_proba(X_t)[:, 1]

        row = {
            "experiment": "E2_Temporal_Split",
            "split":      split_name,
            "year":       year,
            "n_samples":  len(y_t),
            "accuracy":   round(accuracy_score(y_t, y_pred), 4),
            "precision":  round(precision_score(y_t, y_pred, zero_division=0), 4),
            "recall":     round(recall_score(y_t, y_pred, zero_division=0), 4),
            "f1":         round(f1_score(y_t, y_pred, zero_division=0), 4),
            "roc_auc":    round(roc_auc_score(y_t, y_prob), 4),
        }
        all_results.append(row)
        print(f"  [{year}] F1={row['f1']:.4f} | AUC={row['roc_auc']:.4f} | n={len(y_t)}")

    TABLES_DIR.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(all_results).to_csv(TABLES_DIR / "exp2_results.csv", index=False)
    print(f"\nSonuçlar kaydedildi -> {TABLES_DIR / 'exp2_results.csv'}")


if __name__ == "__main__":
    main()
