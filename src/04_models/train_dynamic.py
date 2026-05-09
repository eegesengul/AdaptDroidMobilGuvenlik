"""
Dinamik feature'larla LightGBM modeli eğitir.
Kullanım:
    python train_dynamic.py
"""
import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

import joblib
import pandas as pd
from sklearn.metrics import classification_report, f1_score, roc_auc_score

import lightgbm as lgb

from config import (
    METADATA_CSV, DYNAMIC_PARQUET, MODELS_DIR, LGBM_PARAMS
)


def load_data():
    meta  = pd.read_csv(METADATA_CSV)[["sha256", "label", "split"]]
    feats = pd.read_parquet(DYNAMIC_PARQUET)
    df    = feats.merge(meta, on="sha256", how="inner")
    return df


def get_feature_cols(df: pd.DataFrame) -> list:
    return [c for c in df.columns if c not in ("sha256", "label", "split")]


def train_and_evaluate(df: pd.DataFrame):
    feat_cols = get_feature_cols(df)

    X_train = df.loc[df.split == "train", feat_cols]
    y_train = df.loc[df.split == "train", "label"]
    X_val   = df.loc[df.split == "val",   feat_cols]
    y_val   = df.loc[df.split == "val",   "label"]

    print(f"Train: {len(X_train):,} | Val: {len(X_val):,}")

    model = lgb.LGBMClassifier(**LGBM_PARAMS)
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        callbacks=[lgb.early_stopping(50), lgb.log_evaluation(100)],
    )

    print("\n── Validation ──")
    y_pred = model.predict(X_val)
    y_prob = model.predict_proba(X_val)[:, 1]
    print(classification_report(y_val, y_pred, target_names=["Benign", "Malware"]))
    print(f"ROC-AUC: {roc_auc_score(y_val, y_prob):.4f}")

    for split_name in ["test1", "test2", "test3"]:
        mask = df.split == split_name
        if mask.sum() == 0:
            continue
        pred = model.predict(df.loc[mask, feat_cols])
        prob = model.predict_proba(df.loc[mask, feat_cols])[:, 1]
        print(f"\n── {split_name.upper()} ──")
        print(f"F1: {f1_score(df.loc[mask,'label'], pred):.4f} | "
              f"AUC: {roc_auc_score(df.loc[mask,'label'], prob):.4f}")

    return model, feat_cols


def main():
    print("Veri yükleniyor...")
    df = load_data()
    print(f"Toplam kayıt: {len(df):,}")

    model, feat_cols = train_and_evaluate(df)

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = MODELS_DIR / "dynamic_model.pkl"
    joblib.dump({"model": model, "feature_cols": feat_cols}, out_path)
    print(f"\nModel kaydedildi → {out_path}")


if __name__ == "__main__":
    main()
