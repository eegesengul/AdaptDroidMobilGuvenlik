import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score, classification_report,
    f1_score, roc_auc_score
)

import lightgbm as lgb

from config import (
    METADATA_CSV, STATIC_PARQUET, MODELS_DIR, LGBM_PARAMS, SPLITS
)

def load_data():
    meta  = pd.read_csv(METADATA_CSV)[["sha256", "label", "split"]]
    feats = pd.read_parquet(STATIC_PARQUET)
    df    = feats.merge(meta, on="sha256", how="inner")
    return df

def get_feature_cols(df: pd.DataFrame) -> list:
    return [c for c in df.columns if c not in ("sha256", "label", "split")]

def train_and_evaluate(df: pd.DataFrame):
    feat_cols = get_feature_cols(df)

    train_mask = df["split"] == "train"
    val_mask   = df["split"] == "val"

    X_train = df.loc[train_mask, feat_cols]
    y_train = df.loc[train_mask, "label"]
    X_val   = df.loc[val_mask, feat_cols]
    y_val   = df.loc[val_mask, "label"]

    print(f"Train: {len(X_train):,} | Val: {len(X_val):,}")

    model = lgb.LGBMClassifier(**LGBM_PARAMS)
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        callbacks=[lgb.early_stopping(50), lgb.log_evaluation(100)],
    )

    print("\n── Validation Sonuçları ──")
    y_pred = model.predict(X_val)
    y_prob = model.predict_proba(X_val)[:, 1]
    print(classification_report(y_val, y_pred, target_names=["Benign", "Malware"]))
    print(f"ROC-AUC : {roc_auc_score(y_val, y_prob):.4f}")
    print(f"F1      : {f1_score(y_val, y_pred):.4f}")

    for split_name in ["test1", "test2", "test3"]:
        mask = df["split"] == split_name
        if mask.sum() == 0:
            continue
        X_t = df.loc[mask, feat_cols]
        y_t = df.loc[mask, "label"]
        pred = model.predict(X_t)
        prob = model.predict_proba(X_t)[:, 1]
        years = df.loc[mask, "split"].map(
            {"test1": 2024, "test2": 2025, "test3": 2026}
        ).iloc[0]
        print(f"\n── {split_name.upper()} ({years}) ──")
        print(f"F1: {f1_score(y_t, pred):.4f} | AUC: {roc_auc_score(y_t, prob):.4f}")

    return model, feat_cols

def main():
    print("Veri yükleniyor...")
    df = load_data()
    print(f"Toplam kayıt: {len(df):,}")

    model, feat_cols = train_and_evaluate(df)

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODELS_DIR / "static_model.pkl"
    joblib.dump({"model": model, "feature_cols": feat_cols}, model_path)
    print(f"\nModel kaydedildi -> {model_path}")

if __name__ == "__main__":
    main()
