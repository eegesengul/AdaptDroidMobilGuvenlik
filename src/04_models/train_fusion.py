import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, roc_auc_score, classification_report

from config import (
    METADATA_CSV, STATIC_PARQUET, DYNAMIC_PARQUET,
    MODELS_DIR, DRIFT_THRESHOLD, WEIGHT_STEP
)

def load_scores(meta: pd.DataFrame, split: str,
                static_obj: dict, dynamic_obj: dict) -> tuple:
    mask = meta.split == split
    sha_list = meta.loc[mask, "sha256"].tolist()

    s_feats  = pd.read_parquet(STATIC_PARQUET)
    s_feats  = s_feats[s_feats.sha256.isin(sha_list)]
    s_model  = static_obj["model"]
    s_cols   = static_obj["feature_cols"]
    s_common = [c for c in s_cols if c in s_feats.columns]
    s_score  = s_model.predict_proba(s_feats[s_common])[:, 1]
    s_sha    = s_feats["sha256"].values

    d_feats  = pd.read_parquet(DYNAMIC_PARQUET)
    d_feats  = d_feats[d_feats.sha256.isin(sha_list)]
    d_model  = dynamic_obj["model"]
    d_cols   = dynamic_obj["feature_cols"]
    d_common = [c for c in d_cols if c in d_feats.columns]
    d_score  = d_model.predict_proba(d_feats[d_common])[:, 1]
    d_sha    = d_feats["sha256"].values

    common_sha = list(set(s_sha) & set(d_sha))
    if not common_sha:
        return None, None, None

    s_map = dict(zip(s_sha, s_score))
    d_map = dict(zip(d_sha, d_score))
    label_map = meta.set_index("sha256")["label"].to_dict()

    s_arr = np.array([s_map[h] for h in common_sha])
    d_arr = np.array([d_map[h] for h in common_sha])
    y_arr = np.array([label_map[h] for h in common_sha])

    return s_arr, d_arr, y_arr

def compute_adaptive_weights(val_f1_static: float) -> tuple[float, float]:
    if val_f1_static >= DRIFT_THRESHOLD:
        return 0.5, 0.5

    steps = int((DRIFT_THRESHOLD - val_f1_static) / WEIGHT_STEP)
    w_s   = max(0.1, 0.5 - steps * WEIGHT_STEP)
    w_d   = round(1.0 - w_s, 2)
    return round(w_s, 2), w_d

def fuse(s_scores, d_scores, w_s: float, w_d: float, threshold: float = 0.5):
    combined = w_s * s_scores + w_d * d_scores
    return (combined >= threshold).astype(int), combined

def main():
    static_obj  = joblib.load(MODELS_DIR / "static_model.pkl")
    dynamic_obj = joblib.load(MODELS_DIR / "dynamic_model.pkl")
    meta        = pd.read_csv(METADATA_CSV)[["sha256", "label", "split"]]

    s_val, d_val, y_val = load_scores(meta, "val", static_obj, dynamic_obj)
    if s_val is None:
        print("Validasyon için kesişen SHA bulunamadı.")
        return

    static_val_pred = (s_val >= 0.5).astype(int)
    val_f1_static   = f1_score(y_val, static_val_pred)
    print(f"Validation statik F1 : {val_f1_static:.4f}")

    w_s, w_d = compute_adaptive_weights(val_f1_static)
    print(f"Adaptive ağırlıklar  : w_static={w_s} | w_dynamic={w_d}")

    for split_name in ["val", "test1", "test2", "test3"]:
        s_arr, d_arr, y_arr = load_scores(meta, split_name, static_obj, dynamic_obj)
        if s_arr is None:
            continue

        pred_fixed, prob_fixed   = fuse(s_arr, d_arr, 0.5, 0.5)
        pred_adapt, prob_adapt   = fuse(s_arr, d_arr, w_s, w_d)
        pred_static              = (s_arr >= 0.5).astype(int)
        pred_dynamic             = (d_arr >= 0.5).astype(int)

        print(f"\n── {split_name.upper()} ──────────────────────────────")
        print(f"  Static-only   F1={f1_score(y_arr, pred_static):.4f} "
              f"AUC={roc_auc_score(y_arr, s_arr):.4f}")
        print(f"  Dynamic-only  F1={f1_score(y_arr, pred_dynamic):.4f} "
              f"AUC={roc_auc_score(y_arr, d_arr):.4f}")
        print(f"  Fixed Hybrid  F1={f1_score(y_arr, pred_fixed):.4f} "
              f"AUC={roc_auc_score(y_arr, prob_fixed):.4f}")
        print(f"  Adaptive      F1={f1_score(y_arr, pred_adapt):.4f} "
              f"AUC={roc_auc_score(y_arr, prob_adapt):.4f}")

    fusion_config = {
        "w_static":          w_s,
        "w_dynamic":         w_d,
        "val_f1_static":     val_f1_static,
        "drift_threshold":   DRIFT_THRESHOLD,
    }
    joblib.dump(fusion_config, MODELS_DIR / "fusion_config.pkl")
    print(f"\nFusion config kaydedildi -> {MODELS_DIR / 'fusion_config.pkl'}")

if __name__ == "__main__":
    main()
