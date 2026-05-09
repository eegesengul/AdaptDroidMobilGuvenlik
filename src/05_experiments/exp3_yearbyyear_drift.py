"""
Deney 3 — Year-by-Year Drift Analizi
Her yıl için model performansını ölçer ve drift grafiği üretir.
4 model karşılaştırılır: Static, Dynamic, Fixed Hybrid, Adaptive Hybrid.

Kullanım:
    python exp3_yearbyyear_drift.py
"""
import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import f1_score, roc_auc_score

from config import (
    METADATA_CSV, STATIC_PARQUET, DYNAMIC_PARQUET,
    MODELS_DIR, FIGURES_DIR, TABLES_DIR,
    DRIFT_THRESHOLD, WEIGHT_STEP
)

TEST_YEARS = [2023, 2024, 2025, 2026]


def compute_adaptive_weights(val_f1_static: float) -> tuple:
    if val_f1_static >= DRIFT_THRESHOLD:
        return 0.5, 0.5
    steps = int((DRIFT_THRESHOLD - val_f1_static) / WEIGHT_STEP)
    w_s   = max(0.1, 0.5 - steps * WEIGHT_STEP)
    return round(w_s, 2), round(1.0 - w_s, 2)


def main():
    static_obj  = joblib.load(MODELS_DIR / "static_model.pkl")
    dynamic_obj = joblib.load(MODELS_DIR / "dynamic_model.pkl")
    fusion_cfg  = joblib.load(MODELS_DIR / "fusion_config.pkl")

    meta      = pd.read_csv(METADATA_CSV)[["sha256", "label", "split", "year"]]
    s_feats   = pd.read_parquet(STATIC_PARQUET)
    d_feats   = pd.read_parquet(DYNAMIC_PARQUET)

    s_model   = static_obj["model"]
    s_cols    = static_obj["feature_cols"]
    d_model   = dynamic_obj["model"]
    d_cols    = dynamic_obj["feature_cols"]
    w_s, w_d  = fusion_cfg["w_static"], fusion_cfg["w_dynamic"]

    records = []

    for year in TEST_YEARS:
        mask_meta = meta.year == year
        if mask_meta.sum() == 0:
            continue
        sha_year = meta.loc[mask_meta, "sha256"].tolist()

        # Statik skorlar
        sf = s_feats[s_feats.sha256.isin(sha_year)]
        sc = [c for c in s_cols if c in sf.columns]
        s_score = s_model.predict_proba(sf[sc])[:, 1]
        s_sha   = sf["sha256"].values

        # Dinamik skorlar
        df_d = d_feats[d_feats.sha256.isin(sha_year)]
        dc   = [c for c in d_cols if c in df_d.columns]
        d_score = d_model.predict_proba(df_d[dc])[:, 1]
        d_sha   = df_d["sha256"].values

        # Ortak SHA
        common = list(set(s_sha) & set(d_sha))
        if not common:
            continue

        label_map = meta.set_index("sha256")["label"].to_dict()
        s_map     = dict(zip(s_sha, s_score))
        d_map     = dict(zip(d_sha, d_score))

        s_arr = np.array([s_map[h] for h in common])
        d_arr = np.array([d_map[h] for h in common])
        y_arr = np.array([label_map[h] for h in common])

        fused_fixed  = 0.5 * s_arr + 0.5 * d_arr
        fused_adapt  = w_s  * s_arr + w_d  * d_arr

        records.append({
            "year":           year,
            "n":              len(y_arr),
            "f1_static":      round(f1_score(y_arr, (s_arr >= 0.5).astype(int)), 4),
            "f1_dynamic":     round(f1_score(y_arr, (d_arr >= 0.5).astype(int)), 4),
            "f1_fixed":       round(f1_score(y_arr, (fused_fixed >= 0.5).astype(int)), 4),
            "f1_adaptive":    round(f1_score(y_arr, (fused_adapt >= 0.5).astype(int)), 4),
            "auc_static":     round(roc_auc_score(y_arr, s_arr), 4),
            "auc_dynamic":    round(roc_auc_score(y_arr, d_arr), 4),
            "auc_adaptive":   round(roc_auc_score(y_arr, fused_adapt), 4),
        })

    df_res = pd.DataFrame(records)
    print("\n── E3: Year-by-Year Drift ──")
    print(df_res.to_string(index=False))

    # Tablo kaydet
    TABLES_DIR.mkdir(parents=True, exist_ok=True)
    df_res.to_csv(TABLES_DIR / "exp3_results.csv", index=False)

    # Drift grafiği
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(df_res.year, df_res.f1_static,   "o--", label="Static-only",   color="tomato")
    ax.plot(df_res.year, df_res.f1_dynamic,  "s--", label="Dynamic-only",  color="steelblue")
    ax.plot(df_res.year, df_res.f1_fixed,    "^-",  label="Fixed Hybrid",  color="goldenrod")
    ax.plot(df_res.year, df_res.f1_adaptive, "D-",  label="Adaptive Hybrid", color="green", linewidth=2)
    ax.axhline(y=0.80, color="gray", linestyle=":", alpha=0.7, label="Drift Eşiği (0.80)")
    ax.set_xlabel("Yıl")
    ax.set_ylabel("F1-Score")
    ax.set_title("AdaptDroid — Temporal Concept Drift Analizi")
    ax.legend()
    ax.grid(True, alpha=0.3)
    ax.set_xticks(df_res.year.tolist())
    plt.tight_layout()
    fig.savefig(FIGURES_DIR / "exp3_drift_f1.png", dpi=150)
    print(f"\nGrafik kaydedildi → {FIGURES_DIR / 'exp3_drift_f1.png'}")


if __name__ == "__main__":
    main()
