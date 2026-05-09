"""
SHAP Explainability Analizi
- Hangi feature'lar en önemli?
- Yıllara göre feature önemi nasıl değişiyor? (drift yorumu)
- Malware davranış evrimi

Kullanım:
    python shap_analysis.py
"""
import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import shap

from config import (
    METADATA_CSV, STATIC_PARQUET,
    MODELS_DIR, FIGURES_DIR, TABLES_DIR, RANDOM_SEED
)

ANALYSIS_YEARS = [2019, 2021, 2023, 2025]   # karşılaştırılacak yıllar
TOP_N_FEATURES = 20


def main():
    static_obj = joblib.load(MODELS_DIR / "static_model.pkl")
    model      = static_obj["model"]
    feat_cols  = static_obj["feature_cols"]

    meta  = pd.read_csv(METADATA_CSV)[["sha256", "label", "year"]]
    feats = pd.read_parquet(STATIC_PARQUET)
    df    = feats.merge(meta, on="sha256", how="inner")

    common_cols = [c for c in feat_cols if c in df.columns]
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    TABLES_DIR.mkdir(parents=True, exist_ok=True)

    explainer = shap.TreeExplainer(model)

    # ── 1. Genel SHAP özet grafiği (tüm veri) ─────────────
    X_all = df[common_cols].fillna(0)
    sample_idx = X_all.sample(min(2000, len(X_all)), random_state=RANDOM_SEED).index
    X_sample   = X_all.loc[sample_idx]
    shap_vals  = explainer.shap_values(X_sample)

    if isinstance(shap_vals, list):
        shap_vals = shap_vals[1]   # malware sınıfı

    fig, ax = plt.subplots(figsize=(10, 8))
    shap.summary_plot(shap_vals, X_sample, plot_type="bar",
                      max_display=TOP_N_FEATURES, show=False)
    plt.title("SHAP — Genel Feature Önemi (Tüm Yıllar)")
    plt.tight_layout()
    fig.savefig(FIGURES_DIR / "shap_global.png", dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Genel SHAP -> {FIGURES_DIR / 'shap_global.png'}")

    # ── 2. Yıl bazlı SHAP (drift görselleştirmesi) ────────
    yearly_importance = {}

    for year in ANALYSIS_YEARS:
        mask = df.year == year
        if mask.sum() < 10:
            continue
        X_year    = df.loc[mask, common_cols].fillna(0)
        sv        = explainer.shap_values(X_year)
        if isinstance(sv, list):
            sv = sv[1]
        mean_abs  = np.abs(sv).mean(axis=0)
        importance = pd.Series(mean_abs, index=common_cols)
        yearly_importance[year] = importance

        # Bireysel yıl grafiği
        fig, ax = plt.subplots(figsize=(10, 7))
        shap.summary_plot(sv, X_year, plot_type="bar",
                          max_display=TOP_N_FEATURES, show=False)
        plt.title(f"SHAP — {year} Top {TOP_N_FEATURES} Feature")
        plt.tight_layout()
        fig.savefig(FIGURES_DIR / f"shap_{year}.png", dpi=150, bbox_inches="tight")
        plt.close()
        print(f"  [{year}] SHAP -> {FIGURES_DIR / f'shap_{year}.png'}")

    # ── 3. Yıllara göre top feature'ların önemi değişimi ──
    if len(yearly_importance) >= 2:
        # En önemli genel top-10 feature seç
        overall   = pd.concat(yearly_importance.values(), axis=1).mean(axis=1)
        top10     = overall.nlargest(10).index.tolist()
        heat_data = pd.DataFrame(
            {yr: imp[top10] for yr, imp in yearly_importance.items()}
        )

        fig, ax = plt.subplots(figsize=(10, 6))
        im = ax.imshow(heat_data.values, aspect="auto", cmap="YlOrRd")
        ax.set_xticks(range(len(heat_data.columns)))
        ax.set_xticklabels(heat_data.columns)
        ax.set_yticks(range(len(top10)))
        ax.set_yticklabels(top10, fontsize=9)
        plt.colorbar(im, ax=ax, label="Ortalama |SHAP|")
        ax.set_title("Feature Önem Değişimi — Yıllara Göre (Drift Analizi)")
        ax.set_xlabel("Yıl")
        plt.tight_layout()
        fig.savefig(FIGURES_DIR / "shap_drift_heatmap.png", dpi=150, bbox_inches="tight")
        plt.close()
        print(f"Drift heatmap -> {FIGURES_DIR / 'shap_drift_heatmap.png'}")

        # Tablo kaydet
        heat_data.to_csv(TABLES_DIR / "shap_yearly_importance.csv")

    # ── 4. Beeswarm (detaylı etki yönü) ───────────────────
    X_all2  = df[common_cols].fillna(0).sample(min(1500, len(df)), random_state=RANDOM_SEED)
    sv2     = explainer.shap_values(X_all2)
    if isinstance(sv2, list):
        sv2 = sv2[1]

    fig, ax = plt.subplots(figsize=(10, 8))
    shap.summary_plot(sv2, X_all2, max_display=15, show=False)
    plt.title("SHAP Beeswarm — Feature Etki Yönleri")
    plt.tight_layout()
    fig.savefig(FIGURES_DIR / "shap_beeswarm.png", dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Beeswarm -> {FIGURES_DIR / 'shap_beeswarm.png'}")

    print("\nTüm SHAP analizleri tamamlandı.")


if __name__ == "__main__":
    main()
