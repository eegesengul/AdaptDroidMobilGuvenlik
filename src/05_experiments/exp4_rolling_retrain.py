"""
Deney 4 — Rolling Retraining
Her yeni yıl geldikçe o yılın verisiyle model yeniden eğitilir.
Performans stabilizasyonu ölçülür.

Kullanım:
    python exp4_rolling_retrain.py
"""
import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import lightgbm as lgb
from sklearn.metrics import f1_score, roc_auc_score

from config import (
    METADATA_CSV, STATIC_PARQUET,
    FIGURES_DIR, TABLES_DIR, LGBM_PARAMS
)

# Yıllar arası rolling window tanımı
ROLLING_SCHEDULE = [
    # (train_years,          test_year)
    ([2019, 2020, 2021, 2022], 2023),
    ([2020, 2021, 2022, 2023], 2024),
    ([2021, 2022, 2023, 2024], 2025),
    ([2022, 2023, 2024, 2025], 2026),
]


def main():
    meta  = pd.read_csv(METADATA_CSV)[["sha256", "label", "year"]]
    feats = pd.read_parquet(STATIC_PARQUET)
    df    = feats.merge(meta, on="sha256", how="inner")

    feat_cols = [c for c in df.columns if c not in ("sha256", "label", "year")]

    # Karşılaştırma: sadece orijinal model (train=2019-2022) ile test
    orig_model_trained = False
    orig_model         = None
    orig_f1 = {}
    roll_f1 = {}

    for train_years, test_year in ROLLING_SCHEDULE:
        test_mask = df.year == test_year
        if test_mask.sum() == 0:
            print(f"  [{test_year}] test verisi yok, atlanıyor.")
            continue

        X_test = df.loc[test_mask, feat_cols]
        y_test = df.loc[test_mask, "label"]

        # Orijinal model (sadece 2019-2022)
        if not orig_model_trained:
            train_mask = df.year.isin([2019, 2020, 2021, 2022])
            X_tr = df.loc[train_mask, feat_cols]
            y_tr = df.loc[train_mask, "label"]
            orig_model = lgb.LGBMClassifier(**LGBM_PARAMS)
            orig_model.fit(X_tr, y_tr, callbacks=[lgb.log_evaluation(-1)])
            orig_model_trained = True

        orig_pred = orig_model.predict(X_test)
        orig_f1[test_year] = round(f1_score(y_test, orig_pred), 4)

        # Rolling model (kayan pencere)
        train_mask_roll = df.year.isin(train_years)
        X_roll = df.loc[train_mask_roll, feat_cols]
        y_roll = df.loc[train_mask_roll, "label"]

        roll_model = lgb.LGBMClassifier(**LGBM_PARAMS)
        roll_model.fit(X_roll, y_roll, callbacks=[lgb.log_evaluation(-1)])

        roll_pred = roll_model.predict(X_test)
        roll_f1[test_year] = round(f1_score(y_test, roll_pred), 4)

        print(f"  [{test_year}] Orijinal F1={orig_f1[test_year]:.4f} | "
              f"Rolling F1={roll_f1[test_year]:.4f} | "
              f"Train yılları={train_years}")

    # Tablo
    records = [
        {"year": y, "f1_original": orig_f1[y], "f1_rolling": roll_f1[y]}
        for y in sorted(orig_f1.keys())
    ]
    df_res = pd.DataFrame(records)

    TABLES_DIR.mkdir(parents=True, exist_ok=True)
    df_res.to_csv(TABLES_DIR / "exp4_results.csv", index=False)
    print(f"\nSonuçlar → {TABLES_DIR / 'exp4_results.csv'}")

    # Grafik
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(8, 5))
    years = df_res.year.tolist()
    ax.plot(years, df_res.f1_original, "o--", color="tomato",  label="Orijinal Model (2019-2022)")
    ax.plot(years, df_res.f1_rolling,  "s-",  color="green",   label="Rolling Retrain", linewidth=2)
    ax.axhline(0.80, color="gray", linestyle=":", alpha=0.6)
    ax.set_xlabel("Test Yılı")
    ax.set_ylabel("F1-Score")
    ax.set_title("E4: Rolling Retraining vs Orijinal Model")
    ax.legend(); ax.grid(True, alpha=0.3)
    ax.set_xticks(years)
    plt.tight_layout()
    fig.savefig(FIGURES_DIR / "exp4_rolling_retrain.png", dpi=150)
    print(f"Grafik → {FIGURES_DIR / 'exp4_rolling_retrain.png'}")


if __name__ == "__main__":
    main()
