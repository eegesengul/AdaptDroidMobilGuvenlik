"""
DENEY 2: Temporal Split
------------------------
Train: 2016-2021  |  Val: 2022  |  Test: 2023
3 yaklasim x 3 model = 9 sonuc (val + test ayri raporlanir).

Yaklasimlar : Statik | Dinamik | Fusion
Modeller    : LightGBM | XGBoost | Random Forest
Metrikler   : Accuracy, Precision, Recall, F1, ROC-AUC

Kullanim:
    python src/06_deneyler/deney2_temporal_split.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[2]))

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, roc_auc_score)
from lightgbm import LGBMClassifier
from xgboost import XGBClassifier
import warnings
warnings.filterwarnings("ignore")

RANDOM_STATE     = 42
FEATURES_STATIC  = Path(__file__).parents[2] / "data" / "features_final_training"
FEATURES_DYNAMIC = Path(__file__).parents[2] / "data" / "features"
SKIP_DIRS        = {"2019_eski", "2017-3.8", "2017-eski", "2021-eski", "2023_ege"}
SONUCLAR_DIR     = Path(__file__).parent / "sonuclar"

TRAIN_YEARS = [2016, 2017, 2018, 2019, 2020, 2021]
VAL_YEARS   = [2022]
TEST_YEARS  = [2023]

# ── Veri yukleme ──────────────────────────────────────────────

def load_static(label: int) -> pd.DataFrame:
    folder = "static_features_malware" if label == 1 else "static_features_benign"
    frames = []
    for year_dir in sorted((FEATURES_STATIC / folder).iterdir()):
        if not year_dir.is_dir() or year_dir.name in SKIP_DIRS:
            continue
        f = year_dir / "static_features.parquet"
        if f.exists():
            df = pd.read_parquet(f)
            df["label"] = label
            df["year"]  = int(year_dir.name)
            frames.append(df)
    return pd.concat(frames, ignore_index=True)


def load_dynamic(label: int) -> pd.DataFrame:
    folder = "dynamic_features_malware" if label == 1 else "dynamic_features_benign"
    frames = []
    for year_dir in sorted((FEATURES_DYNAMIC / folder).iterdir()):
        if not year_dir.is_dir() or year_dir.name in SKIP_DIRS:
            continue
        v2 = year_dir / "dynamic_features_5min_v2.parquet"
        f  = v2 if v2.exists() else year_dir / "dynamic_features_5min.parquet"
        if not f.exists():
            continue
        df = pd.read_parquet(f)
        df["label"] = label
        df["year"]  = int(year_dir.name[:4])
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def get_feature_cols(df: pd.DataFrame) -> list:
    return [c for c in df.columns if c not in {"sha256", "label", "year", "frida_used"}]


def split_temporal(df: pd.DataFrame):
    train = df[df.year.isin(TRAIN_YEARS)]
    val   = df[df.year.isin(VAL_YEARS)]
    test  = df[df.year.isin(TEST_YEARS)]
    return train, val, test


# ── Metrik hesaplama ──────────────────────────────────────────

def evaluate(yaklasim, model_name, split_name, y_true, y_pred, y_proba) -> dict:
    base = {
        "deney":    "Deney2_TemporalSplit",
        "yaklasim": yaklasim,
        "model":    model_name,
        "split":    split_name,
        "n":        len(y_true),
        "n_mal":    int(y_true.sum()),
        "n_ben":    int((y_true == 0).sum()),
        "note":     "",
    }
    if len(set(y_true)) < 2:
        base.update({
            "accuracy":  None, "precision": None,
            "recall":    None, "f1":        None,
            "roc_auc":   None,
            "note":      "tek_sinif_sha256_uyumsuzlugu",
        })
        return base
    base.update({
        "accuracy":  round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall":    round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1":        round(f1_score(y_true, y_pred, zero_division=0), 4),
        "roc_auc":   round(roc_auc_score(y_true, y_proba), 4),
    })
    return base


def get_models():
    return [
        LGBMClassifier(n_estimators=500, learning_rate=0.05,
                       num_leaves=63, random_state=RANDOM_STATE,
                       n_jobs=-1, verbose=-1),
        XGBClassifier(n_estimators=500, learning_rate=0.05,
                      max_depth=6, random_state=RANDOM_STATE,
                      n_jobs=-1, eval_metric="logloss", verbosity=0),
        RandomForestClassifier(n_estimators=300, random_state=RANDOM_STATE,
                               n_jobs=-1),
    ]


def run_approach(yaklasim, df, feat_cols):
    train, val, test = split_temporal(df)
    X_tr, y_tr = train[feat_cols], train["label"]
    X_va, y_va = val[feat_cols],   val["label"]
    X_te, y_te = test[feat_cols],  test["label"]

    print(f"  Train: {len(train)} | Val: {len(val)} | Test: {len(test)}")
    print(f"  Train label: mal={y_tr.sum()} ben={(y_tr==0).sum()} | "
          f"Val: mal={y_va.sum()} ben={(y_va==0).sum()} | "
          f"Test: mal={y_te.sum()} ben={(y_te==0).sum()}")

    rows = []
    for model in get_models():
        mname = type(model).__name__
        print(f"  [{mname}] egitiliyor...")
        model.fit(X_tr, y_tr)

        for split_name, X_ev, y_ev in [("val", X_va, y_va), ("test", X_te, y_te)]:
            if len(X_ev) == 0:
                continue
            if len(set(y_ev)) < 2:
                print(f"  [{mname}] {split_name}: tek sinif ({y_ev.unique()}) — metrik hesaplanamaz")
                rows.append(evaluate(yaklasim, mname, split_name, y_ev,
                                     model.predict(X_ev), model.predict_proba(X_ev)[:, 1]))
                continue
            preds = model.predict(X_ev)
            proba = model.predict_proba(X_ev)[:, 1]
            rows.append(evaluate(yaklasim, mname, split_name, y_ev, preds, proba))
    return rows


# ── Ana akis ─────────────────────────────────────────────────

results = []

# 1. STATIK
print("=== Statik ===")
stat = pd.concat([load_static(1), load_static(0)], ignore_index=True)
feat_s = get_feature_cols(stat)
results += run_approach("Statik", stat, feat_s)

# 2. DINAMIK
print("\n=== Dinamik ===")
dyn = pd.concat([load_dynamic(1), load_dynamic(0)], ignore_index=True)
feat_d = get_feature_cols(dyn)
results += run_approach("Dinamik", dyn, feat_d)

# 3. FUSION
print("\n=== Fusion ===")
stat_f = stat.copy()
dyn_f  = dyn.copy()
stat_f["sha256_key"] = stat_f["sha256"].str.upper()
dyn_f["sha256_key"]  = dyn_f["sha256"].str.upper()
merged = pd.merge(
    stat_f.drop(columns=["sha256"]),
    dyn_f.drop(columns=["sha256", "label", "year"]),
    on="sha256_key", how="inner"
).drop(columns=["sha256_key"])
print(f"  Fusion birlesme: {len(merged)} satir (statik={len(stat_f)}, dinamik={len(dyn_f)})")
# Diagnose per-year match counts
for yr in TRAIN_YEARS + VAL_YEARS + TEST_YEARS:
    s_yr = stat_f[stat_f.year == yr]
    d_yr = dyn_f[dyn_f.year == yr]
    m_yr = merged[merged.year == yr]
    print(f"  {yr}: stat={len(s_yr)} dyn={len(d_yr)} esle={len(m_yr)}")
feat_f = get_feature_cols(merged)
results += run_approach("Fusion", merged, feat_f)

# ── Sonuclar ─────────────────────────────────────────────────
print("\n" + "="*90)
print("DENEY 2 - TEMPORAL SPLIT SONUCLARI")
print("="*90)
df_res = pd.DataFrame(results)
print(df_res.to_string(index=False))

SONUCLAR_DIR.mkdir(parents=True, exist_ok=True)
out = SONUCLAR_DIR / "deney2_temporal_split.csv"
df_res.to_csv(out, index=False)
print(f"\nKaydedildi: {out}")
