"""
DENEY 1: Random Split Baseline
--------------------------------
Tum yillar (2016-2023) birlestirilerek rastgele %80 train / %20 test bolunur.
3 yaklasim x 3 model = 9 sonuc.

Yaklasimlar : Statik | Dinamik | Fusion
Modeller    : LightGBM | XGBoost | Random Forest
Metrikler   : Accuracy, Precision, Recall, F1, ROC-AUC

Kullanim:
    python src/06_deneyler/deney1_random_split.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[2]))

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, roc_auc_score)
from lightgbm import LGBMClassifier
from xgboost import XGBClassifier
import warnings
warnings.filterwarnings("ignore")

RANDOM_STATE = 42
TEST_SIZE    = 0.20
FEATURES     = Path(r"C:\Users\berat\Desktop\features")
SKIP_DIRS    = {"2019_eski", "2017-3.8", "2017-eski", "2021-eski", "2023_ege"}
SONUCLAR_DIR = Path(__file__).parent / "sonuclar"

# ── Veri yukleme ──────────────────────────────────────────────

def load_static(label: int) -> pd.DataFrame:
    folder = "static_features_malware" if label == 1 else "static_features_benign"
    frames = []
    for year_dir in sorted((FEATURES / folder).iterdir()):
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
    for year_dir in sorted((FEATURES / folder).iterdir()):
        if not year_dir.is_dir() or year_dir.name in SKIP_DIRS:
            continue
        parquets = list(year_dir.glob("*.parquet"))
        if not parquets:
            continue
        df = pd.read_parquet(parquets[0])
        df["label"] = label
        df["year"]  = int(year_dir.name[:4])
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def get_feature_cols(df: pd.DataFrame) -> list:
    return [c for c in df.columns if c not in {"sha256", "label", "year", "frida_used"}]


# ── Metrik hesaplama ──────────────────────────────────────────

def evaluate(yaklasim, model, X_test, y_test) -> dict:
    preds = model.predict(X_test)
    proba = model.predict_proba(X_test)[:, 1]
    return {
        "deney":     "Deney1_RandomSplit",
        "yaklasim":  yaklasim,
        "model":     type(model).__name__,
        "accuracy":  round(accuracy_score(y_test, preds), 4),
        "precision": round(precision_score(y_test, preds, zero_division=0), 4),
        "recall":    round(recall_score(y_test, preds, zero_division=0), 4),
        "f1":        round(f1_score(y_test, preds, zero_division=0), 4),
        "roc_auc":   round(roc_auc_score(y_test, proba), 4),
    }


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


# ── Ana akis ─────────────────────────────────────────────────

results = []

# 1. STATIK
print("Veri yukleniyor: Statik...")
stat = pd.concat([load_static(1), load_static(0)], ignore_index=True)
feat_s = get_feature_cols(stat)
X_s, y_s = stat[feat_s], stat["label"]
X_tr_s, X_te_s, y_tr_s, y_te_s = train_test_split(
    X_s, y_s, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y_s)
print(f"  Train: {len(X_tr_s)} | Test: {len(X_te_s)} | Ozellik: {len(feat_s)}")
for model in get_models():
    print(f"  [{type(model).__name__}] egitiliyor...")
    model.fit(X_tr_s, y_tr_s)
    results.append(evaluate("Statik", model, X_te_s, y_te_s))

# 2. DINAMIK
print("\nVeri yukleniyor: Dinamik...")
dyn = pd.concat([load_dynamic(1), load_dynamic(0)], ignore_index=True)
feat_d = get_feature_cols(dyn)
X_d, y_d = dyn[feat_d], dyn["label"]
X_tr_d, X_te_d, y_tr_d, y_te_d = train_test_split(
    X_d, y_d, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y_d)
print(f"  Train: {len(X_tr_d)} | Test: {len(X_te_d)} | Ozellik: {len(feat_d)}")
for model in get_models():
    print(f"  [{type(model).__name__}] egitiliyor...")
    model.fit(X_tr_d, y_tr_d)
    results.append(evaluate("Dinamik", model, X_te_d, y_te_d))

# 3. FUSION
print("\nVeri yukleniyor: Fusion...")
stat_f = stat.copy()
dyn_f  = dyn.copy()
stat_f["sha256_key"] = stat_f["sha256"].str.upper()
dyn_f["sha256_key"]  = dyn_f["sha256"].str.upper()
merged = pd.merge(
    stat_f.drop(columns=["sha256"]),
    dyn_f.drop(columns=["sha256", "label", "year"]),
    on="sha256_key", how="inner"
).drop(columns=["sha256_key"])
feat_f = get_feature_cols(merged)
X_f, y_f = merged[feat_f], merged["label"]
X_tr_f, X_te_f, y_tr_f, y_te_f = train_test_split(
    X_f, y_f, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y_f)
print(f"  Train: {len(X_tr_f)} | Test: {len(X_te_f)} | Ozellik: {len(feat_f)}")
for model in get_models():
    print(f"  [{type(model).__name__}] egitiliyor...")
    model.fit(X_tr_f, y_tr_f)
    results.append(evaluate("Fusion", model, X_te_f, y_te_f))

# ── Sonuclar ─────────────────────────────────────────────────
print("\n" + "="*80)
print("DENEY 1 - RANDOM SPLIT BASELINE SONUCLARI")
print("="*80)
df_res = pd.DataFrame(results)
print(df_res.to_string(index=False))

SONUCLAR_DIR.mkdir(parents=True, exist_ok=True)
out = SONUCLAR_DIR / "deney1_random_split.csv"
df_res.to_csv(out, index=False)
print(f"\nKaydedildi: {out}")
