from pathlib import Path

# ── Kök dizin ──────────────────────────────────────────────
ROOT = Path(__file__).parent

# ── Veri dizinleri ─────────────────────────────────────────
DATA_DIR          = ROOT / "data"
APK_DIR           = DATA_DIR / "apks"
MALWARE_DIR       = APK_DIR / "malware"
BENIGN_DIR        = APK_DIR / "benign"
FEATURES_DIR      = DATA_DIR / "features"
DYNAMIC_LOGS_DIR  = DATA_DIR / "dynamic_logs"
METADATA_CSV      = DATA_DIR / "metadata.csv"
STATIC_PARQUET    = FEATURES_DIR / "static_features.parquet"
DYNAMIC_PARQUET   = FEATURES_DIR / "dynamic_features.parquet"

# ── Model ve sonuç dizinleri ───────────────────────────────
MODELS_DIR        = ROOT / "models"
RESULTS_DIR       = ROOT / "results"
FIGURES_DIR       = RESULTS_DIR / "figures"
TABLES_DIR        = RESULTS_DIR / "tables"

# ── APK hedef sayıları (yıl → [malware, benign]) ──────────
APK_TARGETS = {
    # [malware, benign]
    # Train: 2016-2021, Val: 2022, Test: 2023
    2016: [625, 625],
    2017: [625, 625],
    2018: [625, 625],
    2019: [625, 625],
    2020: [625, 625],
    2021: [625, 625],
    2022: [625, 625],
    2023: [625, 625],
}

# ── Temporal split ─────────────────────────────────────────
SPLITS = {
    "train": [2016, 2017, 2018, 2019, 2020, 2021],
    "val":   [2022],
    "test":  [2023],
}

# ── Dinamik analiz alt kümesi (yıl → [malware, benign]) ───
DYNAMIC_TARGETS = {
    2016: [50, 0],   # sadece malware (henüz benign yok)
    2019: [50, 50],
    2020: [50, 50],
    2021: [50, 50],
    2022: [50, 50],
    2023: [75, 75],
    2024: [75, 75],
    2025: [100, 100],
    2026: [50, 50],
}

# ── API anahtarları (.env dosyasından okunur) ──────────────
import os as _os
from dotenv import load_dotenv as _load
_load(ROOT / ".env")
ANDROZOO_API_KEY  = _os.getenv("ANDROZOO_API_KEY", "ANDROZOO_KEY_BURAYA")
VT_API_KEY        = _os.getenv("VT_API_KEY", "VIRUSTOTAL_KEY_BURAYA")

# ── Model parametreleri ────────────────────────────────────
LGBM_PARAMS = {
    "n_estimators":  500,
    "learning_rate": 0.05,
    "num_leaves":    63,
    "random_state":  42,
    "n_jobs":        -1,
}

# ── Adaptive fusion eşiği ──────────────────────────────────
DRIFT_THRESHOLD   = 0.80   # statik F1 bu değerin altına düşerse ağırlık kayar
WEIGHT_STEP       = 0.10   # her drift adımında kaç kayar

RANDOM_SEED       = 42
