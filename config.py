from pathlib import Path

ROOT = Path(__file__).parent

DATA_DIR          = ROOT / "data"
APK_DIR           = DATA_DIR / "apks"
MALWARE_DIR       = APK_DIR / "malware"
BENIGN_DIR        = APK_DIR / "benign"
FEATURES_DIR      = DATA_DIR / "features_old"
DYNAMIC_LOGS_DIR  = DATA_DIR / "dynamic_logs"
METADATA_CSV      = DATA_DIR / "metadata.csv"
STATIC_PARQUET    = FEATURES_DIR / "static_features.parquet"
DYNAMIC_PARQUET   = FEATURES_DIR / "dynamic_features.parquet"

MODELS_DIR        = ROOT / "models"
RESULTS_DIR       = ROOT / "results"
FIGURES_DIR       = RESULTS_DIR / "figures"
TABLES_DIR        = RESULTS_DIR / "tables"

APK_TARGETS = {
    2016: [625, 650],
    2017: [625, 650],
    2018: [625, 650],
    2019: [625, 650],
    2020: [625, 650],
    2021: [625, 650],
    2022: [625, 650],
    2023: [625, 650],
}

SPLITS = {
    "train": [2016, 2017, 2018, 2019, 2020, 2021],
    "val":   [2022],
    "test":  [2023],
}

DYNAMIC_TARGETS = {
    2016: [50, 0],
    2017: [50, 0],
    2018: [50, 0],
    2019: [60, 60],
    2020: [50, 50],
    2021: [50, 50],
    2022: [50, 50],
    2023: [75, 75],
    2024: [75, 75],
    2025: [100, 100],
    2026: [50, 50],
}

import os as _os
try:
    from dotenv import load_dotenv as _load
    _load(ROOT / ".env")
except ImportError:
    pass
ANDROZOO_API_KEY  = _os.getenv("ANDROZOO_API_KEY", "ANDROZOO_KEY_BURAYA")
VT_API_KEY        = _os.getenv("VT_API_KEY", "VIRUSTOTAL_KEY_BURAYA")

LGBM_PARAMS = {
    "n_estimators":  500,
    "learning_rate": 0.05,
    "num_leaves":    63,
    "random_state":  42,
    "n_jobs":        -1,
}

DRIFT_THRESHOLD   = 0.80
WEIGHT_STEP       = 0.10

RANDOM_SEED       = 42
