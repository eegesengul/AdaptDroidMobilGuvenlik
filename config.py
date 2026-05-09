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
    2019: [650, 650],
    2020: [650, 650],
    2021: [650, 650],
    2022: [650, 650],
    2023: [700, 700],
    2024: [700, 700],
    2025: [600, 600],
    2026: [400, 400],
}

# ── Temporal split ─────────────────────────────────────────
SPLITS = {
    "train": [2019, 2020, 2021, 2022],
    "val":   [2023],
    "test1": [2024],
    "test2": [2025],
    "test3": [2026],
}

# ── Dinamik analiz alt kümesi (yıl → [malware, benign]) ───
DYNAMIC_TARGETS = {
    2019: [50, 50],
    2020: [50, 50],
    2021: [50, 50],
    2022: [50, 50],
    2023: [75, 75],
    2024: [75, 75],
    2025: [100, 100],
    2026: [50, 50],
}

# ── API anahtarları (kendi keylerini gir) ──────────────────
ANDROZOO_API_KEY  = "ANDROZOO_KEY_BURAYA"
VT_API_KEY        = "VIRUSTOTAL_KEY_BURAYA"

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
