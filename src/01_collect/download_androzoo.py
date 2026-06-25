import argparse
import os
import sys
import time
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

import pandas as pd
import requests
from tqdm import tqdm

from config import (
    ANDROZOO_API_KEY, APK_TARGETS, MALWARE_DIR,
    BENIGN_DIR, RANDOM_SEED
)

ANDROZOO_BASE = "https://androzoo.uni.lu/api/download"
MALWARE_MIN_DETECTIONS = 4
BENIGN_MAX_DETECTIONS  = 0

def download_apk(sha256: str, dest_path: str, api_key: str) -> bool:
    if os.path.exists(dest_path):
        return True
    try:
        r = requests.get(
            ANDROZOO_BASE,
            params={"apikey": api_key, "sha256": sha256},
            timeout=60,
            stream=True,
        )
        if r.status_code != 200:
            return False
        with open(dest_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except Exception:
        return False

def load_index(index_path: str) -> pd.DataFrame:
    print(f"Index yükleniyor: {index_path}")
    df = pd.read_csv(index_path, low_memory=False)
    df["year"] = pd.to_datetime(df["dex_date"], errors="coerce").dt.year
    df = df.dropna(subset=["year", "sha256", "vt_detection"])
    df["year"] = df["year"].astype(int)
    df["vt_detection"] = pd.to_numeric(df["vt_detection"], errors="coerce").fillna(0).astype(int)
    print(f"Toplam kayıt: {len(df):,}")
    return df

def download_for_year(df: pd.DataFrame, year: int, label: int, count: int, api_key: str):
    dest_root = MALWARE_DIR / str(year) if label == 1 else BENIGN_DIR / str(year)
    dest_root.mkdir(parents=True, exist_ok=True)

    if label == 1:
        pool = df[(df.year == year) & (df.vt_detection >= MALWARE_MIN_DETECTIONS)]
    else:
        pool = df[(df.year == year) & (df.vt_detection <= BENIGN_MAX_DETECTIONS)]

    already = {f.stem for f in dest_root.glob("*.apk")}
    pool = pool[~pool.sha256.isin(already)]

    sample = pool.sample(min(count - len(already), len(pool)), random_state=RANDOM_SEED)
    if sample.empty:
        print(f"  [{year}] {'malware' if label==1 else 'benign'}: yeterli APK bulunamadı (pool={len(pool)})")
        return

    ok, fail = 0, 0
    for _, row in tqdm(sample.iterrows(), total=len(sample),
                       desc=f"{year} {'mal' if label==1 else 'ben'}"):
        dest = str(dest_root / f"{row.sha256}.apk")
        if download_apk(row.sha256, dest, api_key):
            ok += 1
        else:
            fail += 1
        time.sleep(0.1)

    print(f"  [{year}] {'malware' if label==1 else 'benign'}: {ok} indirildi, {fail} hata")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", required=True, help="androzoo_latest.csv.gz yolu")
    parser.add_argument("--years", nargs="+", type=int, default=list(APK_TARGETS.keys()))
    parser.add_argument("--only", choices=["malware", "benign", "both"], default="both")
    parser.add_argument("--limit", type=int, default=None, help="Her yıl/label için max APK (test için)")
    args = parser.parse_args()

    if ANDROZOO_API_KEY == "ANDROZOO_KEY_BURAYA":
        print("HATA: config.py içinde ANDROZOO_API_KEY ayarla!")
        sys.exit(1)

    df = load_index(args.index)

    for year in args.years:
        mal_count, ben_count = APK_TARGETS.get(year, [0, 0])
        if args.limit:
            mal_count = min(mal_count, args.limit)
            ben_count = min(ben_count, args.limit)
        print(f"\n── {year} ──────────────────────────")
        if args.only in ("malware", "both"):
            download_for_year(df, year, label=1, count=mal_count, api_key=ANDROZOO_API_KEY)
        if args.only in ("benign", "both"):
            download_for_year(df, year, label=0, count=ben_count, api_key=ANDROZOO_API_KEY)

    print("\nTamamlandı.")

if __name__ == "__main__":
    main()
