"""
F-Droid'dan yıl bazlı benign APK indirme scripti.
Kullanım:
    python download_fdroid.py --years 2019 2020 2021
"""
import argparse
import os
import sys
import time
from datetime import datetime
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

import requests
from tqdm import tqdm

from config import APK_TARGETS, BENIGN_DIR, RANDOM_SEED

FDROID_INDEX = "https://f-droid.org/repo/index-v2.json"
FDROID_BASE  = "https://f-droid.org/repo/"


def fetch_index() -> dict:
    print("F-Droid index indiriliyor (~50MB)...")
    r = requests.get(FDROID_INDEX, timeout=120)
    return r.json()


def collect_candidates(index: dict, target_years: list) -> dict:
    """Yıl → APK URL listesi döner."""
    candidates = {y: [] for y in target_years}

    for pkg_name, pkg_data in index.get("packages", {}).items():
        for ver_code, ver in pkg_data.get("versions", {}).items():
            added_ms = ver.get("added", 0)
            if not added_ms:
                continue
            year = datetime.fromtimestamp(added_ms / 1000).year
            if year not in candidates:
                continue
            file_info = ver.get("file", {})
            fname = file_info.get("name", "")
            if not fname.endswith(".apk"):
                continue
            candidates[year].append({
                "url":    FDROID_BASE + fname.lstrip("/"),
                "name":   fname,
                "pkg":    pkg_name,
                "year":   year,
            })
    return candidates


def download_apk(url: str, dest_path: str) -> bool:
    if os.path.exists(dest_path):
        return True
    try:
        r = requests.get(url, timeout=60, stream=True)
        if r.status_code != 200:
            return False
        with open(dest_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--years", nargs="+", type=int, default=list(APK_TARGETS.keys()))
    args = parser.parse_args()

    index = fetch_index()
    candidates = collect_candidates(index, args.years)

    import random
    random.seed(RANDOM_SEED)

    for year in args.years:
        target_count = APK_TARGETS.get(year, [0, 0])[1]
        pool = candidates.get(year, [])
        random.shuffle(pool)

        dest_dir = BENIGN_DIR / str(year)
        dest_dir.mkdir(parents=True, exist_ok=True)

        already = len(list(dest_dir.glob("*.apk")))
        remaining = target_count - already
        if remaining <= 0:
            print(f"[{year}] Zaten tamamlanmış ({already} APK)")
            continue

        print(f"\n── {year}: {remaining} benign APK indirilecek ──")
        ok, fail = 0, 0
        for item in tqdm(pool[:remaining], desc=f"F-Droid {year}"):
            # dosya adını sha-benzeri yap (paket adı + ver)
            safe_name = item["pkg"].replace(".", "_") + ".apk"
            dest = str(dest_dir / safe_name)
            if download_apk(item["url"], dest):
                ok += 1
            else:
                fail += 1
            time.sleep(0.1)

        print(f"  [{year}] benign: {ok} indirildi, {fail} hata")

    print("\nTamamlandı.")


if __name__ == "__main__":
    main()
