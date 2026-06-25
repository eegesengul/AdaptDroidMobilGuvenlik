import hashlib
import os
import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

import pandas as pd
from tqdm import tqdm

from config import (
    MALWARE_DIR, BENIGN_DIR, METADATA_CSV,
    SPLITS, DYNAMIC_TARGETS, RANDOM_SEED
)

def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def year_to_split(year: int) -> str:
    for split_name, years in SPLITS.items():
        if year in years:
            return split_name
    return "unknown"

def collect_apks() -> list:
    rows = []

    for label, base_dir in [(1, MALWARE_DIR), (0, BENIGN_DIR)]:
        label_str = "malware" if label == 1 else "benign"
        for year_dir in sorted(base_dir.iterdir()):
            if not year_dir.is_dir():
                continue
            try:
                year = int(year_dir.name)
            except ValueError:
                continue
            apks = list(year_dir.glob("*.apk"))
            for apk_path in tqdm(apks, desc=f"{label_str}/{year}"):
                rows.append({
                    "sha256":        apk_path.stem,
                    "apk_path":      str(apk_path),
                    "year":          year,
                    "label":         label,
                    "source":        label_str,
                    "vt_detection":  -1,
                    "split":         year_to_split(year),
                    "in_dynamic":    0,
                })
    return rows

def get_abi(apk_path: str) -> str:
    import zipfile
    try:
        with zipfile.ZipFile(apk_path) as z:
            libs = [n for n in z.namelist()
                    if n.startswith("lib/") and n.endswith(".so")]
            if not libs:
                return "none"

            has_64 = False
            has_32_only = False
            for lib in libs:
                folder = lib.split("/")[1] if len(lib.split("/")) > 2 else ""
                if folder in ("x86_64", "arm64-v8a"):
                    expected_64 = True
                elif folder in ("x86", "armeabi", "armeabi-v7a"):
                    expected_64 = False
                else:
                    continue

                try:
                    data = z.read(lib, )[:8]
                    if data[:4] == b'\x7fELF':
                        actual_64 = (data[4] == 2)
                    else:
                        actual_64 = expected_64
                except Exception:
                    actual_64 = expected_64

                if actual_64:
                    has_64 = True
                else:
                    has_32_only = True

            if has_64:
                return "compat"
            if has_32_only:
                return "armeabi_only"
            return "none"
    except Exception:
        return "unknown"

def assign_dynamic_subset(df: pd.DataFrame) -> pd.DataFrame:
    import random
    random.seed(RANDOM_SEED)
    df = df.copy()
    df["in_dynamic"] = 0

    for year, (mal_n, ben_n) in DYNAMIC_TARGETS.items():
        for label, n in [(1, mal_n), (0, ben_n)]:
            pool_df = df[(df.year == year) & (df.label == label)]
            if pool_df.empty or n == 0:
                continue

            pool_df = pool_df.copy()
            pool_df["_abi"] = pool_df["apk_path"].apply(get_abi)
            compat = pool_df[pool_df["_abi"].isin(["none", "compat"])].index.tolist()
            other  = pool_df[pool_df["_abi"] == "armeabi_only"].index.tolist()

            chosen = random.sample(compat, min(n, len(compat)))
            if len(chosen) < n:
                extra = random.sample(other, min(n - len(chosen), len(other)))
                chosen += extra

            df.loc[chosen, "in_dynamic"] = 1
            compat_count = sum(1 for c in chosen if c in set(compat))
            print(f"  {year} label={label}: {len(chosen)} seçildi "
                  f"({compat_count} uyumlu, {len(chosen)-compat_count} armeabi)")

    return df

def main():
    print("APK'lar taranıyor...")
    rows = collect_apks()

    if not rows:
        print("Hiç APK bulunamadı. Önce download scriptlerini çalıştır.")
        return

    df = pd.DataFrame(rows)
    df = df.drop_duplicates(subset="sha256")
    df = assign_dynamic_subset(df)

    METADATA_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(METADATA_CSV, index=False)

    print(f"\nmetadata.csv oluşturuldu -> {METADATA_CSV}")
    print(f"Toplam APK : {len(df):,}")
    print(f"  Malware  : {(df.label==1).sum():,}")
    print(f"  Benign   : {(df.label==0).sum():,}")
    print(f"  Dinamik  : {df.in_dynamic.sum():,}")
    print("\nYıl dağılımı:")
    print(df.groupby(["year", "label"]).size().unstack(fill_value=0).to_string())

if __name__ == "__main__":
    main()
