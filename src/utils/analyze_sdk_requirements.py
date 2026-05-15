"""
Dinamik analizi tamamlanmis APK'larin SDK gereksinimlerini analiz eder.
Hangi emulator API seviyesinin kullanilmasi gerektigini belirler.

Kullanim:
    python src/utils/analyze_sdk_requirements.py
    python src/utils/analyze_sdk_requirements.py --apk-base data/apks --features-base data/features
    python src/utils/analyze_sdk_requirements.py --output sdk_report.csv
"""

import argparse
import glob
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pandas as pd


# ── aapt tespiti ──────────────────────────────────────────────

def find_aapt():
    """Android SDK build-tools icindeki aapt.exe'yi bulur."""
    # 1. PATH'te var mi?
    for name in ("aapt", "aapt.exe"):
        try:
            subprocess.run([name, "version"], capture_output=True, timeout=5)
            return name
        except Exception:
            pass

    # 2. ANDROID_HOME / ANDROID_SDK_ROOT env var
    sdk_roots = []
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        val = os.environ.get(var)
        if val:
            sdk_roots.append(val)

    # 3. Varsayilan konumlar
    sdk_roots += [
        os.path.expanduser("~/AppData/Local/Android/Sdk"),   # Windows
        os.path.expanduser("~/Android/Sdk"),                  # Linux
        os.path.expanduser("~/Library/Android/sdk"),          # macOS
        "/opt/android-sdk",
        "/usr/local/lib/android/sdk",
    ]

    for root in sdk_roots:
        pattern = os.path.join(root, "build-tools", "*", "aapt.exe")
        matches = sorted(glob.glob(pattern), reverse=True)
        if not matches:
            pattern = os.path.join(root, "build-tools", "*", "aapt")
            matches = sorted(glob.glob(pattern), reverse=True)
        if matches:
            return matches[0]

    return None


# ── APK SDK okuma ───────────────────────────────────────────���─

def get_sdk(aapt_path, apk_path):
    """aapt dump badging ile minSdk ve targetSdk dondurur."""
    try:
        r = subprocess.run(
            [aapt_path, "dump", "badging", str(apk_path)],
            capture_output=True, timeout=20,
            encoding="utf-8", errors="ignore"
        )
        target = re.search(r"targetSdkVersion:'(\d+)'", r.stdout)
        minsdk = re.search(r"sdkVersion:'(\d+)'", r.stdout)
        return {
            "target_sdk": int(target.group(1)) if target else None,
            "min_sdk":    int(minsdk.group(1)) if minsdk else 1,
        }
    except Exception:
        return {"target_sdk": None, "min_sdk": None}


# ── APK yolu eslestirme ───────────────────────────────────────

def collect_apk_records(features_base, apk_base):
    """
    Dinamik feature parquet'lerindeki sha256'lari APK dosyalariyla eslestirir.
    Doner: [{'sha256', 'label', 'year', 'apk_path'}, ...]
    """
    records = []
    features_base = Path(features_base)
    apk_base = Path(apk_base)

    for label in ("benign", "malware"):
        feat_dir = features_base / f"dynamic_features_{label}"
        if not feat_dir.exists():
            continue
        for year_dir in sorted(feat_dir.iterdir()):
            if not year_dir.is_dir():
                continue
            pq = year_dir / "dynamic_features.parquet"
            if not pq.exists():
                continue
            apk_dir = apk_base / label / year_dir.name
            if not apk_dir.exists():
                continue

            df = pd.read_parquet(pq, columns=["sha256"])

            # Klasordeki tum APK'lari once indekse al (hizli eslesme)
            apk_index = {}
            for f in apk_dir.glob("*.apk"):
                apk_index[f.stem.upper()] = f

            for sha in df["sha256"]:
                key = str(sha).upper()
                apk_path = apk_index.get(key)
                if apk_path:
                    records.append({
                        "sha256":   key,
                        "label":    label,
                        "year":     int(year_dir.name),
                        "apk_path": apk_path,
                    })

    return records


# ── Rapor ─────────────────────────────────────────────────────

def print_report(df):
    total = len(df)
    print(f"\n{'='*60}")
    print(f" SDK GEREKSINIM RAPORU  ({total} APK)")
    print(f"{'='*60}")

    print(f"\nminSdkVersion  aralik : {int(df['min_sdk'].min())} - {int(df['min_sdk'].max())}")
    print(f"targetSdkVersion aralik: {int(df['target_sdk'].min())} - {int(df['target_sdk'].max())}")

    print("\n--- minSdkVersion dagilimi ---")
    print(df["min_sdk"].value_counts().sort_index().to_string())

    print("\n--- targetSdkVersion dagilimi ---")
    print(df["target_sdk"].value_counts().sort_index().to_string())

    print("\n--- Yil x Label bazli targetSdk (min/max/ortalama) ---")
    grp = df.groupby(["label", "year"])["target_sdk"].agg(["min", "max", "mean"]).round(1)
    print(grp.to_string())

    # Emulator API karsilastirmasi
    android_names = {
        28: "9 Pie", 29: "10", 30: "11", 31: "12",
        32: "12L", 33: "13", 34: "14", 35: "15",
    }
    # Android 14+ (API 33+) low-target-sdk block: targetSdk < 23
    bypass_count = int((df["target_sdk"] < 23).sum())

    print("\n--- Emulator API seviyesi karsilastirmasi ---")
    header = f"{'API':>5}  {'Android':>10}  {'native calisan':>16}  {'bypass gereken':>14}  {'targetSdk asiliyor':>18}"
    print(header)
    print("-" * len(header))
    for api in (28, 29, 30, 31, 32, 33, 34, 35):
        native   = int((df["min_sdk"] <= api).sum())
        pct      = native / total * 100
        over_tgt = int((df["target_sdk"] > api).sum())
        aname    = android_names.get(api, "")
        print(
            f"{api:>5}  {aname:>10}  "
            f"{native:>5}/{total} ({pct:>3.0f}%)  "
            f"{bypass_count:>14}  "
            f"{over_tgt:>18}"
        )

    # Oneri
    min_sdk_max = int(df["min_sdk"].max())
    recommended = max(min_sdk_max, 29)
    # targetSdk'larin %95'ini karsilayan en kucuk API
    for api in range(28, 36):
        over = int((df["target_sdk"] > api).sum())
        if over / total <= 0.05:
            recommended = api
            break

    print(f"\nONERILEN EMULATOR: API {recommended} (Android {android_names.get(recommended, '')})")
    print(f"  - Tum APK'larin minSdk'si <= {recommended}")
    print(f"  - targetSdk'larin %{100 - int((df['target_sdk'] > recommended).sum())/total*100:.0f}'ini karsilar")
    if bypass_count:
        print(f"  - {bypass_count} APK icin --bypass-low-target-sdk-block gerekiyor (pipeline'da mevcut)")
    print()


# ── main ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Dinamik analiz APK SDK gereksinim analizi")
    parser.add_argument("--apk-base",      default="data/apks",
                        help="APK klasorlerinin kok dizini (varsayilan: data/apks)")
    parser.add_argument("--features-base", default="data/features",
                        help="Feature parquet'lerinin kok dizini (varsayilan: data/features)")
    parser.add_argument("--output",        default=None,
                        help="Sonuclari CSV olarak kaydet")
    parser.add_argument("--workers",       type=int, default=8,
                        help="Paralel is parcacigi sayisi (varsayilan: 8)")
    args = parser.parse_args()

    # aapt bul
    aapt = find_aapt()
    if not aapt:
        print("HATA: aapt bulunamadi. Android SDK'nin PATH'te oldugunu dogrulayin.")
        print("  Ornek: set ANDROID_HOME=C:\\Users\\<kullanici>\\AppData\\Local\\Android\\Sdk")
        sys.exit(1)
    print(f"aapt: {aapt}")

    # APK kayitlarini topla
    print(f"APK yollari taranıyor: {args.apk_base}")
    records = collect_apk_records(args.features_base, args.apk_base)
    total_parquet = sum(
        len(pd.read_parquet(p, columns=["sha256"]))
        for p in Path(args.features_base).glob("dynamic_features_*/*/dynamic_features.parquet")
    )
    print(f"Parquet'te toplam APK : {total_parquet}")
    print(f"Dosyasi bulunan APK   : {len(records)}")
    if not records:
        print("HATA: Eslesecek APK dosyasi bulunamadi.")
        sys.exit(1)

    # aapt paralel calistir
    print(f"SDK bilgisi okunuyor ({args.workers} is parcacigi)...")
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(get_sdk, aapt, r["apk_path"]): r for r in records}
        done = 0
        for fut in as_completed(futs):
            row = futs[fut]
            sdk = fut.result()
            results.append({**row, "apk_path": str(row["apk_path"]), **sdk})
            done += 1
            if done % 100 == 0:
                print(f"  {done}/{len(records)} islendi...")

    df = pd.DataFrame(results)
    df = df.dropna(subset=["target_sdk", "min_sdk"])
    df["target_sdk"] = df["target_sdk"].astype(int)
    df["min_sdk"]    = df["min_sdk"].astype(int)

    print_report(df)

    if args.output:
        out_path = Path(args.output)
        df.to_csv(out_path, index=False)
        print(f"CSV kaydedildi: {out_path}")


if __name__ == "__main__":
    main()
