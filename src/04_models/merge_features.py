"""
Statik ve dinamik feature'ları metadata ile birleştirir.
Çıktı: data/features/merged_features.parquet

Kullanım:
    python merge_features.py
    python merge_features.py --static-only   # dinamik analiz henüz yapılmadıysa
"""
import argparse
import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

import pandas as pd
import numpy as np

from config import (
    METADATA_CSV, STATIC_PARQUET, DYNAMIC_PARQUET, FEATURES_DIR
)

MERGED_PARQUET = FEATURES_DIR / "merged_features.parquet"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--static-only", action="store_true",
                        help="Sadece statik feature'ları kullan")
    args = parser.parse_args()

    # ── Metadata ──────────────────────────────────────────
    print("Metadata yükleniyor...")
    meta = pd.read_csv(METADATA_CSV)
    meta = meta[["sha256", "year", "label", "split", "in_dynamic"]].copy()
    print(f"  Toplam APK: {len(meta):,}")

    # ── Statik features ───────────────────────────────────
    if not STATIC_PARQUET.exists():
        print("HATA: static_features.parquet bulunamadı.")
        print("Önce: python src/02_static/extract_static.py")
        sys.exit(1)

    print("Statik features yükleniyor...")
    static_df = pd.read_parquet(STATIC_PARQUET)
    print(f"  Satır: {len(static_df):,} | Kolon: {len(static_df.columns):,}")

    # ── Merge: metadata + static ──────────────────────────
    df = meta.merge(static_df, on="sha256", how="inner")
    print(f"\nMetadata + Statik birleşimi: {len(df):,} satır")

    # ── Dinamik features ──────────────────────────────────
    if not args.static_only:
        if not DYNAMIC_PARQUET.exists():
            print("UYARI: dynamic_features.parquet bulunamadı.")
            print("  Dinamik özellikler sıfır olarak doldurulacak.")
            args.static_only = True
        else:
            print("Dinamik features yükleniyor...")
            dyn_df = pd.read_parquet(DYNAMIC_PARQUET)
            print(f"  Satır: {len(dyn_df):,} | Kolon: {len(dyn_df.columns):,}")
            df = df.merge(dyn_df, on="sha256", how="left")
            # Dinamik analiz yapılmayan APK'larda NaN -> 0
            dyn_cols = [c for c in dyn_df.columns if c != "sha256"]
            df[dyn_cols] = df[dyn_cols].fillna(0)
            print(f"  Dinamik analiz yapılan: {df['frida_used'].sum():,.0f} APK")

    if args.static_only:
        print("Sadece statik modda çalışılıyor.")

    # ── Eksik değer doldur ────────────────────────────────
    feature_cols = [c for c in df.columns
                    if c not in ["sha256", "year", "label", "split", "in_dynamic"]]
    missing_before = df[feature_cols].isna().sum().sum()
    if missing_before > 0:
        print(f"\nEksik değer: {missing_before:,} -> 0 ile dolduruluyor")
        df[feature_cols] = df[feature_cols].fillna(0)

    # ── Özet ──────────────────────────────────────────────
    print(f"\n{'='*50}")
    print(f"Birleşik veri seti özeti:")
    print(f"  Toplam satır    : {len(df):,}")
    print(f"  Toplam özellik  : {len(feature_cols):,}")
    print(f"  Malware         : {(df.label==1).sum():,}")
    print(f"  Benign          : {(df.label==0).sum():,}")
    print(f"\nSplit dağılımı:")
    print(df.groupby(["split", "label"]).size().unstack(fill_value=0).to_string())

    print(f"\nÖzellik grupları:")
    for prefix in ["perm_", "api_", "ref_", "dex_", "anti_", "obf_",
                   "manifest_", "file_", "net_",
                   "frida_", "network_event", "dns_", "crypto_",
                   "dex_loader", "runtime_exec", "sms_", "contact_",
                   "reflection_count", "native_lib", "camera_",
                   "mic_", "location_", "clipboard_", "device_admin",
                   "wakelock_", "exception_"]:
        count = sum(1 for c in feature_cols if c.startswith(prefix))
        if count:
            print(f"  {prefix:<25} {count:>3} özellik")

    # ── Kaydet ────────────────────────────────────────────
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)
    df.to_parquet(MERGED_PARQUET, index=False)
    print(f"\nKaydedildi -> {MERGED_PARQUET}")


if __name__ == "__main__":
    main()
