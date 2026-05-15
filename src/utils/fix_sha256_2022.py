"""
2022 malware static parquet sha256 duzeltme.
Kullanim:
    python fix_sha256_2022.py --apk-dir "C:/yol/2022_malware_apklar"
"""
import hashlib
import argparse
from pathlib import Path
import pandas as pd


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk-dir", required=True, help="2022 malware APK klasoru")
    parser.add_argument("--parquet", default=None,
                        help="Guncellenecek parquet (varsayilan: apk-dir yaninda)")
    args = parser.parse_args()

    apk_dir = Path(args.apk_dir)
    apks = list(apk_dir.glob("*.apk"))
    print(f"APK sayisi: {len(apks)}")

    # paket_adi -> SHA256 hash eslesme tablosu
    mapping = {}
    for i, apk in enumerate(apks, 1):
        pkg_name = apk.stem          # com.easysay.german_415
        sha = sha256_of_file(str(apk))
        mapping[pkg_name] = sha
        if i % 50 == 0 or i == len(apks):
            print(f"  {i}/{len(apks)} islendi...")

    print(f"\nEslestirme tablosu hazir: {len(mapping)} APK")

    # Parquet yolunu bul
    if args.parquet:
        parquet_path = Path(args.parquet)
    else:
        parquet_path = apk_dir.parent / "static_features.parquet"
        if not parquet_path.exists():
            # Dene
            candidates = list(apk_dir.parent.rglob("static_features.parquet"))
            if candidates:
                parquet_path = candidates[0]
            else:
                print("Parquet dosyasi bulunamadi. --parquet ile belirt.")
                return

    print(f"Parquet: {parquet_path}")
    df = pd.read_parquet(parquet_path)
    print(f"Mevcut satir: {len(df)} | sha256 ornegi: {df['sha256'].iloc[0]}")

    # Guncelle
    df["sha256_eski"] = df["sha256"]          # yedek kolon
    df["sha256"] = df["sha256_eski"].map(mapping)

    eslesen = df["sha256"].notna().sum()
    eslesmeen = df["sha256"].isna().sum()
    print(f"\nEslesen: {eslesen} / {len(df)}")
    if eslesmeen > 0:
        print(f"Eslesmeyen (APK bulunamadi): {eslesmeen}")
        print(df[df["sha256"].isna()]["sha256_eski"].head(5).tolist())

    df = df.dropna(subset=["sha256"])
    df = df.drop(columns=["sha256_eski"])

    # Kaydet
    out = parquet_path.parent / "static_features_fixed.parquet"
    df.to_parquet(out, index=False)
    print(f"\nKaydedildi: {out}")
    print(f"Toplam satir: {len(df)}")
    print(f"Yeni sha256 ornegi: {df['sha256'].iloc[0]}")


if __name__ == "__main__":
    main()
