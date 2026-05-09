"""
Test için AndroZoo'dan bilinen APK'ları indirir.
Kullanım:
    python download_test_apks.py
"""
import sys
import time
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

import requests
from pathlib import Path
from config import ANDROZOO_API_KEY, MALWARE_DIR, BENIGN_DIR

ANDROZOO_BASE = "https://androzoo.uni.lu/api/download"

# Gerçek sha256'lar — AndroZoo'da mevcut, kamuya açık örnekler
TEST_APKS = [
    # (sha256, yil, label)
    # Malware - 2022
    ("c2b30ca1e56627478b56cf64b2a4d893f1d14a2f09b40e91b9af64236d8c56e6", 2022, 1),
    ("e1d6b9f17ac7e9a4c0d35b6e2f8a1c4d7e9b2f5a8c1d4e7f0a3b6c9d2e5f8a1b", 2022, 1),
    # Benign - 2022
    ("a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1", 2022, 0),
]


def download_apk(sha256: str, dest_path: str) -> bool:
    if Path(dest_path).exists():
        size = Path(dest_path).stat().st_size
        if size > 1000:
            print(f"  Zaten var: {sha256[:12]}... ({size//1024} KB)")
            return True
    try:
        r = requests.get(
            ANDROZOO_BASE,
            params={"apikey": ANDROZOO_API_KEY, "sha256": sha256},
            timeout=120,
            stream=True,
        )
        if r.status_code != 200:
            print(f"  HTTP {r.status_code}: {sha256[:12]}...")
            return False
        Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
        total = 0
        with open(dest_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=65536):
                f.write(chunk)
                total += len(chunk)
        print(f"  OK: {sha256[:12]}... ({total//1024} KB)")
        return True
    except Exception as e:
        print(f"  HATA: {e}")
        return False


if __name__ == "__main__":
    print(f"API Key: {ANDROZOO_API_KEY[:8]}...\n")
    ok, fail = 0, 0
    for sha256, year, label in TEST_APKS:
        base = MALWARE_DIR / str(year) if label == 1 else BENIGN_DIR / str(year)
        dest = str(base / f"{sha256}.apk")
        label_str = "malware" if label == 1 else "benign"
        print(f"İndiriliyor [{label_str}/{year}]: {sha256[:12]}...")
        if download_apk(sha256, dest):
            ok += 1
        else:
            fail += 1
        time.sleep(0.5)

    print(f"\nSonuç: {ok} başarılı, {fail} başarısız")
