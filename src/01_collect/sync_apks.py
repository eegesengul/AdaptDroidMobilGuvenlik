"""
İki bilgisayar arasında APK koleksiyonunu senkronize eder.

Kullanım:
    # Bu bilgisayarda: mevcut APK listesini dışa aktar
    python sync_apks.py --export

    # Diğer bilgisayarda: eksik APK'ları indir
    python sync_apks.py --sync --manifest apk_manifest.txt

    # Ne indirileceğini görmek için (indirmeden):
    python sync_apks.py --sync --dry-run

Benign APK'lar F-Droid'dan, malware APK'lar AndroZoo'dan indirilir.
"""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2]))

import requests
from tqdm import tqdm

from config import ANDROZOO_API_KEY, APK_DIR

FDROID_BASE   = "https://f-droid.org/repo/"
ANDROZOO_BASE = "https://androzoo.uni.lu/api/download"


# ── Yardımcılar ────────────────────────────────────────────

def scan_local_apks() -> list:
    """data/apks/ altındaki tüm APK'ları relative path olarak döner."""
    entries = []
    for apk in sorted(APK_DIR.rglob("*.apk")):
        rel = apk.relative_to(APK_DIR)   # orn: malware/2017/ABCD.apk
        entries.append(str(rel).replace("\\", "/"))
    return entries


def download_file(url, dest, params=None):
    if dest.exists():
        return True
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    try:
        r = requests.get(url, params=params, timeout=120, stream=True)
        if r.status_code != 200:
            return False
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(chunk_size=65536):
                f.write(chunk)
        tmp.rename(dest)
        return True
    except Exception as e:
        print(f"    HATA: {e}")
        if tmp.exists():
            tmp.unlink()
        return False


def download_benign(filename, dest):
    """F-Droid'dan benign APK indir. URL doğrudan dosya adından kurulur."""
    return download_file(FDROID_BASE + filename, dest)


def download_malware(sha256, dest):
    """AndroZoo'dan SHA256 ile malware APK indir."""
    if not ANDROZOO_API_KEY or ANDROZOO_API_KEY == "ANDROZOO_KEY_BURAYA":
        print("    HATA: ANDROZOO_API_KEY .env dosyasında tanımlı değil.")
        return False
    return download_file(ANDROZOO_BASE, dest,
                         params={"apikey": ANDROZOO_API_KEY, "sha256": sha256})


# ── Export ─────────────────────────────────────────────────

def cmd_export(out_path, label_filter=None):
    entries = scan_local_apks()
    if label_filter:
        entries = [e for e in entries if e.startswith(label_filter + "/")]
    out_path.write_text("\n".join(entries), encoding="utf-8")
    print(f"Manifest yazıldı -> {out_path}  ({len(entries):,} APK)")

    from collections import Counter
    labels = Counter(e.split("/")[0] for e in entries)
    years  = Counter(e.split("/")[1] for e in entries if len(e.split("/")) >= 3)
    print("\nLabel dağılımı:")
    for k, v in sorted(labels.items()):
        print(f"  {k}: {v:,}")
    print("\nYıl dağılımı:")
    for k, v in sorted(years.items()):
        print(f"  {k}: {v:,}")
    print(f"\nBu dosyayı diğer bilgisayara kopyala, sonra:\n"
          f"  python src/01_collect/sync_apks.py --sync --manifest {out_path.name}")


# ── Sync ───────────────────────────────────────────────────

def cmd_sync(manifest_path, dry_run=False, label_filter=None):
    if not manifest_path.exists():
        print(f"HATA: manifest bulunamadı: {manifest_path}")
        print("Kaynak bilgisayarda önce: python sync_apks.py --export")
        sys.exit(1)

    desired = [l.strip() for l in manifest_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    if label_filter:
        desired = [e for e in desired if e.startswith(label_filter + "/")]
    local   = set(scan_local_apks())

    missing = [e for e in desired if e not in local]
    print(f"Manifest : {len(desired):,} APK")
    print(f"Yerel    : {len(desired) - len(missing):,} mevcut, {len(missing):,} eksik")

    if not missing:
        print("Tüm APK'lar mevcut, indirme gerekmez.")
        return

    if dry_run:
        print("\n-- DRY RUN: indirilecek dosyalar (ilk 20) --")
        for e in missing[:20]:
            print(f"  {e}")
        if len(missing) > 20:
            print(f"  ... ve {len(missing) - 20} tane daha")
        return

    ok = fail = skip = 0
    with tqdm(missing, desc="İndiriliyor") as bar:
        for rel_path in bar:
            parts = rel_path.split("/")   # [label, year, filename]
            if len(parts) != 3:
                skip += 1
                continue

            label, year, filename = parts
            dest = APK_DIR / label / year / filename

            if label == "benign":
                success = download_benign(filename, dest)
            elif label == "malware":
                sha256 = Path(filename).stem.upper()
                success = download_malware(sha256, dest)
            else:
                skip += 1
                continue

            if success:
                ok += 1
            else:
                fail += 1
            bar.set_postfix_str(f"OK:{ok} HATA:{fail}")
            time.sleep(0.05)

    print(f"\nTamamlandı — indirildi: {ok:,} | hata: {fail:,} | atlandı: {skip:,}")
    if fail:
        print("Hatalı dosyalar için tekrar çalıştır, mevcutlar otomatik atlanır.")


# ── CLI ────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="APK koleksiyonu senkronizasyonu")
    parser.add_argument("--export",   action="store_true", help="Bu bilgisayardaki APK listesini dışa aktar")
    parser.add_argument("--sync",     action="store_true", help="Manifest'e göre eksik APK'ları indir")
    parser.add_argument("--manifest", default="apk_manifest.txt", help="Manifest dosyası (--sync için)")
    parser.add_argument("--out",      default="apk_manifest.txt", help="Çıktı dosyası (--export için)")
    parser.add_argument("--dry-run",  action="store_true", help="İndirmeden ne yapılacağını göster")
    parser.add_argument("--label",    choices=["benign", "malware"], default=None,
                        help="Sadece bu label'ı işle (varsayılan: ikisi de)")
    args = parser.parse_args()

    if args.export:
        cmd_export(Path(args.out), label_filter=args.label)
    elif args.sync:
        cmd_sync(Path(args.manifest), dry_run=args.dry_run, label_filter=args.label)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
