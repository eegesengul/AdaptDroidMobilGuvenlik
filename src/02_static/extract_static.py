"""
Androguard ile statik feature extraction.
Kullanım:
    python extract_static.py
    python extract_static.py --workers 4
"""
import argparse
import sys
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

import pandas as pd
from tqdm import tqdm

from config import METADATA_CSV, STATIC_PARQUET, FEATURES_DIR

# ── İzlenecek Android izinleri (binary feature) ───────────
PERMISSIONS = [
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CALL_LOG",
    "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS", "READ_CONTACTS",
    "WRITE_CONTACTS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "CAMERA", "RECORD_AUDIO", "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE", "INTERNET", "ACCESS_NETWORK_STATE",
    "ACCESS_WIFI_STATE", "CHANGE_WIFI_STATE", "BLUETOOTH",
    "BLUETOOTH_ADMIN", "RECEIVE_BOOT_COMPLETED", "WAKE_LOCK",
    "VIBRATE", "GET_ACCOUNTS", "USE_CREDENTIALS",
    "AUTHENTICATE_ACCOUNTS", "MANAGE_ACCOUNTS", "READ_PHONE_STATE",
    "CALL_PHONE", "READ_PRIVILEGED_PHONE_STATE",
    "SYSTEM_ALERT_WINDOW", "BIND_DEVICE_ADMIN",
    "RECEIVE_WAP_PUSH", "RECEIVE_MMS", "INSTALL_PACKAGES",
    "DELETE_PACKAGES", "MOUNT_UNMOUNT_FILESYSTEMS",
    "CHANGE_COMPONENT_ENABLED_STATE", "DISABLE_KEYGUARD",
    "STATUS_BAR", "PACKAGE_USAGE_STATS", "REQUEST_INSTALL_PACKAGES",
    "USE_BIOMETRIC", "USE_FINGERPRINT",
]

# ── İzlenecek tehlikeli API çağrıları ──────────────────────
DANGEROUS_APIS = [
    "getDeviceId", "getSubscriberId", "getSimSerialNumber",
    "getImei", "getMeid", "sendTextMessage", "sendMultipartTextMessage",
    "exec", "Runtime", "ProcessBuilder", "loadDex",
    "DexClassLoader", "PathClassLoader", "BaseDexClassLoader",
    "getDeclaredMethod", "getMethod", "invoke",
    "getClass", "forName", "newInstance",
    "Cipher", "SecretKeySpec", "IvParameterSpec",
    "MessageDigest", "KeyGenerator", "KeyPairGenerator",
    "createSocket", "HttpURLConnection", "OkHttpClient",
    "TelephonyManager", "SmsManager", "ContactsContract",
    "ContentResolver", "AccountManager",
    "PackageManager", "getInstalledPackages",
    "ActivityManager", "getRunningServices",
    "PowerManager", "acquireWakeLock",
    "AccessibilityService", "onAccessibilityEvent",
    "DevicePolicyManager", "setPasswordQuality",
    "startActivity", "sendBroadcast", "startService",
]


def extract_features(apk_path: str) -> dict | None:
    try:
        from androguard.misc import AnalyzeAPK
        a, d, dx = AnalyzeAPK(apk_path)

        declared_perms = set(a.get_permissions())
        all_code = " ".join(
            str(m.get_method()) for m in dx.get_methods()
        )
        strings = a.get_strings() or []

        # Permissions (binary)
        perm_feats = {
            f"perm_{p}": int(
                f"android.permission.{p}" in declared_perms
                or p in declared_perms
            )
            for p in PERMISSIONS
        }

        # API calls (binary)
        api_feats = {
            f"api_{a_name}": int(a_name in all_code)
            for a_name in DANGEROUS_APIS
        }

        # Reflection features
        ref_feats = {
            "ref_getDeclaredMethod":  int("getDeclaredMethod" in all_code),
            "ref_invoke":             int(".invoke(" in all_code),
            "ref_forName":            int("forName" in all_code),
            "ref_classLoader":        int("ClassLoader" in all_code),
            "ref_newInstance":        int("newInstance" in all_code),
        }

        # DEX / kod özellikleri
        num_classes = len(list(dx.get_classes()))
        num_methods = len(list(dx.get_methods()))
        str_list    = list(strings)
        num_strings = len(str_list)
        avg_str_len = (
            sum(len(s) for s in str_list) / num_strings
            if num_strings else 0
        )

        dex_feats = {
            "dex_num_classes":   num_classes,
            "dex_num_methods":   num_methods,
            "dex_num_strings":   num_strings,
            "dex_avg_str_len":   round(avg_str_len, 2),
            "dex_has_native":    int(any("native" in str(m.get_access_flags_string())
                                        for m in dx.get_methods())),
        }

        # Anti-analiz / anti-emülatör
        anti_feats = {
            "anti_isEmulator":         int("isEmulator" in all_code),
            "anti_FINGERPRINT":        int("FINGERPRINT" in all_code),
            "anti_isDebuggerConnected":int("isDebuggerConnected" in all_code),
            "anti_checkVPN":           int("checkVPN" in all_code or "VpnService" in all_code),
            "anti_checkRoot":          int("su" in str_list or "superuser" in all_code.lower()),
            "anti_BOARD":              int("android.os.Build" in all_code and
                                          ("BOARD" in all_code or "BRAND" in all_code)),
        }

        # Obfuscation feature'ları
        class_names = [str(c.name) for c in dx.get_classes()]
        short_names  = [n for n in class_names if len(n.split("/")[-1]) <= 2]
        obf_feats = {
            "obf_short_class_ratio":   round(len(short_names) / max(len(class_names), 1), 4),
            "obf_avg_class_name_len":  round(
                sum(len(n.split("/")[-1]) for n in class_names) / max(len(class_names), 1), 2
            ),
            "obf_has_proguard":        int(any("a.a.a" in n or "b.b.b" in n for n in class_names)),
            "obf_high_entropy_strings": int(
                sum(1 for s in str_list if len(s) > 20 and not s.startswith("http")) > 50
            ),
            "obf_num_short_classes":   len(short_names),
        }

        return {**perm_feats, **api_feats, **ref_feats, **dex_feats, **anti_feats, **obf_feats}

    except Exception:
        return None


def process_row(row):
    feats = extract_features(row["apk_path"])
    if feats is None:
        return None
    feats["sha256"] = row["sha256"]
    return feats


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=2,
                        help="Paralel işçi sayısı (RAM'e göre ayarla)")
    parser.add_argument("--resume",  action="store_true",
                        help="Daha önce yapılanları atla")
    args = parser.parse_args()

    meta = pd.read_csv(METADATA_CSV)
    print(f"Toplam APK: {len(meta):,}")

    # Resume desteği
    done_sha = set()
    if args.resume and STATIC_PARQUET.exists():
        done = pd.read_parquet(STATIC_PARQUET, columns=["sha256"])
        done_sha = set(done["sha256"].tolist())
        meta = meta[~meta.sha256.isin(done_sha)]
        print(f"Zaten tamamlanan: {len(done_sha):,} | Kalan: {len(meta):,}")

    rows_list = meta.to_dict("records")
    results   = []
    failed    = 0

    with ProcessPoolExecutor(max_workers=args.workers) as exe:
        futures = {exe.submit(process_row, row): row for row in rows_list}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="Statik extraction"):
            res = fut.result()
            if res:
                results.append(res)
            else:
                failed += 1

    print(f"\nBaşarılı: {len(results):,} | Başarısız: {failed:,}")

    if not results:
        print("Hiç feature çıkarılamadı.")
        return

    df_new = pd.DataFrame(results)

    # Resume modunda var olanla birleştir
    if args.resume and STATIC_PARQUET.exists():
        df_old = pd.read_parquet(STATIC_PARQUET)
        df_new = pd.concat([df_old, df_new], ignore_index=True)

    FEATURES_DIR.mkdir(parents=True, exist_ok=True)
    df_new.to_parquet(STATIC_PARQUET, index=False)
    print(f"\nKaydedildi → {STATIC_PARQUET}")
    print(f"Toplam satır: {len(df_new):,} | Kolon: {len(df_new.columns):,}")


if __name__ == "__main__":
    main()
