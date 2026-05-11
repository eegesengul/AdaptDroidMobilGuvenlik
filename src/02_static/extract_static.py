"""
Androguard ile statik feature extraction.
Kullanım:
    python extract_static.py
    python extract_static.py --workers 4
"""
import argparse
import sys
import os
import logging
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[2]))

logging.getLogger("androguard").setLevel(logging.ERROR)
from loguru import logger as _loguru; _loguru.disable("androguard")

import pandas as pd
from tqdm import tqdm

from config import METADATA_CSV, STATIC_PARQUET, FEATURES_DIR

# ── İzlenecek Android izinleri (binary feature) ───────────
PERMISSIONS = [
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CALL_LOG",
    "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS", "READ_CONTACTS",
    "WRITE_CONTACTS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION", "CAMERA", "RECORD_AUDIO",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "MANAGE_EXTERNAL_STORAGE", "INTERNET", "ACCESS_NETWORK_STATE",
    "ACCESS_WIFI_STATE", "CHANGE_WIFI_STATE", "CHANGE_NETWORK_STATE",
    "BLUETOOTH", "BLUETOOTH_ADMIN", "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN",
    "RECEIVE_BOOT_COMPLETED", "WAKE_LOCK", "VIBRATE",
    "GET_ACCOUNTS", "USE_CREDENTIALS", "AUTHENTICATE_ACCOUNTS",
    "MANAGE_ACCOUNTS", "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    "CALL_PHONE", "READ_PRIVILEGED_PHONE_STATE",
    "SYSTEM_ALERT_WINDOW", "BIND_DEVICE_ADMIN",
    "RECEIVE_WAP_PUSH", "RECEIVE_MMS", "INSTALL_PACKAGES",
    "DELETE_PACKAGES", "MOUNT_UNMOUNT_FILESYSTEMS",
    "CHANGE_COMPONENT_ENABLED_STATE", "DISABLE_KEYGUARD",
    "STATUS_BAR", "PACKAGE_USAGE_STATS", "REQUEST_INSTALL_PACKAGES",
    "USE_BIOMETRIC", "USE_FINGERPRINT", "FOREGROUND_SERVICE",
    "HIDE_OVERLAY_WINDOWS", "SCHEDULE_EXACT_ALARM",
    "ACCESS_NOTIFICATION_POLICY", "BIND_ACCESSIBILITY_SERVICE",
    "BIND_NOTIFICATION_LISTENER_SERVICE",
]

# ── İzlenecek tehlikeli API çağrıları ──────────────────────
DANGEROUS_APIS = [
    "getDeviceId", "getSubscriberId", "getSimSerialNumber",
    "getImei", "getMeid", "sendTextMessage", "sendMultipartTextMessage",
    "exec", "Runtime", "ProcessBuilder", "loadDex",
    "DexClassLoader", "PathClassLoader", "BaseDexClassLoader",
    "InMemoryDexClassLoader",
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
    "ClipboardManager", "getPrimaryClip",
    "LocationManager", "getLastKnownLocation",
    "MediaRecorder", "AudioRecord",
    "Camera", "CameraManager",
    "AlarmManager", "setExact",
    "NotificationManager", "createNotificationChannel",
    "JobScheduler", "WorkManager",
    "Base64", "URLEncoder",
    "ZipFile", "ZipInputStream",
    "SharedPreferences", "getSharedPreferences",
    "SQLiteDatabase", "openDatabase",
    "Binder", "IBinder", "AIDL",
    "WebView", "loadUrl", "evaluateJavascript",
    "addJavascriptInterface",
]


def extract_features(apk_path: str) -> dict | None:
    try:
        import logging; logging.getLogger("androguard").setLevel(logging.ERROR)
        from loguru import logger as _lg; _lg.disable("androguard")
        from androguard.misc import AnalyzeAPK
        a, d, dx = AnalyzeAPK(apk_path)

        declared_perms = set(a.get_permissions())
        # class_name + name + descriptor — disassembly olmadan, hızlı
        all_code = " ".join(
            f"{m.class_name} {m.name} {m.descriptor}"
            for m in dx.get_methods()
        )
        # Androguard 4.x: strings DEX nesnesinde, APK'da değil
        str_list = []
        if isinstance(d, list):
            for dex in d:
                str_list.extend(str(s) for s in dex.get_strings())
        elif d is not None:
            str_list = [str(s) for s in d.get_strings()]

        # ── 1. İzinler (binary) ───────────────────────────
        perm_feats = {
            f"perm_{p}": int(
                f"android.permission.{p}" in declared_perms or p in declared_perms
            )
            for p in PERMISSIONS
        }

        # ── 2. API çağrıları (binary) ─────────────────────
        api_feats = {
            f"api_{a_name}": int(a_name in all_code)
            for a_name in DANGEROUS_APIS
        }

        # ── 3. Reflection ─────────────────────────────────
        ref_feats = {
            "ref_getDeclaredMethod": int("getDeclaredMethod" in all_code),
            "ref_invoke":            int(".invoke(" in all_code),
            "ref_forName":           int("forName" in all_code),
            "ref_classLoader":       int("ClassLoader" in all_code),
            "ref_newInstance":       int("newInstance" in all_code),
        }

        # ── 4. DEX / kod özellikleri ──────────────────────
        classes     = list(dx.get_classes())
        methods     = list(dx.get_methods())
        num_classes = len(classes)
        num_methods = len(methods)
        num_strings = len(str_list)
        avg_str_len = (
            sum(len(s) for s in str_list) / num_strings if num_strings else 0
        )
        num_native_methods = sum(
            1 for m in methods
            if "native" in str(m.get_access_flags_string())
        )

        dex_feats = {
            "dex_num_classes":        num_classes,
            "dex_num_methods":        num_methods,
            "dex_num_strings":        num_strings,
            "dex_avg_str_len":        round(avg_str_len, 2),
            "dex_has_native":         int(num_native_methods > 0),
            "dex_num_native_methods": num_native_methods,
            "dex_methods_per_class":  round(num_methods / max(num_classes, 1), 2),
        }

        # ── 5. Anti-analiz / anti-emülatör ───────────────
        anti_feats = {
            "anti_isEmulator":          int("isEmulator" in all_code),
            "anti_FINGERPRINT":         int("FINGERPRINT" in all_code),
            "anti_isDebuggerConnected": int("isDebuggerConnected" in all_code),
            "anti_checkVPN":            int("checkVPN" in all_code or "VpnService" in all_code),
            "anti_checkRoot":           int("su" in str_list or "superuser" in all_code.lower()),
            "anti_BOARD":               int("android.os.Build" in all_code and
                                           ("BOARD" in all_code or "BRAND" in all_code)),
            "anti_EMULATOR_str":        int(any("emulator" in s.lower() for s in str_list)),
            "anti_hook_detect":         int("frida" in all_code.lower() or
                                           "xposed" in all_code.lower() or
                                           "substrate" in all_code.lower()),
        }

        # ── 6. Obfuscation ────────────────────────────────
        class_names = [str(c.name) for c in classes]
        short_names = [n for n in class_names if len(n.split("/")[-1]) <= 2]
        obf_feats = {
            "obf_short_class_ratio":    round(len(short_names) / max(len(class_names), 1), 4),
            "obf_avg_class_name_len":   round(
                sum(len(n.split("/")[-1]) for n in class_names) / max(len(class_names), 1), 2
            ),
            "obf_has_proguard":         int(any("a.a.a" in n or "b.b.b" in n for n in class_names)),
            "obf_high_entropy_strings": int(
                sum(1 for s in str_list if len(s) > 20 and not s.startswith("http")) > 50
            ),
            "obf_num_short_classes":    len(short_names),
            "obf_num_long_strings":     sum(1 for s in str_list if len(s) > 50),
            "obf_url_count":            sum(1 for s in str_list if s.startswith("http")),
            "obf_ip_count":             sum(1 for s in str_list
                                            if len(s.split(".")) == 4 and
                                            all(p.isdigit() for p in s.split("."))),
        }

        # ── 7. Manifest bileşenleri ───────────────────────
        try:
            activities  = a.get_activities()  or []
            services    = a.get_services()    or []
            receivers   = a.get_receivers()   or []
            providers   = a.get_providers()   or []
            min_sdk     = int(a.get_min_sdk_version()  or 0)
            target_sdk  = int(a.get_target_sdk_version() or 0)
        except Exception:
            activities = services = receivers = providers = []
            min_sdk = target_sdk = 0

        manifest_feats = {
            "manifest_activity_count":   len(activities),
            "manifest_service_count":    len(services),
            "manifest_receiver_count":   len(receivers),
            "manifest_provider_count":   len(providers),
            "manifest_component_total":  len(activities) + len(services) + len(receivers) + len(providers),
            "manifest_min_sdk":          min_sdk,
            "manifest_target_sdk":       target_sdk,
            "manifest_perm_count":       len(declared_perms),
            "manifest_custom_perm_count": sum(
                1 for p in declared_perms
                if not p.startswith("android.permission.")
                and not p.startswith("com.android.")
            ),
            "manifest_has_launcher":     int(any("LAUNCHER" in str(a.get_intent_filters("activity", act) or "")
                                                  for act in activities)),
            "manifest_exported_activity": sum(1 for act in activities
                                               if "exported" in str(a.get_intent_filters("activity", act) or "")),
        }

        # ── 8. APK dosya özellikleri ──────────────────────
        apk_size_kb = round(os.path.getsize(apk_path) / 1024, 1)
        file_feats = {
            "file_size_kb": apk_size_kb,
            "file_size_mb": round(apk_size_kb / 1024, 2),
        }

        # ── 9. Network / URL özellikler ───────────────────
        suspicious_domains = ["pastebin", "ngrok", "bit.ly", "tinyurl", "duckdns",
                               ".ru", ".cn", ".tk", ".top", "no-ip"]
        network_feats = {
            "net_has_suspicious_domain": int(
                any(d in all_code.lower() or d in " ".join(str_list).lower()
                    for d in suspicious_domains)
            ),
            "net_hardcoded_ip": sum(
                1 for s in str_list
                if len(s.split(".")) == 4 and all(p.isdigit() for p in s.split("."))
                and s not in ["0.0.0.0", "127.0.0.1", "255.255.255.255"]
            ),
            "net_uses_http":  int("http://" in " ".join(str_list)),
            "net_uses_https": int("https://" in " ".join(str_list)),
            "net_uses_tor":   int(".onion" in " ".join(str_list).lower()),
        }

        return {
            **perm_feats,
            **api_feats,
            **ref_feats,
            **dex_feats,
            **anti_feats,
            **obf_feats,
            **manifest_feats,
            **file_feats,
            **network_feats,
        }

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
    parser.add_argument("--year",    type=int, default=None,
                        help="Sadece belirli yılı işle (orn: --year 2016)")
    parser.add_argument("--apk-dir", type=str, default=None,
                        help="APK klasörü (metadata.csv yerine direkt klasörden oku)")
    parser.add_argument("--label",   type=int, default=0,
                        help="--apk-dir ile kullanılır: 0=benign, 1=malware (varsayılan: 0)")
    parser.add_argument("--out",     type=str, default=None,
                        help="Çıktı parquet yolu (varsayılan: otomatik)")
    args = parser.parse_args()

    from pathlib import Path

    # ── APK kaynağı: klasör mü, metadata mü? ──────────────
    if args.apk_dir:
        apk_dir = Path(args.apk_dir)
        apk_files = sorted(apk_dir.glob("*.apk"))
        if not apk_files:
            print(f"HATA: {apk_dir} içinde .apk bulunamadı!")
            return
        year = args.year or 0
        meta = pd.DataFrame([
            {"sha256": f.stem, "apk_path": str(f), "label": args.label, "year": year}
            for f in apk_files
        ])
        print(f"Klasör modu: {apk_dir} → {len(meta):,} APK  (label={args.label})")
    else:
        meta = pd.read_csv(METADATA_CSV)
        if args.year:
            meta = meta[meta.year == args.year].reset_index(drop=True)
            print(f"Yıl filtresi: {args.year} → {len(meta):,} APK")
        else:
            print(f"Toplam APK: {len(meta):,}")

    # ── Çıktı yolu ─────────────────────────────────────────
    if args.out:
        out_path = Path(args.out)
        out_dir  = out_path.parent
    elif args.apk_dir:
        tag      = Path(args.apk_dir).name          # klasör adı (orn: 2023)
        lbl      = "benign" if args.label == 0 else "malware"
        out_dir  = FEATURES_DIR / "static_features" / lbl / tag
        out_path = out_dir / "static_features.parquet"
    elif args.year:
        out_dir  = FEATURES_DIR / "static_features" / str(args.year)
        out_path = out_dir / "static_features.parquet"
    else:
        out_dir  = FEATURES_DIR
        out_path = STATIC_PARQUET

    print(f"Çıktı: {out_path}")

    done_sha = set()
    if args.resume and out_path.exists():
        done = pd.read_parquet(out_path, columns=["sha256"])
        done_sha = set(done["sha256"].tolist())
        meta = meta[~meta.sha256.isin(done_sha)]
        print(f"Zaten tamamlanan: {len(done_sha):,} | Kalan: {len(meta):,}")

    rows_list = meta.to_dict("records")
    results   = []
    failed    = 0

    with ProcessPoolExecutor(max_workers=args.workers) as exe:
        futures = {exe.submit(process_row, row): row for row in rows_list}
        bar = tqdm(as_completed(futures), total=len(futures), desc="Statik extraction",
                   dynamic_ncols=True)
        for fut in bar:
            row = futures[fut]
            apk_name = os.path.basename(row.get("apk_path", "?"))
            bar.set_postfix_str(apk_name, refresh=True)
            res = fut.result()
            if res:
                results.append(res)
            else:
                failed += 1
                tqdm.write(f"  [HATA] {apk_name}")

    print(f"\nBaşarılı: {len(results):,} | Başarısız: {failed:,}")

    if not results:
        print("Hiç feature çıkarılamadı.")
        return

    df_new = pd.DataFrame(results)

    if args.resume and out_path.exists():
        df_old = pd.read_parquet(out_path)
        df_new = pd.concat([df_old, df_new], ignore_index=True)

    out_dir.mkdir(parents=True, exist_ok=True)
    df_new.to_parquet(out_path, index=False)
    print(f"\nKaydedildi -> {out_path}")
    print(f"Toplam satır: {len(df_new):,} | Kolon: {len(df_new.columns):,}")
    print(f"\nÖzellik grupları:")
    for prefix in ["perm_", "api_", "ref_", "dex_", "anti_", "obf_", "manifest_", "file_", "net_"]:
        count = sum(1 for c in df_new.columns if c.startswith(prefix))
        print(f"  {prefix:<12} {count:>3} özellik")


if __name__ == "__main__":
    main()
