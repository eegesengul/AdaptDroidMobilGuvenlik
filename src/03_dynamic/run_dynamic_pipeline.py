"""
Android emülatör üzerinde Frida destekli dinamik analiz pipeline.
Adımlar: install -> frida attach -> logcat clear -> launch -> monkey -> hook monitoring -> feature -> uninstall

Kullanım:
    python run_dynamic_pipeline.py
    python run_dynamic_pipeline.py --resume
    python run_dynamic_pipeline.py --no-frida   # Frida olmadan sadece logcat
"""
import argparse
import os
import re
import subprocess
import sys
import time
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[2]))

import pandas as pd
from tqdm import tqdm

from config import (
    METADATA_CSV, DYNAMIC_PARQUET, DYNAMIC_LOGS_DIR, FEATURES_DIR
)

MONKEY_EVENTS    = 500
MONKEY_THROTTLE  = 200
ANALYSIS_WAIT    = 60
ADB              = "adb"
FRIDA_HOOKS_JS   = Path(__file__).parent / "frida_hooks.js"


# ── ADB yardımcıları ───────────────────────────────────────

def adb(*args, timeout=30) -> str:
    try:
        r = subprocess.run([ADB] + list(args), capture_output=True,
                           text=True, timeout=timeout,
                           encoding="utf-8", errors="ignore")
        return (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return ""
    except FileNotFoundError:
        print("HATA: adb bulunamadı.")
        sys.exit(1)


def get_package_name(apk_path: str) -> str | None:
    try:
        out = subprocess.check_output(
            ["aapt", "dump", "badging", apk_path],
            stderr=subprocess.DEVNULL, timeout=20
        ).decode(errors="ignore")
        m = re.search(r"package: name='([^']+)'", out)
        return m.group(1) if m else None
    except Exception:
        return None


def install_apk(apk_path: str) -> bool:
    out = adb("install", "-r", "-t", apk_path, timeout=120)
    return "Success" in out or "success" in out.lower()


def uninstall_apk(package: str):
    adb("uninstall", package, timeout=30)


def launch_app(package: str):
    adb("shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1")
    time.sleep(3)


def run_monkey(package: str):
    subprocess.Popen([
        ADB, "shell", "monkey", "-p", package,
        "--throttle", str(MONKEY_THROTTLE),
        "--ignore-crashes", "--ignore-timeouts",
        str(MONKEY_EVENTS)
    ])


def collect_logcat(log_path: str):
    out = adb("logcat", "-d", timeout=90)
    with open(log_path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(out)


def force_stop(package: str):
    adb("shell", "am", "force-stop", package)


# ── Frida yardımcıları ─────────────────────────────────────

def _get_pid(package: str, retries: int = 3, delay: float = 1.5) -> int | None:
    """Cihaz tarafında grep yaparak PID döner (büyük ps çıktısı truncate olmaz)."""
    for _ in range(retries):
        # Grep device'da çalışır → sadece ilgili satır gelir
        out = adb("shell", f"ps -A | grep {package}", timeout=15)
        for line in out.splitlines():
            if package in line:
                parts = line.split()
                # ps -A: USER PID PPID VSZ RSS WCHAN ADDR S NAME
                if len(parts) >= 2:
                    try:
                        return int(parts[1])
                    except ValueError:
                        continue
        time.sleep(delay)
    return None

def frida_attach(package: str, frida_log_path: str, pid: int | None = None):
    """Frida'yı çalışan APK process'ine attach et, olayları frida_log dosyasına yazar.
    Bağlantı: adb forward tcp:27042 tcp:27042 ile TCP üzerinden.
    pid verilirse PID ile, yoksa paket adıyla attach dener.
    """
    try:
        import frida
        import threading, time as _time

        script_src = FRIDA_HOOKS_JS.read_text(encoding="utf-8")
        events = []

        # TCP üzerinden bağlan — emülatör için get_usb_device değil
        dm = frida.get_device_manager()
        try:
            device = dm.add_remote_device("localhost:27042")
        except Exception:
            devices = dm.enumerate_devices()
            device = next((d for d in devices if "localhost" in str(d.id)), None)
            if device is None:
                raise RuntimeError("localhost:27042 cihazı bulunamadı")

        if pid is None:
            raise RuntimeError(f"PID alınamadı (app başlamadı veya çöktü): {package}")

        session = device.attach(pid)
        script  = session.create_script(script_src)

        def on_message(msg, _data):
            if msg.get("type") == "send":
                events.append(msg["payload"])

        script.on("message", on_message)
        script.load()

        def _writer():
            _time.sleep(ANALYSIS_WAIT + 5)
            with open(frida_log_path, "w") as f:
                json.dump(events, f)

        threading.Thread(target=_writer, daemon=True).start()
        return session

    except Exception as e:
        print(f"  [Frida] attach başarısız: {e} — sadece logcat kullanılacak")
        return None


# ── Feature extraction ─────────────────────────────────────

def parse_logcat(log_path: str) -> dict:
    try:
        with open(log_path, encoding="utf-8", errors="ignore") as f:
            log = f.read()
    except FileNotFoundError:
        log = ""

    return {
        # Ağ
        "network_event_count":    len(re.findall(r"connect|socket|http|https", log, re.I)),
        "dns_query_count":        len(re.findall(r"getaddrinfo|nslookup|resolv", log, re.I)),
        # Kripto
        "crypto_count":           len(re.findall(r"javax\.crypto|AES|RSA|Cipher", log)),
        # Kod yükleme
        "dex_loader_count":       len(re.findall(r"DexClassLoader|loadDex|BaseDex", log)),
        "runtime_exec_count":     len(re.findall(r"Runtime\.exec|ProcessBuilder|/bin/sh", log)),
        # Hassas erişimler
        "sms_send_count":         len(re.findall(r"sendTextMessage|SmsManager", log)),
        "sms_read_count":         len(re.findall(r"content://sms|content://mms", log)),
        "contact_access_count":   len(re.findall(r"ContactsContract|getContacts|CONTACTS", log)),
        "call_log_access_count":  len(re.findall(r"call_log|CallLog", log)),
        # Dosya
        "file_write_count":       len(re.findall(r"FileOutputStream|openFileOutput|FileWriter", log)),
        # Reflection
        "reflection_count":       len(re.findall(r"getDeclaredMethod|\.invoke\(|forName", log)),
        # Native
        "native_lib_count":       len(re.findall(r"System\.loadLibrary|dlopen", log)),
        # Kamera / Mikrofon
        "camera_access_count":    len(re.findall(r"android\.hardware\.Camera|CameraManager|openCamera", log)),
        "mic_access_count":       len(re.findall(r"AudioRecord|MediaRecorder|startRecording", log)),
        # Konum
        "location_access_count":  len(re.findall(r"getLastKnownLocation|requestLocationUpdates|LocationManager", log)),
        # Pano
        "clipboard_access_count": len(re.findall(r"ClipboardManager|getPrimaryClip", log)),
        # Cihaz yönetimi
        "device_admin_count":     len(re.findall(r"DevicePolicyManager|isAdminActive|BIND_DEVICE_ADMIN", log)),
        # WakeLock / persistence
        "wakelock_count":         len(re.findall(r"acquireWakeLock|PARTIAL_WAKE_LOCK|WakeLock", log)),
        # Hata / çökme
        "exception_count":        len(re.findall(r"Exception|FATAL|ANR", log)),
    }


def parse_frida_log(frida_log_path: str) -> dict:
    """Frida olaylarından feature çıkar."""
    try:
        with open(frida_log_path) as f:
            events = json.load(f)
    except Exception:
        events = []

    counts = {
        # Reflection
        "frida_reflection_forName":    0,
        "frida_reflection_invoke":     0,
        # DEX yükleme
        "frida_dex_load":              0,
        "frida_dex_load_inmemory":     0,
        # Kripto
        "frida_crypto_cipher":         0,
        "frida_crypto_digest":         0,
        "frida_base64_encode":         0,
        # Ağ
        "frida_network_socket":        0,
        "frida_network_http":          0,
        # Komut çalıştırma
        "frida_runtime_exec":          0,
        # Dosya
        "frida_file_write":            0,
        "frida_zip_open":              0,
        # SMS / telefon
        "frida_sms_send":              0,
        "frida_sms_read":              0,
        "frida_telephony_query":       0,
        # Rehber / arama
        "frida_contact_query":         0,
        "frida_call_log_read":         0,
        # Pano
        "frida_clipboard_read":        0,
        "frida_clipboard_write":       0,
        # Kamera
        "frida_camera_open":           0,
        # Konum
        "frida_location_request":      0,
        # Ayarlar / persistence
        "frida_shared_prefs_write":    0,
        "frida_alarm_set":             0,
        # Broadcast
        "frida_broadcast_send":        0,
        # Native
        "frida_native_lib_load":       0,
        # Veri ayrıştırma (C2 belirtisi)
        "frida_json_parse":            0,
        # Cihaz yönetimi
        "frida_device_admin_check":    0,
        # Paket listesi
        "frida_package_enum":          0,
    }

    # Benzersiz host sayacı (network çeşitlilik özelliği)
    unique_hosts = set()

    for e in events:
        t = e.get("type", "")
        key = f"frida_{t}"
        if key in counts:
            counts[key] += 1
        # Benzersiz host takibi
        if t == "network_socket" and e.get("host"):
            unique_hosts.add(e["host"])
        elif t == "network_http" and e.get("url"):
            try:
                from urllib.parse import urlparse
                host = urlparse(e["url"]).netloc
                if host:
                    unique_hosts.add(host)
            except Exception:
                pass

    counts["frida_unique_hosts"] = len(unique_hosts)
    return counts


# ── Ana pipeline ───────────────────────────────────────────

def analyze_apk(sha256: str, apk_path: str, use_frida: bool = True) -> dict | None:
    log_path        = str(DYNAMIC_LOGS_DIR / f"{sha256}.log")
    frida_log_path  = str(DYNAMIC_LOGS_DIR / f"{sha256}_frida.json")

    package = get_package_name(apk_path)
    if not package:
        return None

    frida_session = None
    try:
        if not install_apk(apk_path):
            return None

        adb("logcat", "-c")
        time.sleep(1)

        if use_frida:
            # Monkey'i ÖNCE başlat (--ignore-crashes ile app'i ayakta tutar)
            # Sonra PID görününce Frida attach ol
            run_monkey(package)
            pid = _get_pid(package)   # monkey çalışırken poll eder (retry var)
            frida_session = frida_attach(package, frida_log_path, pid=pid)
            time.sleep(ANALYSIS_WAIT)
        else:
            launch_app(package)
            run_monkey(package)
            time.sleep(ANALYSIS_WAIT)
        collect_logcat(log_path)
        force_stop(package)

        if frida_session:
            try:
                frida_session.detach()
            except Exception:
                pass
        time.sleep(2)

    finally:
        uninstall_apk(package)

    feats = parse_logcat(log_path)
    feats.update(parse_frida_log(frida_log_path))
    feats["sha256"]     = sha256
    feats["frida_used"] = int(use_frida and os.path.exists(frida_log_path))
    return feats


def _save(results: list, done_sha: set):
    if not results:
        return
    df_new = pd.DataFrame(results)
    if DYNAMIC_PARQUET.exists() and done_sha:
        df_old = pd.read_parquet(DYNAMIC_PARQUET)
        df_new = pd.concat([df_old, df_new], ignore_index=True)
        df_new = df_new.drop_duplicates(subset="sha256")
    df_new.to_parquet(DYNAMIC_PARQUET, index=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume",   action="store_true")
    parser.add_argument("--no-frida", action="store_true", help="Frida olmadan çalıştır")
    parser.add_argument("--limit",    type=int, default=None, help="Kaç APK analiz edilsin (test için)")
    args = parser.parse_args()

    DYNAMIC_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)

    meta = pd.read_csv(METADATA_CSV)
    dynamic_apks = meta[meta.in_dynamic == 1].reset_index(drop=True)
    if args.limit:
        dynamic_apks = dynamic_apks.head(args.limit)
    print(f"Dinamik analiz APK: {len(dynamic_apks):,} | Frida: {'KAPALI' if args.no_frida else 'AÇIK'}")

    done_sha = set()
    if args.resume and DYNAMIC_PARQUET.exists():
        done = pd.read_parquet(DYNAMIC_PARQUET, columns=["sha256"])
        done_sha = set(done["sha256"].tolist())
        dynamic_apks = dynamic_apks[~dynamic_apks.sha256.isin(done_sha)]
        print(f"Kalan: {len(dynamic_apks):,}")

    devices = adb("devices")
    if "emulator" not in devices and len(devices.strip().split("\n")) < 2:
        print("UYARI: Emülatör bulunamadı. Android Studio'dan başlat.")
        return

    results, failed = [], 0

    for _, row in tqdm(dynamic_apks.iterrows(), total=len(dynamic_apks), desc="Dinamik analiz"):
        res = analyze_apk(row["sha256"], row["apk_path"], use_frida=not args.no_frida)
        if res:
            results.append(res)
        else:
            failed += 1

        if len(results) % 50 == 0 and results:
            _save(results, done_sha)

    _save(results, done_sha)
    print(f"\nBaşarılı: {len(results):,} | Başarısız: {failed:,}")
    print(f"Kaydedildi -> {DYNAMIC_PARQUET}")


if __name__ == "__main__":
    main()
