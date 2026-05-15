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
import threading
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
KEEPER_INTERVAL  = 8
ADB              = "adb"
FRIDA_HOOKS_JS   = Path(__file__).parent / "frida_hooks.js"
BYPASS_HOOKS_JS  = Path(__file__).parent / "bypass_hooks.js"


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


def _find_aapt() -> str:
    for name in ("aapt", "aapt.exe"):
        try:
            subprocess.run([name, "version"], capture_output=True, timeout=5)
            return name
        except Exception:
            pass
    import glob as _glob
    for sdk_root in (
        os.environ.get("ANDROID_HOME", ""),
        os.environ.get("ANDROID_SDK_ROOT", ""),
        os.path.expanduser("~/AppData/Local/Android/Sdk"),
        os.path.expanduser("~/Android/Sdk"),
    ):
        if not sdk_root:
            continue
        for hit in sorted(_glob.glob(os.path.join(sdk_root, "build-tools", "*", "aapt.exe")), reverse=True):
            return hit
        for hit in sorted(_glob.glob(os.path.join(sdk_root, "build-tools", "*", "aapt")), reverse=True):
            return hit
    return "aapt"

AAPT = _find_aapt()


def get_package_name(apk_path: str) -> str | None:
    try:
        out = subprocess.check_output(
            [AAPT, "dump", "badging", apk_path],
            stderr=subprocess.DEVNULL, timeout=20
        ).decode(errors="ignore")
        m = re.search(r"package: name='([^']+)'", out)
        return m.group(1) if m else None
    except Exception:
        return None


def install_apk(apk_path: str) -> bool:
    """APK kur. Android 14+ eski targetSdk (<23) bloke edebilir;
    --bypass-low-target-sdk-block ile aşılır."""
    # Önce normal kur
    out = adb("install", "-r", "-t", apk_path, timeout=120)
    if "Success" in out or "success" in out.lower():
        return True
    # Eski targetSdk bloğu varsa bypass ile tekrar dene
    if "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in out or "low target sdk" in out.lower():
        out2 = adb("install", "-r", "-t", "--bypass-low-target-sdk-block", apk_path, timeout=120)
        return "Success" in out2 or "success" in out2.lower()
    return False


def uninstall_apk(package: str):
    adb("uninstall", package, timeout=30)


def launch_app(package: str):
    adb("shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1")
    time.sleep(3)


def run_monkey(package: str):
    subprocess.Popen([
        ADB, "shell", "monkey", "-p", package,
        "--throttle",       str(MONKEY_THROTTLE),
        "--ignore-crashes", "--ignore-timeouts",
        "--pct-syskeys",    "0",
        "--pct-appswitch",  "0",
        "--pct-majornav",   "0",
        "--pct-nav",        "0",
        "--pct-trackball",  "0",
        "--pct-touch",      "60",
        "--pct-motion",     "25",
        "--pct-pinchzoom",  "10",
        "--pct-anyevent",   "5",
        str(MONKEY_EVENTS)
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def foreground_keeper(package: str, stop_event):
    """Analiz boyunca bildirim panelini kapatır ve uygulamayı ön planda tutar."""
    while not stop_event.wait(KEEPER_INTERVAL):
        adb("shell", "cmd", "statusbar", "collapse", timeout=3)
        ps_out = adb("shell", f"ps -A | grep {package}", timeout=5)
        if package in ps_out:
            adb("shell", "monkey", "-p", package,
                "-c", "android.intent.category.LAUNCHER", "1", timeout=5)


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

def _get_frida_device():
    """USB üzerinden Frida device döner (emülatör için)."""
    import frida
    try:
        return frida.get_usb_device(timeout=10)
    except Exception:
        dm = frida.get_device_manager()
        devices = dm.enumerate_devices()
        device = next((d for d in devices if d.type in ("usb", "local")), None)
        if device is None:
            raise RuntimeError("Frida USB/local cihazı bulunamadı")
        return device


def _restart_frida_server():
    """DeadSystemException sonrası frida-server'ı yeniden başlat."""
    print("  [frida-restart] sistem kurtarılıyor, frida-server yeniden başlatılıyor...")
    adb("shell", "pkill", "-f", "frida-server", timeout=5)
    time.sleep(5)
    subprocess.Popen(
        [ADB, "shell", "/data/local/tmp/frida-server &"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(4)
    adb("forward", "tcp:27042", "tcp:27042", timeout=5)
    print("  [frida-restart] tamamlandı")


def _ensure_selinux_permissive():
    """SELinux'u permissive moduna al — API 33'te ptrace için gerekli."""
    try:
        out = adb("shell", "getenforce", timeout=5)
        if "Enforcing" in out:
            adb("shell", "setenforce", "0", timeout=5)
    except Exception:
        pass


def _load_hook_script() -> str:
    """📦 başlık satırlarını atar, frida-java-bridge dahil tüm scripti döner."""
    raw = FRIDA_HOOKS_JS.read_text(encoding="utf-8")
    lines = raw.splitlines(keepends=True)
    # İlk 3 satır: 📦 / "448085 /hooks.js" / ✄  — Frida 17.x bunları "Malformed package" olarak reddeder
    if lines and lines[0].strip() == "\U0001f4e6":
        return "".join(lines[3:])
    return raw


def frida_spawn(package: str, use_bypass: bool = False):
    """App'i Frida ile spawn veya attach eder, hook'ları yükler.
    Döner: (session, events, pid)
    """
    try:
        import frida
        script_src = _load_hook_script()
        if use_bypass and BYPASS_HOOKS_JS.exists():
            bypass_src = BYPASS_HOOKS_JS.read_text(encoding="utf-8")
            script_src = bypass_src + "\n" + script_src
        events = []

        device = _get_frida_device()

        # Spawn dene
        try:
            pid = device.spawn([package])
            session = device.attach(pid)
            script  = session.create_script(script_src)
            script.on("message", lambda msg, _: events.append(msg["payload"]) if msg.get("type") == "send" else None)
            script.load()
            device.resume(pid)
            return session, events, pid
        except Exception as spawn_err:
            # Spawn başarısız (InvocationTargetException, API 33 uyumsuzluğu vb.)
            print(f"  [spawn-err] {package}: {spawn_err}")
            if "DeadSystem" in str(spawn_err):
                _restart_frida_server()
            try:
                adb("shell", "am", "force-stop", package)
            except Exception:
                pass
            time.sleep(2)

        # Attach modu: SELinux'u permissive yap, uygulamayı elle başlat
        _ensure_selinux_permissive()
        launch_app(package)
        time.sleep(5)

        attach_pid = _get_pid(package, retries=5, delay=2.0)
        if attach_pid is None:
            raise RuntimeError(f"Uygulama başlatılamadı veya PID alınamadı: {package}")

        # Attach için retry (process başlamayı bitirmemiş olabilir)
        last_err = None
        for _ in range(3):
            try:
                session = device.attach(attach_pid)
                script  = session.create_script(script_src)
                script.on("message", lambda msg, _: events.append(msg["payload"]) if msg.get("type") == "send" else None)
                script.load()
                return session, events, attach_pid
            except Exception as attach_err:
                last_err = attach_err
                time.sleep(2)

        raise RuntimeError(f"Attach başarısız (3 deneme): {last_err}")

    except Exception as e:
        print(f"  [Frida-spawn] başarısız: {e} — logcat moduna geçiliyor")
        return None, [], None


def frida_attach(package: str, pid: int | None = None, use_bypass: bool = False):
    """Çalışan process'e attach et (spawn başarısız olursa fallback).
    Döner: (session, events)
    """
    try:
        import frida
        script_src = _load_hook_script()
        if use_bypass and BYPASS_HOOKS_JS.exists():
            bypass_src = BYPASS_HOOKS_JS.read_text(encoding="utf-8")
            script_src = bypass_src + "\n" + script_src
        events = []

        device = _get_frida_device()

        if pid is None:
            raise RuntimeError(f"PID alınamadı: {package}")

        session = device.attach(pid)
        script  = session.create_script(script_src)

        def on_message(msg, _data):
            if msg.get("type") == "send":
                events.append(msg["payload"])

        script.on("message", on_message)
        script.load()
        return session, events

    except Exception as e:
        print(f"  [Frida-attach] başarısız: {e} — sadece logcat kullanılacak")
        return None, []


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

def analyze_apk(sha256: str, apk_path: str, use_frida: bool = True,
                frida_only: bool = False, analysis_wait: int = 60,
                use_bypass: bool = False) -> dict | None:
    """APK analiz eder.
    frida_only=True → Frida hook kurulamazsa None döner (APK atlanır).
    """
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

        frida_events = []
        if use_frida:
            frida_session, frida_events, _ = frida_spawn(package, use_bypass=use_bypass)

            if frida_session is None:
                if frida_only:
                    return None  # finally → uninstall
                launch_app(package)
                run_monkey(package)
                pid = _get_pid(package)
                frida_session, frida_events = frida_attach(package, pid=pid, use_bypass=use_bypass)
                if frida_only and frida_session is None:
                    return None  # finally → uninstall
            else:
                run_monkey(package)

            stop_keeper = threading.Event()
            keeper = threading.Thread(
                target=foreground_keeper, args=(package, stop_keeper), daemon=True
            )
            keeper.start()
            time.sleep(analysis_wait)
            stop_keeper.set()
            keeper.join(timeout=KEEPER_INTERVAL + 2)
        else:
            launch_app(package)
            run_monkey(package)
            stop_keeper = threading.Event()
            keeper = threading.Thread(
                target=foreground_keeper, args=(package, stop_keeper), daemon=True
            )
            keeper.start()
            time.sleep(analysis_wait)
            stop_keeper.set()
            keeper.join(timeout=KEEPER_INTERVAL + 2)

        collect_logcat(log_path)
        force_stop(package)

        # Frida olaylarını yaz (detach'ten ÖNCE — tüm pending send()'ler flush olsun)
        if frida_session:
            try:
                time.sleep(1)  # Son mesajların gelmesi için kısa bekleme
                with open(frida_log_path, "w") as f:
                    json.dump(frida_events, f)
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

    # frida_only modunda: Frida tutunamamışsa bu APK'yı geç
    if frida_only and feats["frida_used"] == 0:
        return None

    return feats


def _save(results: list, done_sha: set, out_path: Path = DYNAMIC_PARQUET,
          overwrite_sha: set | None = None):
    """Sonuçları parquet'e yaz.
    overwrite_sha: bu SHA256'lar için eski kayıt silinip yeni veri yazılır (yeniden analiz).
    """
    if not results:
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df_new = pd.DataFrame(results)
    if out_path.exists():
        df_old = pd.read_parquet(out_path)
        if overwrite_sha:
            df_old = df_old[~df_old["sha256"].str.upper().isin(overwrite_sha)]
        df_new = pd.concat([df_old, df_new], ignore_index=True)
        df_new = df_new.drop_duplicates(subset="sha256")
    df_new.to_parquet(out_path, index=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume",      action="store_true")
    parser.add_argument("--no-frida",    action="store_true",  help="Frida olmadan çalıştır")
    parser.add_argument("--frida-only",  action="store_true",  help="Frida tutunamamışsa APK'yı geç")
    parser.add_argument("--target",      type=int, default=None,
                        help="Kaç başarılı analiz istendiği; hedefe ulaşınca dur")
    parser.add_argument("--limit",       type=int, default=None, help="Kaç APK denilsin (test için)")
    parser.add_argument("--year",        type=int, default=None, help="Sadece belirli yılı analiz et")
    parser.add_argument("--benign",      action="store_true",   help="Benign APKları analiz et (label=0)")
    parser.add_argument("--apk-dir",     type=str, default=None,
                        help="Metadata yerine doğrudan APK klasörü (orn: data/apks/benign/2020)")
    parser.add_argument("--output",      type=str, default=None,
                        help="Çıktı parquet yolu (varsayılan: features_old/<yil>/dynamic_features.parquet)")
    parser.add_argument("--sha256-list", type=str, default=None,
                        help="Sadece bu dosyadaki SHA256'ları analiz et (yeniden analiz için); mevcut kayıtların üzerine yazar")
    parser.add_argument("--analysis-wait", type=int, default=60,
                        help="Uygulama çalıştırma süresi (saniye, varsayılan: 60)")
    parser.add_argument("--known-only", action="store_true",
                        help="Sadece mevcut parquet'te frida_used=1 olan APK'ları analiz et")
    parser.add_argument("--bypass", action="store_true",
                        help="SSL pinning / root detection / emulator detection bypass uygula")
    args = parser.parse_args()

    DYNAMIC_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)

    # Çıktı yolunu belirle
    if args.output:
        out_parquet = Path(args.output)
    elif args.apk_dir:
        year_part = Path(args.apk_dir).name  # orn: "2023"
        out_parquet = FEATURES_DIR / year_part / "dynamic_features.parquet"
    else:
        out_parquet = DYNAMIC_PARQUET

    # APK klasörü doğrudan verilmişse metadata'ya gerek yok
    if args.apk_dir:
        apk_dir = Path(args.apk_dir)
        apk_files = list(apk_dir.glob("*.apk"))
        if not apk_files:
            print(f"HATA: {apk_dir} içinde APK bulunamadı.")
            return
        label = 0 if args.benign else 1
        # SHA256 dosya adından al
        dynamic_apks = pd.DataFrame([
            {"sha256": f.stem.upper(), "apk_path": str(f), "label": label, "year": args.year}
            for f in apk_files
        ])
        print(f"APK klasörü: {apk_dir} → {len(dynamic_apks):,} APK (label={label})")
    else:
        meta = pd.read_csv(METADATA_CSV)
        label_filter = 0 if args.benign else 1

        if args.year:
            # Yıl belirtilmişse o yılın APK'larını havuz olarak kullan
            dynamic_apks = meta[(meta.year == args.year) & (meta.label == label_filter)].reset_index(drop=True)
        else:
            dynamic_apks = meta[meta.in_dynamic == 1].reset_index(drop=True)
            if args.benign:
                dynamic_apks = dynamic_apks[dynamic_apks.label == 0].reset_index(drop=True)

    # Sadece daha önce Frida ile başarıyla analiz edilenleri filtrele
    if args.known_only:
        if out_parquet.exists():
            df_existing = pd.read_parquet(out_parquet, columns=["sha256", "frida_used"])
            known_sha = set(df_existing[df_existing["frida_used"] == 1]["sha256"].str.upper())
            dynamic_apks = dynamic_apks[dynamic_apks["sha256"].str.upper().isin(known_sha)].reset_index(drop=True)
            print(f"--known-only: {len(known_sha)} frida_used=1 kayıt → havuzdan {len(dynamic_apks)} APK eşleşti")
        else:
            print("UYARI: --known-only verildi ama parquet bulunamadı, tüm havuz kullanılıyor.")

    # SHA256 listesi verilmişse havuzu o listeyle kısıtla
    rerun_sha: set = set()
    if args.sha256_list:
        rerun_sha = {h.strip().upper() for h in Path(args.sha256_list).read_text().splitlines() if h.strip()}
        dynamic_apks = dynamic_apks[dynamic_apks["sha256"].str.upper().isin(rerun_sha)].reset_index(drop=True)
        print(f"--sha256-list: {len(rerun_sha)} SHA256 → havuzdan {len(dynamic_apks)} APK eşleşti")

    if args.limit:
        dynamic_apks = dynamic_apks.head(args.limit)

    frida_tag = "KAPALI" if args.no_frida else ("SADECE FRİDA" if args.frida_only else "AÇIK")
    target_tag = f" | Hedef: {args.target}" if args.target else ""
    print(f"Dinamik analiz APK havuzu: {len(dynamic_apks):,} | Frida: {frida_tag} | Bekleme: {args.analysis_wait}s{target_tag}")

    done_sha = set()
    if args.resume and out_parquet.exists():
        done = pd.read_parquet(out_parquet, columns=["sha256"])
        done_sha = set(s.upper() for s in done["sha256"].tolist())
        dynamic_apks = dynamic_apks[~dynamic_apks.sha256.str.upper().isin(done_sha)]
        print(f"Kalan havuz: {len(dynamic_apks):,}")

    devices = adb("devices")
    if "emulator" not in devices and len(devices.strip().split("\n")) < 2:
        print("UYARI: Emülatör bulunamadı. Android Studio'dan başlat.")
        return

    if not args.no_frida:
        _ensure_selinux_permissive()

    results, failed, skipped_frida = [], 0, 0
    session_skip: set = set()  # Bu session'da zaten başarısız olan sha256'lar

    with tqdm(dynamic_apks.iterrows(), total=len(dynamic_apks), desc="Dinamik analiz") as bar:
      for _, row in bar:
        # Hedefe ulaşıldıysa dur
        if args.target and len(results) >= args.target:
            break

        sha = str(row["sha256"]).upper()
        if sha in session_skip:
            skipped_frida += 1
            bar.set_postfix_str(f"Frida:{len(results)} Atlanan:{skipped_frida}")
            continue

        res = analyze_apk(
            row["sha256"], row["apk_path"],
            use_frida=not args.no_frida,
            frida_only=args.frida_only,
            analysis_wait=args.analysis_wait,
            use_bypass=args.bypass,
        )
        if res:
            results.append(res)
        elif args.frida_only:
            session_skip.add(sha)
            skipped_frida += 1
        else:
            failed += 1

        bar.set_postfix_str(f"Frida:{len(results)} Atlanan:{skipped_frida}")

        if len(results) % 20 == 0 and results:
            _save(results, done_sha, out_parquet, overwrite_sha=rerun_sha or None)

    _save(results, done_sha, out_parquet, overwrite_sha=rerun_sha or None)

    frida_line = f" | Frida tutunmadı (atlandı): {skipped_frida:,}" if args.frida_only else ""
    print(f"\nBaşarılı: {len(results):,} | Başarısız: {failed:,}{frida_line}")
    if args.target:
        status = "✓ HEDEFE ULAŞILDI" if len(results) >= args.target else "✗ Havuz tükendi"
        print(f"Hedef {args.target} → {status}")
    print(f"Kaydedildi -> {out_parquet}")


if __name__ == "__main__":
    main()
