"""
3 emülatör paralel dinamik analiz pipeline.
Mevcut parquet üzerine ekler (resume otomatik).

Kullanım:
    # Emülatörleri otomatik algıla
    python run_dynamic_parallel.py --apk-dir data/apks/benign/2021 --benign --year 2021

    # Emülatörleri elle belirt
    python run_dynamic_parallel.py --apk-dir data/apks/malware/2017 --year 2017 ^
        --devices emulator-5554 emulator-5556 emulator-5558

    # Hedef sayı belirt (toplam, tüm emülatörlere bölünür)
    python run_dynamic_parallel.py --apk-dir data/apks/benign/2019 --benign --year 2019 --target 200
"""
import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parents[2]))

import pandas as pd
from tqdm import tqdm

from config import DYNAMIC_LOGS_DIR, FEATURES_DIR

MONKEY_EVENTS   = 1000
MONKEY_THROTTLE = 150
KEEPER_INTERVAL = 4   # saniyede bir foreground kontrolü
ANALYSIS_WAIT   = 60
FRIDA_HOOKS_JS  = Path(__file__).parent / "frida_hooks.js"
BYPASS_HOOKS_JS = Path(__file__).parent / "bypass_hooks.js"

# Analiz sırasında kapatılacak / müdahale eden uygulamalar
INTERFERING_PKGS = [
    "com.android.chrome",
    "com.google.android.apps.maps",
    "com.android.phone",
    "com.google.android.dialer",
    "com.android.contacts",
    "com.google.android.apps.messaging",
]

# Kurulum sonrası otomatik verilecek tehlikeli izinler
DANGEROUS_PERMISSIONS = [
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
]

# Diyalog kapatma için tıklanacak düğme metinleri (öncelik sırasıyla)
_DISMISS_TEXTS = (
    "Allow all the time",
    "Allow only while using the app",
    "While using the app",
    "Allow",
    "ALLOW",
    "Continue",
    "CONTINUE",
    "OK",
    "Done",
    "Accept",
    "Grant",
    "Wait",         # ANR diyalogu — uygulamayı yaşat
    "WAIT",
    "GOT IT",
    "Got it",
)


# ── ADB (device-aware) ─────────────────────────────────────

def adb(serial, *args, timeout=30):
    try:
        cmd = ["adb", "-s", serial] + list(args)
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, encoding="utf-8", errors="ignore")
        return (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return ""
    except FileNotFoundError:
        print("HATA: adb bulunamadı.")
        sys.exit(1)


def detect_emulators():
    """Bağlı tüm emülatör/cihaz seriallerini döner."""
    try:
        out = subprocess.check_output(["adb", "devices"], text=True, timeout=10)
    except Exception:
        return []
    serials = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if line and "\t" in line:
            serial, state = line.split("\t", 1)
            if state.strip() == "device":
                serials.append(serial.strip())
    return serials


def _find_aapt():
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


def get_package_name(apk_path):
    try:
        out = subprocess.check_output(
            [AAPT, "dump", "badging", apk_path],
            stderr=subprocess.DEVNULL, timeout=20
        ).decode(errors="ignore")
        m = re.search(r"package: name='([^']+)'", out)
        return m.group(1) if m else None
    except Exception:
        return None


def grant_all_permissions(serial, package):
    """Kurulu pakete tüm tehlikeli izinleri önceden ver (diyalog engellemek için)."""
    for perm in DANGEROUS_PERMISSIONS:
        adb(serial, "shell", "pm", "grant", package, perm, timeout=5)


def _tap_bounds(serial, bounds_str):
    m = re.search(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds_str)
    if m:
        cx = (int(m.group(1)) + int(m.group(3))) // 2
        cy = (int(m.group(2)) + int(m.group(4))) // 2
        adb(serial, "shell", "input", "tap", str(cx), str(cy), timeout=5)
        return True
    return False


def _dismiss_dialogs(serial):
    """Ekrandaki tüm engelleyici diyalogları kapat."""
    try:
        dump = adb(serial, "shell",
                   "uiautomator dump /sdcard/ui.xml && cat /sdcard/ui.xml",
                   timeout=15)
        if not dump or "<hierarchy" not in dump:
            return

        # 1. Intent Chooser (Chrome/Maps/vb. açılmasını önle) → BACK ile kapat
        if ("ChooserActivity" in dump or "ResolverActivity" in dump
                or "android:id/resolver_list" in dump
                or "com.android.internal.app" in dump):
            adb(serial, "shell", "input", "keyevent", "4", timeout=3)
            return

        # 2. Bilinen düğme metinlerine göre tıkla (izin, ANR, sistem diyalogları)
        for text in _DISMISS_TEXTS:
            idx = dump.find(f'text="{text}"')
            if idx == -1:
                continue
            seg = dump[max(0, idx - 500): idx + 500]
            bm = re.search(r'bounds="(\[\d+,\d+\]\[\d+,\d+\])"', seg)
            if bm and _tap_bounds(serial, bm.group(1)):
                return

        # 3. permissioncontroller / packageinstaller → en sağdaki clickable düğme
        if "permissioncontroller" in dump or "packageinstaller" in dump:
            last_b = None
            for bm in re.finditer(r'clickable="true"[^>]*bounds="(\[\d+,\d+\]\[\d+,\d+\])"', dump):
                last_b = bm.group(1)
            if last_b:
                _tap_bounds(serial, last_b)
    except Exception:
        pass


def _wake_screen(serial):
    """Ekran karardıysa uyandır, keyguard'ı kaldır."""
    adb(serial, "shell", "input keyevent KEYCODE_WAKEUP", timeout=3)
    adb(serial, "shell", "wm dismiss-keyguard", timeout=3)


def setup_emulator_for_analysis(serial):
    """
    Emülatörü analiz moduna al.
    Her APK öncesi çağrılır — snapshot restore sonrası tüm ayarlar sıfırlanır.
    """
    # Ekran sürekli açık kalsın
    adb(serial, "shell", "settings put global stay_on_while_plugged_in 3", timeout=5)
    adb(serial, "shell", "settings put system screen_off_timeout 2147483647", timeout=5)
    # Keyguard / kilit ekranı kapat
    adb(serial, "shell", "settings put secure lockscreen.disabled 1", timeout=5)
    adb(serial, "shell", "wm dismiss-keyguard", timeout=5)
    # Animasyonları devre dışı bırak
    adb(serial, "shell", "settings put global window_animation_scale 0", timeout=5)
    adb(serial, "shell", "settings put global transition_animation_scale 0", timeout=5)
    adb(serial, "shell", "settings put global animator_duration_scale 0", timeout=5)
    # Gesture navigation → 3-tuş navigasyona geç
    adb(serial, "shell", "settings put secure navigation_mode 0", timeout=5)
    # Ekranı portrait'e kilitle (Monkey rotation event göndermesin)
    adb(serial, "shell", "settings put system accelerometer_rotation 0", timeout=5)
    adb(serial, "shell", "settings put system user_rotation 0", timeout=5)
    adb(serial, "shell", "wm user-rotation lock 0", timeout=5)


# ── Emülatör başına işlemler ───────────────────────────────

def install_apk(serial, apk_path):
    # -g: manifest'teki tüm runtime izinlerini kurulumda ver (DroidBot / MobSF yaklaşımı)
    out = adb(serial, "install", "-r", "-t", "-g", apk_path, timeout=120)
    if "Success" in out or "success" in out.lower():
        return True
    if "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in out or "low target sdk" in out.lower():
        out2 = adb(serial, "install", "-r", "-t", "-g", "--bypass-low-target-sdk-block", apk_path, timeout=120)
        return "Success" in out2 or "success" in out2.lower()
    return False


def uninstall_apk(serial, package):
    adb(serial, "uninstall", package, timeout=30)


def launch_app(serial, package):
    adb(serial, "shell", "monkey", "-p", package,
        "-c", "android.intent.category.LAUNCHER", "1")
    time.sleep(3)


def run_monkey(serial, package):
    subprocess.Popen(
        ["adb", "-s", serial, "shell", "monkey", "-p", package,
         "--throttle",        str(MONKEY_THROTTLE),
         "--ignore-crashes",  "--ignore-timeouts",
         # Uygulamayı arka plana düşüren event kategorilerini sıfırla
         "--pct-syskeys",    "0",   # HOME / BACK / POWER / VOLUME tuşları yok
         "--pct-appswitch",  "0",   # başka uygulama açma yok
         "--pct-majornav",   "0",   # MENU / CALL / geri nav yok
         "--pct-nav",        "0",   # DPAD yön tuşları yok
         "--pct-trackball",  "0",   # trackball yok
         # Kalan bütçeyi dokunuş / hareket olarak kullan
         "--pct-touch",      "70",  # tek parmak dokunuş
         "--pct-motion",     "20",  # swipe / drag
         "--pct-pinchzoom",  "10",  # pinch / zoom
         "--pct-anyevent",   "0",   # rotation vb. kapalı
         str(MONKEY_EVENTS)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def foreground_keeper(serial, package, stop_event):
    """
    Analiz süresi boyunca her KEEPER_INTERVAL saniyede:
      1. Ekranı uyandır / keyguard kaldır
      2. Bildirim panelini kapat
      3. Intent Chooser / izin / ANR diyaloglarını kapat
      4. Uygulama çöktüyse yeniden başlat
      5. Başka uygulama ön plandaysa am start ile geri getir
    """
    while not stop_event.wait(KEEPER_INTERVAL):
        _wake_screen(serial)
        adb(serial, "shell", "cmd", "statusbar", "collapse", timeout=3)
        _dismiss_dialogs(serial)

        ps_out = adb(serial, "shell", f"ps -A | grep {package}", timeout=5)
        if package not in ps_out:
            # Uygulama çöktü — yeniden başlat
            adb(serial, "shell",
                f"am start -a android.intent.action.MAIN"
                f" -c android.intent.category.LAUNCHER -p {package}",
                timeout=5)
            continue

        fg = adb(serial, "shell",
                 "dumpsys activity activities | grep -m1 mResumedActivity",
                 timeout=6)
        if fg and package not in fg:
            # Başka uygulama ön planda — back-stack'e dokunmadan ön plana getir
            adb(serial, "shell",
                f"am start --activity-brought-to-front"
                f" -a android.intent.action.MAIN"
                f" -c android.intent.category.LAUNCHER -p {package}",
                timeout=5)


def collect_logcat(serial, log_path):
    out = adb(serial, "logcat", "-d", timeout=90)
    with open(log_path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(out)


def force_stop(serial, package):
    adb(serial, "shell", "am", "force-stop", package)


def ensure_selinux_permissive(serial):
    try:
        out = adb(serial, "shell", "getenforce", timeout=5)
        if "Enforcing" in out:
            adb(serial, "shell", "setenforce", "0", timeout=5)
    except Exception:
        pass


def _frida_port_for(serial):
    """Her emülatöre benzersiz yerel port: emulator-5554→27042, 5556→27044, ..."""
    m = re.search(r"(\d+)$", serial)
    base = int(m.group(1)) if m else 5554
    # emulator-5554 → 27042, emulator-5556 → 27044, emulator-5558 → 27046
    return 27042 + (base - 5554) // 2


def restart_frida_server(serial):
    port = _frida_port_for(serial)
    print(f"  [{serial}] frida-server yeniden başlatılıyor (port {port})...")
    adb(serial, "shell", "pkill", "-f", "frida-server", timeout=5)
    time.sleep(5)
    subprocess.Popen(
        ["adb", "-s", serial, "shell", "/data/local/tmp/frida-server &"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(4)
    # Her emülatöre farklı yerel port → çakışma olmaz
    adb(serial, "forward", f"tcp:{port}", "tcp:27042", timeout=5)


def reset_emulator(serial, snapshot):
    """Emülatörü temiz snapshot'a döndür, boot tamamlanana kadar bekle."""
    print(f"\n  [{serial}] Snapshot yükleniyor: '{snapshot}' ...")

    # Snapshot yükle (emülatör konsolu üzerinden)
    adb(serial, "emu", "avd", "snapshot", "load", snapshot, timeout=30)

    # Cihaz hazır olana kadar bekle
    try:
        subprocess.run(["adb", "-s", serial, "wait-for-device"],
                       timeout=120, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    # Boot tamamlanana kadar bekle (sys.boot_completed = 1)
    for _ in range(30):
        out = adb(serial, "shell", "getprop", "sys.boot_completed", timeout=10)
        if out.strip() == "1":
            break
        time.sleep(3)

    time.sleep(3)  # Ekstra stabilizasyon

    # SELinux permissive + frida-server + analiz ayarları
    ensure_selinux_permissive(serial)
    restart_frida_server(serial)
    setup_emulator_for_analysis(serial)
    print(f"  [{serial}] Reset tamamlandı.")


def get_pid(serial, package, retries=3, delay=1.5):
    for _ in range(retries):
        out = adb(serial, "shell", f"ps -A | grep {package}", timeout=15)
        for line in out.splitlines():
            if package in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        return int(parts[1])
                    except ValueError:
                        continue
        time.sleep(delay)
    return None


def load_hook_script(use_bypass=False):
    raw = FRIDA_HOOKS_JS.read_text(encoding="utf-8")
    lines = raw.splitlines(keepends=True)
    if lines and lines[0].strip() == "\U0001f4e6":
        raw = "".join(lines[3:])
    if use_bypass and BYPASS_HOOKS_JS.exists():
        bypass_src = BYPASS_HOOKS_JS.read_text(encoding="utf-8")
        return bypass_src + "\n" + raw
    return raw


def frida_spawn(serial, package, use_bypass=False):
    """Frida spawn/attach. Döner: (session, events, pid)"""
    try:
        import frida
        script_src = load_hook_script(use_bypass=use_bypass)
        events = []

        dm = frida.get_device_manager()
        device = None
        for d in dm.enumerate_devices():
            if d.id == serial:
                device = d
                break
        # Serial ile bulunamazsa port üzerinden dene
        if device is None:
            port = _frida_port_for(serial)
            try:
                device = dm.add_remote_device(f"127.0.0.1:{port}")
            except Exception:
                pass
        if device is None:
            raise RuntimeError(f"Frida cihazı bulunamadı: {serial}")

        try:
            pid = device.spawn([package])
            session = device.attach(pid)
            script = session.create_script(script_src)
            script.on("message", lambda msg, _: events.append(msg["payload"])
                      if msg.get("type") == "send" else None)
            script.load()
            device.resume(pid)
            return session, events, pid
        except Exception as spawn_err:
            if "DeadSystem" in str(spawn_err):
                restart_frida_server(serial)
            try:
                adb(serial, "shell", "am", "force-stop", package)
            except Exception:
                pass
            time.sleep(2)

        ensure_selinux_permissive(serial)
        launch_app(serial, package)
        time.sleep(5)

        attach_pid = get_pid(serial, package, retries=5, delay=2.0)
        if attach_pid is None:
            raise RuntimeError(f"PID alınamadı: {package}")

        last_err = None
        for _ in range(3):
            try:
                session = device.attach(attach_pid)
                script = session.create_script(script_src)
                script.on("message", lambda msg, _: events.append(msg["payload"])
                          if msg.get("type") == "send" else None)
                script.load()
                return session, events, attach_pid
            except Exception as e:
                last_err = e
                time.sleep(2)

        raise RuntimeError(f"Attach başarısız: {last_err}")

    except Exception as e:
        return None, [], None


# ── Feature extraction ─────────────────────────────────────

def parse_logcat(log_path):
    try:
        log = open(log_path, encoding="utf-8", errors="ignore").read()
    except FileNotFoundError:
        log = ""
    return {
        "network_event_count":    len(re.findall(r"connect|socket|http|https", log, re.I)),
        "dns_query_count":        len(re.findall(r"getaddrinfo|nslookup|resolv", log, re.I)),
        "crypto_count":           len(re.findall(r"javax\.crypto|AES|RSA|Cipher", log)),
        "dex_loader_count":       len(re.findall(r"DexClassLoader|loadDex|BaseDex", log)),
        "runtime_exec_count":     len(re.findall(r"Runtime\.exec|ProcessBuilder|/bin/sh", log)),
        "sms_send_count":         len(re.findall(r"sendTextMessage|SmsManager", log)),
        "sms_read_count":         len(re.findall(r"content://sms|content://mms", log)),
        "contact_access_count":   len(re.findall(r"ContactsContract|getContacts|CONTACTS", log)),
        "call_log_access_count":  len(re.findall(r"call_log|CallLog", log)),
        "file_write_count":       len(re.findall(r"FileOutputStream|openFileOutput|FileWriter", log)),
        "reflection_count":       len(re.findall(r"getDeclaredMethod|\.invoke\(|forName", log)),
        "native_lib_count":       len(re.findall(r"System\.loadLibrary|dlopen", log)),
        "camera_access_count":    len(re.findall(r"android\.hardware\.Camera|CameraManager|openCamera", log)),
        "mic_access_count":       len(re.findall(r"AudioRecord|MediaRecorder|startRecording", log)),
        "location_access_count":  len(re.findall(r"getLastKnownLocation|requestLocationUpdates|LocationManager", log)),
        "clipboard_access_count": len(re.findall(r"ClipboardManager|getPrimaryClip", log)),
        "device_admin_count":     len(re.findall(r"DevicePolicyManager|isAdminActive|BIND_DEVICE_ADMIN", log)),
        "wakelock_count":         len(re.findall(r"acquireWakeLock|PARTIAL_WAKE_LOCK|WakeLock", log)),
        "exception_count":        len(re.findall(r"Exception|FATAL|ANR", log)),
    }


def parse_frida_log(frida_log_path):
    try:
        events = json.load(open(frida_log_path))
    except Exception:
        events = []

    counts = {k: 0 for k in [
        "frida_reflection_forName", "frida_reflection_invoke",
        "frida_dex_load", "frida_dex_load_inmemory",
        "frida_crypto_cipher", "frida_crypto_digest", "frida_base64_encode",
        "frida_network_socket", "frida_network_http",
        "frida_runtime_exec", "frida_file_write", "frida_zip_open",
        "frida_sms_send", "frida_sms_read", "frida_telephony_query",
        "frida_contact_query", "frida_call_log_read",
        "frida_clipboard_read", "frida_clipboard_write",
        "frida_camera_open", "frida_location_request",
        "frida_shared_prefs_write", "frida_alarm_set",
        "frida_broadcast_send", "frida_native_lib_load",
        "frida_json_parse", "frida_device_admin_check", "frida_package_enum",
    ]}
    unique_hosts = set()
    for e in events:
        t = e.get("type", "")
        key = f"frida_{t}"
        if key in counts:
            counts[key] += 1
        if t == "network_socket" and e.get("host"):
            unique_hosts.add(e["host"])
        elif t == "network_http" and e.get("url"):
            try:
                from urllib.parse import urlparse
                h = urlparse(e["url"]).netloc
                if h:
                    unique_hosts.add(h)
            except Exception:
                pass
    counts["frida_unique_hosts"] = len(unique_hosts)
    return counts


# ── Tek APK analizi ────────────────────────────────────────

def analyze_apk(serial, sha256, apk_path, use_frida=True, use_bypass=False, analysis_wait=ANALYSIS_WAIT):
    log_path       = str(DYNAMIC_LOGS_DIR / f"{sha256}_{serial}.log")
    frida_log_path = str(DYNAMIC_LOGS_DIR / f"{sha256}_{serial}_frida.json")

    package = get_package_name(apk_path)
    if not package:
        return None

    frida_session = None
    try:
        if not install_apk(serial, apk_path):
            return None

        # Analiz ayarları (snapshot reset sonrası sıfırlanmış olabilir)
        setup_emulator_for_analysis(serial)
        # Analizi engelleyebilecek uygulamaları kapat
        for ipkg in INTERFERING_PKGS:
            adb(serial, "shell", f"am force-stop {ipkg}", timeout=3)

        grant_all_permissions(serial, package)
        adb(serial, "logcat", "-c")
        time.sleep(1)

        frida_events = []
        if use_frida:
            frida_session, frida_events, _ = frida_spawn(serial, package, use_bypass=use_bypass)
            if frida_session is None:
                launch_app(serial, package)
                run_monkey(serial, package)
            else:
                run_monkey(serial, package)
        else:
            launch_app(serial, package)
            run_monkey(serial, package)

        # Uygulama başlar başlamaz beliren diyalogları hemen kapat
        time.sleep(3)
        _dismiss_dialogs(serial)

        stop_keeper = threading.Event()
        keeper = threading.Thread(
            target=foreground_keeper,
            args=(serial, package, stop_keeper),
            daemon=True,
        )
        keeper.start()
        time.sleep(analysis_wait)
        stop_keeper.set()
        keeper.join(timeout=KEEPER_INTERVAL + 2)

        collect_logcat(serial, log_path)
        force_stop(serial, package)

        if frida_session:
            try:
                time.sleep(1)
                with open(frida_log_path, "w") as f:
                    json.dump(frida_events, f)
                frida_session.detach()
            except Exception:
                pass
        time.sleep(2)

    finally:
        uninstall_apk(serial, package)

    feats = parse_logcat(log_path)
    feats.update(parse_frida_log(frida_log_path))
    feats["sha256"]     = sha256
    feats["frida_used"] = int(use_frida and os.path.exists(frida_log_path))
    return feats


# ── Thread-safe kaydetme ───────────────────────────────────

def save(results, out_path, lock, overwrite_sha=None):
    if not results:
        return
    with lock:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        df_new = pd.DataFrame(results)
        if out_path.exists():
            df_old = pd.read_parquet(out_path)
            if overwrite_sha:
                df_old = df_old[~df_old["sha256"].str.upper().isin(overwrite_sha)]
            df_new = pd.concat([df_old, df_new], ignore_index=True)
            df_new = df_new.drop_duplicates(subset="sha256")
        df_new.to_parquet(out_path, index=False)


# ── Worker (her emülatör için bir thread) ─────────────────

FRIDA_FEATURE_COLS = [
    "frida_reflection_forName", "frida_reflection_invoke",
    "frida_dex_load", "frida_dex_load_inmemory",
    "frida_crypto_cipher", "frida_crypto_digest", "frida_base64_encode",
    "frida_network_socket", "frida_network_http",
    "frida_runtime_exec", "frida_file_write", "frida_zip_open",
    "frida_sms_send", "frida_sms_read", "frida_telephony_query",
    "frida_contact_query", "frida_call_log_read",
    "frida_clipboard_read", "frida_clipboard_write",
    "frida_camera_open", "frida_location_request",
    "frida_shared_prefs_write", "frida_alarm_set",
    "frida_broadcast_send", "frida_native_lib_load",
    "frida_json_parse", "frida_device_admin_check", "frida_package_enum",
    "frida_unique_hosts",
]


def has_frida_signal(feats):
    """Frida'nın gerçekten bir şey yakaladığı mı?"""
    return any(feats.get(c, 0) > 0 for c in FRIDA_FEATURE_COLS)


def worker(serial, apk_queue, out_path, done_sha, lock,
           counters, use_frida, target, pbar, reset_every, snapshot,
           use_bypass=False, analysis_wait=ANALYSIS_WAIT):
    """
    counters["frida_ok"]: --target için sayılan değer (Frida'da ≥1 event yakalanan)
    counters["ok"]      : kurulum başarılı olan toplam
    counters["fail"]    : kurulum/analiz başarısız
    """
    local_results = []
    since_reset = 0

    for sha256, apk_path in apk_queue:
        with lock:
            # Hedef: Frida sinyali yakalanan örnek sayısı
            if target and counters["frida_ok"] >= target:
                break
            if sha256.upper() in done_sha:
                pbar.update(1)
                continue

        if reset_every and since_reset >= reset_every:
            if local_results:
                save(local_results, out_path, lock)
                local_results = []
            reset_emulator(serial, snapshot)
            since_reset = 0

        res = analyze_apk(serial, sha256, apk_path, use_frida=use_frida,
                          use_bypass=use_bypass, analysis_wait=analysis_wait)

        with lock:
            if res:
                done_sha.add(sha256.upper())
                local_results.append(res)
                counters["ok"] += 1
                since_reset += 1
                if has_frida_signal(res):
                    counters["frida_ok"] += 1
            else:
                counters["fail"] += 1
            pbar.set_postfix_str(
                "Frida:{frida_ok} OK:{ok} F:{fail} [{s}]".format(
                    s=serial[-4:], **counters)
            )
            pbar.update(1)

        if len(local_results) % 10 == 0 and local_results:
            save(local_results, out_path, lock)
            local_results = []

    if local_results:
        save(local_results, out_path, lock)


# ── Ana fonksiyon ──────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Paralel dinamik analiz (çok emülatör)")
    parser.add_argument("--apk-dir",  required=True,
                        help="APK klasörü (orn: data/apks/benign/2021)")
    parser.add_argument("--year",     type=int, required=True,
                        help="Yıl etiketi (parquet yoluna yazılır)")
    parser.add_argument("--benign",   action="store_true",
                        help="Benign APK'lar (varsayılan: malware)")
    parser.add_argument("--devices",  nargs="+", default=None,
                        help="Emülatör serials (varsayılan: otomatik algıla)")
    parser.add_argument("--target",   type=int, default=None,
                        help="Toplam hedef analiz sayısı (tüm emülatörlere bölünür)")
    parser.add_argument("--no-frida",    action="store_true",
                        help="Frida olmadan çalıştır")
    parser.add_argument("--output",      type=str, default=None,
                        help="Çıktı parquet yolu (varsayılan: features/dynamic_features_LABEL/YEAR/)")
    parser.add_argument("--reset-every", type=int, default=25,
                        help="Kaç başarılı APK sonrası emülatör sıfırlansın (0=hiç, varsayılan: 25)")
    parser.add_argument("--snapshot",    type=str, default="clean",
                        help="Yüklenecek AVD snapshot adı (varsayılan: 'clean')")
    parser.add_argument("--skip-from",   type=str, default=None,
                        help="Bu features/ dizinindeki mevcut parquet'lerden done SHA256'ları oku "
                             "(orn: C:\\proje\\data\\features)")
    parser.add_argument("--bypass", action="store_true",
                        help="SSL pinning / root detection / emulator detection bypass uygula")
    parser.add_argument("--analysis-wait", type=int, default=ANALYSIS_WAIT,
                        help=f"Uygulama calistirma suresi saniye (varsayilan: {ANALYSIS_WAIT})")
    parser.add_argument("--known-parquet", type=str, default=None,
                        help="Sadece bu parquet'te frida_used=1 olan SHA256'lari analiz et")
    args = parser.parse_args()

    # Emülatörleri belirle
    if args.devices:
        serials = args.devices
    else:
        serials = detect_emulators()
        if not serials:
            print("HATA: Bağlı emülatör bulunamadı. Android Studio'dan başlat.")
            sys.exit(1)

    reset_label = f"her {args.reset_every} APK'da bir" if args.reset_every else "kapali"
    print(f"Kullanilacak emulatorler ({len(serials)}): {serials}")
    print(f"Emulator reset  : {reset_label}" + (f" (snapshot: '{args.snapshot}')" if args.reset_every else ""))
    print(f"Analiz suresi   : {args.analysis_wait}s")

    # Çıktı yolu
    label_str = "benign" if args.benign else "malware"
    if args.output:
        out_path = Path(args.output)
    else:
        out_path = (Path(__file__).parents[2] / "data" / "features"
                    / f"dynamic_features_{label_str}" / str(args.year)
                    / "dynamic_features.parquet")

    print(f"Çıktı: {out_path}")

    # APK listesini oluştur
    apk_dir = Path(args.apk_dir)
    apk_files = list(apk_dir.glob("*.apk"))
    if not apk_files:
        print(f"HATA: {apk_dir} içinde APK bulunamadı.")
        sys.exit(1)

    # sha256 = dosya adından al (büyük harf normalize)
    all_apks = [(f.stem.upper(), str(f)) for f in apk_files]

    # --known-parquet: sadece daha önce frida_used=1 olan APK'ları çalıştır
    if args.known_parquet:
        kp = Path(args.known_parquet)
        if not kp.exists():
            print(f"HATA: --known-parquet dosyası bulunamadı: {kp}")
            sys.exit(1)
        df_kp = pd.read_parquet(kp)
        known_sha = set(df_kp[df_kp["frida_used"] == 1]["sha256"].str.upper())
        all_apks = [(sha, path) for sha, path in all_apks if sha in known_sha]
        print(f"--known-parquet: {len(known_sha)} frida_used=1 SHA256 -> {len(all_apks)} APK eslesti")

    # done_sha: hem yerel çıktıdan hem --skip-from dizininden yükle
    done_sha = set()
    frida_ok_existing = 0

    def _load_parquet_sha(path):
        """Parquet'ten sha256 setini ve frida_ok sayısını döner."""
        try:
            df = pd.read_parquet(path)
            shas = set(s.upper() for s in df["sha256"].tolist())
            cols = [c for c in FRIDA_FEATURE_COLS if c in df.columns]
            fok = int((df[cols].sum(axis=1) > 0).sum()) if cols else 0
            return shas, fok
        except Exception:
            return set(), 0

    # Yerel çıktı dosyası (resume)
    if out_path.exists():
        shas, fok = _load_parquet_sha(out_path)
        done_sha |= shas
        frida_ok_existing += fok
        print(f"Yerel kayıt   : {len(shas)} APK ({fok} Frida sinyalli) — atlanacak")

    # --skip-from: başka makinedeki features/ dizini
    if args.skip_from:
        skip_parquet = (Path(args.skip_from)
                        / f"dynamic_features_{label_str}"
                        / str(args.year)
                        / "dynamic_features.parquet")
        if skip_parquet.resolve() == out_path.resolve():
            print(f"--skip-from   : çıktı dosyasıyla aynı, atlanıyor")
        elif skip_parquet.exists():
            shas, fok = _load_parquet_sha(skip_parquet)
            new_skip = shas - done_sha
            done_sha |= shas
            frida_ok_existing += fok
            print(f"--skip-from   : {len(new_skip)} ek APK atlanacak ({fok} Frida sinyalli) — {skip_parquet}")
        else:
            print(f"UYARI: --skip-from dosyası bulunamadı: {skip_parquet}")

    # Done olanları filtrele
    remaining = [(sha, path) for sha, path in all_apks if sha not in done_sha]
    print(f"APK havuzu: {len(all_apks)} toplam | {len(remaining)} kalan")

    if not remaining:
        print("Tüm APK'lar zaten analiz edilmiş.")
        return

    if args.target:
        # Hedefe mevcut dosyadan gelen Frida örnekleri de dahil
        still_needed = max(0, args.target - frida_ok_existing)
        print(f"Hedef: {args.target} Frida sinyalli örnek "
              f"(mevcut: {frida_ok_existing}, gereken: {still_needed})")
        if still_needed == 0:
            print("Hedefe zaten ulaşılmış.")
            return

    # APK'ları emülatörlere böl (round-robin değil, blok halinde)
    n = len(serials)
    chunks = [remaining[i::n] for i in range(n)]
    for i, (serial, chunk) in enumerate(zip(serials, chunks)):
        print(f"  {serial}: {len(chunk)} APK")

    # SELinux permissive (tüm emülatörler)
    if not args.no_frida:
        for serial in serials:
            ensure_selinux_permissive(serial)

    # Paylaşılan state
    lock     = threading.Lock()
    counters = {"ok": 0, "fail": 0, "frida_ok": frida_ok_existing}
    pbar     = tqdm(total=len(remaining), desc="Toplam ilerleme")

    # Thread'leri başlat
    threads = []
    for serial, chunk in zip(serials, chunks):
        t = threading.Thread(
            target=worker,
            args=(serial, chunk, out_path, done_sha, lock,
                  counters, not args.no_frida, args.target, pbar,
                  args.reset_every, args.snapshot),
            kwargs={"use_bypass": args.bypass, "analysis_wait": args.analysis_wait},
            daemon=True,
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    pbar.close()

    total_now = len(pd.read_parquet(out_path)) if out_path.exists() else 0
    print(f"\nBaşarılı: {counters['ok']} | Frida sinyalli: {counters['frida_ok']} | Başarısız: {counters['fail']}")
    print(f"Parquet toplam: {total_now} örnek -> {out_path}")


if __name__ == "__main__":
    main()
