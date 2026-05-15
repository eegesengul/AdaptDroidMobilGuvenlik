"""
Tum benign yillarini sirayla analiz eder.
Emulator offline, frida ölü, parquet bozuk, pipeline takili gibi
durumlarda otomatik kurtarir.
Calistir: python run_benign_all.py
"""

import io
import subprocess
import sys
import time
import logging
from pathlib import Path
from datetime import datetime

YEARS         = [2016, 2017, 2018, 2019, 2020, 2021]
AVD_NAME      = "Pixel_3"
SNAPSHOT      = "clean"
ANALYSIS_WAIT = 300
MAX_RETRIES   = 9999
RETRY_DELAY   = 45

# Emulator hizli bitiyorsa (saniyelerde) cihaz offline demektir
MIN_SANE_DURATION = 30

# Bir APK icin maksimum bekleme suresi (saniye). Bu katiyla carpilarak
# toplam subprocess timeout hesaplanir.
MAX_SECONDS_PER_APK = ANALYSIS_WAIT + 120   # 420s / APK

FRIDA_SERVER  = "/data/local/tmp/frida-server"
SDK_EMU       = Path.home() / "AppData/Local/Android/Sdk/emulator/emulator.exe"

LOG_FILE = Path("data/dynamic_logs/benign_all_run.log")
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(
            io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        ),
    ],
)
log = logging.getLogger()


# ── Emulator yardimcilari ─────────────────────────────────

def _adb(*args, timeout=10) -> str:
    try:
        r = subprocess.run(["adb"] + list(args), capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception:
        return ""


def online_serial() -> str | None:
    """Cihazlar listesinden ilk 'device' durumundaki emulator serialini dondur."""
    out = _adb("devices")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == "device" and parts[0].startswith("emulator-"):
            return parts[0]
    return None


def wait_for_online(timeout=180) -> str | None:
    log.info("  Emulator online olana kadar bekleniyor...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        serial = online_serial()
        if serial:
            for _ in range(20):
                out = _adb("-s", serial, "shell", "getprop", "sys.boot_completed")
                if out.strip() == "1":
                    log.info(f"  Emulator hazir: {serial}")
                    return serial
                time.sleep(5)
        time.sleep(5)
    return None


def kill_offline_emulators():
    out = _adb("devices")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == "offline" and parts[0].startswith("emulator-"):
            log.info(f"  Offline emulator kapatiliyor: {parts[0]}")
            _adb("-s", parts[0], "emu", "kill", timeout=5)


def kill_all_emulators():
    """Calisir durumdaki tum emulatorleri kapat."""
    out = _adb("devices")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].startswith("emulator-"):
            log.info(f"  Emulator kapatiliyor: {parts[0]}")
            _adb("-s", parts[0], "emu", "kill", timeout=5)
    time.sleep(3)


def start_emulator() -> str | None:
    """Cold boot ile emulator baslatir, clean snapshot yukler, online olmasini bekler."""
    kill_all_emulators()
    time.sleep(5)

    if not SDK_EMU.exists():
        log.error(f"  emulator.exe bulunamadi: {SDK_EMU}")
        return None

    log.info(f"  Emulator cold-boot ile baslatiliyor: {AVD_NAME}")
    subprocess.Popen(
        [str(SDK_EMU), "-avd", AVD_NAME, "-no-audio", "-no-window", "-no-snapshot-load"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(10)
    serial = wait_for_online(timeout=300)
    if serial is None:
        log.error("  Cold boot sonrasi emulator online olmadi.")
        return None

    # Clean snapshot yukle (frida-server ve ayarlar icin)
    log.info(f"  [{serial}] Clean snapshot yukleniyor: '{SNAPSHOT}'")
    out = _adb("-s", serial, "emu", "avd", "snapshot", "load", SNAPSHOT, timeout=60)
    log.info(f"  Snapshot yaniti: {out[:80] if out else '(bos)'}")
    time.sleep(8)

    # Snapshot sonrasi boot bekleme
    for _ in range(24):
        if _adb("-s", serial, "shell", "getprop", "sys.boot_completed").strip() == "1":
            log.info(f"  [{serial}] Snapshot sonrasi boot tamamlandi.")
            return serial
        time.sleep(5)

    log.warning("  Snapshot sonrasi boot tamamlanamadi, devam ediliyor.")
    return serial


def ensure_emulator() -> str | None:
    """Online emulator yoksa baslatip serialini dondur."""
    serial = online_serial()
    if serial:
        return serial
    log.warning("  Hic online emulator yok, baslatiliyor...")
    return start_emulator()


def start_frida_server(serial: str):
    """Frida-server'i oldur ve yeniden baslat."""
    _adb("-s", serial, "shell", "pkill -f frida-server", timeout=5)
    time.sleep(2)
    _adb("-s", serial, "shell", f"su 0 nohup {FRIDA_SERVER} &>/dev/null &", timeout=5)
    time.sleep(4)
    # Kontrol
    out = _adb("-s", serial, "shell", "ps 2>/dev/null | grep frida-server", timeout=5)
    if "frida-server" in out:
        log.info(f"  [{serial}] frida-server calisiyor.")
    else:
        log.warning(f"  [{serial}] frida-server baslatılamadi! Analiz Frida olmadan devam edecek.")


def setup_emulator(serial: str):
    """Portrait kilidi, animasyonlar kapali, monkey temizle, frida-server yeniden baslat."""
    cmds = [
        "settings put global stay_on_while_plugged_in 3",
        "settings put system screen_off_timeout 2147483647",
        "settings put secure lockscreen.disabled 1",
        "settings put global window_animation_scale 0",
        "settings put global transition_animation_scale 0",
        "settings put global animator_duration_scale 0",
        "settings put system accelerometer_rotation 0",
        "settings put system user_rotation 0",
        "wm user-rotation lock 0",
        "wm dismiss-keyguard",
        "pkill -f monkey",
    ]
    for cmd in cmds:
        _adb("-s", serial, "shell", cmd, timeout=6)
    start_frida_server(serial)
    log.info(f"  [{serial}] Emulator ayarlari uygulandı.")


def restore_snapshot(serial: str) -> bool:
    """Clean snapshot yukle ve boot bekle. Basarili olursa True doner."""
    log.info(f"  [{serial}] Snapshot restore: '{SNAPSHOT}'")
    _adb("-s", serial, "emu", "avd", "snapshot", "load", SNAPSHOT, timeout=60)
    time.sleep(8)
    for _ in range(24):
        if _adb("-s", serial, "shell", "getprop", "sys.boot_completed").strip() == "1":
            return True
        time.sleep(5)
    return False


# ── Pipeline yardimcilari ─────────────────────────────────

def output_path(year: int) -> Path:
    return Path(f"data/features/dynamic_features_benign/{year}/dynamic_features_5min.parquet")


def apk_dir(year: int) -> Path:
    return Path(f"data/apks/benign/{year}")


def count_done(year: int) -> int:
    out = output_path(year)
    if not out.exists():
        return 0
    try:
        import pandas as pd
        return len(pd.read_parquet(out))
    except Exception:
        log.warning(f"  Bozuk parquet dosyasi siliniyor: {out}")
        try:
            out.unlink()
        except Exception:
            pass
        return 0


def build_cmd(year: int, serial: str) -> list[str]:
    return [
        sys.executable, "src/03_dynamic/run_dynamic_parallel.py",
        "--apk-dir",        str(apk_dir(year)),
        "--year",           str(year),
        "--benign",
        "--devices",        serial,
        "--reset-every",    "25",
        "--snapshot",       SNAPSHOT,
        "--analysis-wait",  str(ANALYSIS_WAIT),
        "--bypass",
        "--output",         str(output_path(year)),
    ]


def subprocess_timeout(total_apks: int, done: int) -> int:
    """Kalan APK sayisina gore subprocess timeout hesapla (x1.8 guvenlik payi)."""
    remaining = max(total_apks - done, 1)
    return int(remaining * MAX_SECONDS_PER_APK * 1.8)


# ── Ana dongu ─────────────────────────────────────────────

def run_year(year: int):
    total = len(list(apk_dir(year).glob("*.apk")))
    log.info(f"=== Yil {year} basliyor ({total} APK) ===")

    for attempt in range(1, MAX_RETRIES + 1):
        serial = ensure_emulator()
        if serial is None:
            log.error("  Emulator baslatılamadi! 60s sonra tekrar denenecek.")
            time.sleep(60)
            continue

        setup_emulator(serial)

        done_before = count_done(year)
        timeout_s   = subprocess_timeout(total, done_before)
        log.info(
            f"  [{year}] Deneme #{attempt} | Tamamlanan: {done_before}/{total} "
            f"| Cihaz: {serial} | Timeout: {timeout_s//3600}s{(timeout_s%3600)//60}dk"
        )

        t0 = time.time()
        try:
            result = subprocess.run(build_cmd(year, serial), timeout=timeout_s)
            rc = result.returncode
        except subprocess.TimeoutExpired:
            log.error(
                f"  [{year}] TIMEOUT! {timeout_s}s sonra hala bitmedi — "
                f"pipeline takilmis. Emulator yeniden baslatiliyor."
            )
            rc = -1

        elapsed = time.time() - t0
        done_after = count_done(year)
        gained     = done_after - done_before

        # Basari: yeterli APK tamamlandi
        if rc == 0 and done_after >= total * 0.95:
            log.info(f"  [{year}] TAMAMLANDI ({done_after}/{total} APK kaydedildi)")
            return

        # Exit 0 ama az APK: sessiz hata
        if rc == 0 and done_after < total * 0.95:
            log.warning(
                f"  [{year}] exit 0 ama sadece {done_after}/{total} APK "
                f"(%{100*done_after//total if total else 0}) — yeniden baslatiliyor"
            )

        log.warning(
            f"  [{year}] rc={rc} | +{gained} APK | Sure={elapsed:.0f}s"
        )

        # Hizli bitis veya hic ilerleme yoksa: emulator/frida bozuk
        need_hard_reset = elapsed < MIN_SANE_DURATION or (elapsed > 120 and gained == 0)

        if need_hard_reset:
            log.warning("  Sert reset: emulator yeniden baslatiliyor...")
            serial = start_emulator()
            if serial is None:
                log.error("  Emulator baslatılamadi, 60s bekleniyor...")
                time.sleep(60)
        else:
            # Hafif reset: sadece snapshot geri yukle + frida yeniden baslat
            log.info("  Hafif reset: snapshot restore + frida yeniden baslatma...")
            ok = restore_snapshot(serial)
            if not ok:
                log.warning("  Snapshot restore basarisiz, sert reset deneniyor...")
                serial = start_emulator()
                if serial is None:
                    time.sleep(60)
                    continue
            start_frida_server(serial)
            time.sleep(RETRY_DELAY)


def main():
    log.info(f"Benign analiz basliyor - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    log.info(f"  Yillar: {YEARS} | Analiz: {ANALYSIS_WAIT}s | AVD: {AVD_NAME}")

    for year in YEARS:
        run_year(year)

    log.info("Tum yillar tamamlandi.")


if __name__ == "__main__":
    main()
