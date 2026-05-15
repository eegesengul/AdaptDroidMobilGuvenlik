"""
Tum benign yillarini sirayla analiz eder.
Emulator offline olursa otomatik yeniden baslatir.
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
RETRY_DELAY   = 45    # hata sonrasi bekleme (saniye)

# Emulator hizli bitiyorsa (saniyelerde) cihaz offline demektir — bu esik altindaysa yeniden baslat
MIN_SANE_DURATION = 30  # saniye

SDK_EMU = Path.home() / "AppData/Local/Android/Sdk/emulator/emulator.exe"

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
            # boot tamamlanmasi icin sys.boot_completed=1 bekle
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


def start_emulator() -> str | None:
    """Emulator baslatir ve online olmasini bekler."""
    kill_offline_emulators()
    if not SDK_EMU.exists():
        log.error(f"  emulator.exe bulunamadi: {SDK_EMU}")
        return None

    log.info(f"  Emulator baslatiliyor: {AVD_NAME}")
    subprocess.Popen(
        [str(SDK_EMU), "-avd", AVD_NAME, "-no-audio", "-no-window",
         "-snapshot", SNAPSHOT],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(10)
    return wait_for_online(timeout=300)


def ensure_emulator() -> str | None:
    """Online emulator yoksa baslatip serialini dondur."""
    serial = online_serial()
    if serial:
        return serial
    log.warning("  Hic online emulator yok, baslatiliyor...")
    return start_emulator()


def setup_emulator(serial: str):
    """Portrait kilidi, animasyonlar kapali, frida-server."""
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
    ]
    for cmd in cmds:
        _adb("-s", serial, "shell", cmd, timeout=6)
    log.info(f"  [{serial}] Emulator ayarlari uygulandI.")


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
        return 0


def build_cmd(year: int, serial: str) -> list[str]:
    return [
        sys.executable, "src/03_dynamic/run_dynamic_parallel.py",
        "--apk-dir",        str(apk_dir(year)),
        "--year",           str(year),
        "--benign",
        "--devices",        serial,
        "--reset-every",    "1",
        "--snapshot",       SNAPSHOT,
        "--analysis-wait",  str(ANALYSIS_WAIT),
        "--bypass",
        "--output",         str(output_path(year)),
    ]


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
        log.info(f"  [{year}] Deneme #{attempt} | Tamamlanan: {done_before}/{total} | Cihaz: {serial}")

        t0 = time.time()
        result = subprocess.run(build_cmd(year, serial))
        elapsed = time.time() - t0

        done_after = count_done(year)

        if result.returncode == 0:
            log.info(f"  [{year}] TAMAMLANDI ({done_after}/{total} APK kaydedildi)")
            return

        gained = done_after - done_before
        log.warning(
            f"  [{year}] Cikis kodu={result.returncode} | "
            f"  {gained} APK eklendi | "
            f"  Sure={elapsed:.0f}s"
        )

        # Cok hizli bitiyorsa emulator offline olmus demektir
        if elapsed < MIN_SANE_DURATION:
            log.warning("  Cok hizli bitis — emulator offline. Yeniden baslatiliyor...")
            _adb("-s", serial, "emu", "kill", timeout=5)
            time.sleep(10)
            serial = start_emulator()
            if serial is None:
                log.error("  Emulator baslatılamadi, 60s bekleniyor...")
                time.sleep(60)
        else:
            time.sleep(RETRY_DELAY)


def main():
    log.info(f"Benign analiz basliyor - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    log.info(f"  Yillar: {YEARS} | Analiz: {ANALYSIS_WAIT}s | AVD: {AVD_NAME}")

    for year in YEARS:
        run_year(year)

    log.info("Tum yillar tamamlandi.")


if __name__ == "__main__":
    main()
