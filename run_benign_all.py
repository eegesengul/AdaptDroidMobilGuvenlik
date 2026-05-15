"""
Tum benign yillarini N emülatörle paralel analiz eder.
Emulator offline, frida ölü, parquet bozuk, pipeline takili gibi
durumlarda otomatik kurtarir.
Calistir: python run_benign_all.py [--years 2016 2017 2018]
"""

import argparse
import io
import subprocess
import sys
import time
import logging
from pathlib import Path
from datetime import datetime

DEFAULT_YEARS   = [2016, 2017, 2018, 2019, 2020, 2021]
NUM_EMULATORS   = 2                          # kac emulator kullanilacak
AVD_NAMES       = [f"Pixel_3_{i+1}" for i in range(NUM_EMULATORS)]
SNAPSHOT        = "clean"
ANALYSIS_WAIT   = 300
MAX_RETRIES     = 9999
RETRY_DELAY     = 45

MIN_SANE_DURATION   = 30
MAX_SECONDS_PER_APK = ANALYSIS_WAIT + 120   # 420s / APK

FRIDA_SERVER = "/data/local/tmp/frida-server"
SDK_EMU      = Path.home() / "AppData/Local/Android/Sdk/emulator/emulator.exe"

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


def online_serials() -> list[str]:
    """Tum 'device' durumundaki emulator seriallerini dondur."""
    out = _adb("devices")
    return [
        line.split()[0]
        for line in out.splitlines()
        if len(line.split()) == 2
        and line.split()[1] == "device"
        and line.split()[0].startswith("emulator-")
    ]


def wait_for_online(timeout=300) -> list[str]:
    """NUM_EMULATORS kadar serial gelene kadar bekle."""
    log.info(f"  {NUM_EMULATORS} emulator online olana kadar bekleniyor...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        serials = online_serials()
        booted = []
        for s in serials:
            if _adb("-s", s, "shell", "getprop", "sys.boot_completed").strip() == "1":
                booted.append(s)
        if len(booted) >= NUM_EMULATORS:
            log.info(f"  Tum emulatorler hazir: {booted}")
            return booted[:NUM_EMULATORS]
        time.sleep(5)
    # Zaman asimi: elinde ne varsa dondur
    booted = [s for s in online_serials()
              if _adb("-s", s, "shell", "getprop", "sys.boot_completed").strip() == "1"]
    return booted


def kill_all_emulators():
    out = _adb("devices")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].startswith("emulator-"):
            _adb("-s", parts[0], "emu", "kill", timeout=5)
    time.sleep(4)


def start_emulator(avd_name: str):
    """Tek bir AVD'yi cold boot ile baslatir (arka planda)."""
    if not SDK_EMU.exists():
        log.error(f"  emulator.exe bulunamadi: {SDK_EMU}")
        return
    log.info(f"  Emulator baslatiliyor: {avd_name}")
    subprocess.Popen(
        [str(SDK_EMU), "-avd", avd_name, "-no-audio", "-no-window", "-no-snapshot-load"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def start_all_emulators() -> list[str]:
    """Tum AVD'leri cold boot ile baslatir, online olana kadar bekler."""
    kill_all_emulators()
    time.sleep(3)
    for avd in AVD_NAMES:
        start_emulator(avd)
        time.sleep(3)          # port catismasini onlemek icin
    time.sleep(8)
    serials = wait_for_online(timeout=360)
    if not serials:
        log.error("  Hic emulator online olmadi!")
    return serials


def ensure_all_emulators() -> list[str]:
    """Online emulator sayisi yetersizse eksikleri baslatir."""
    serials = [s for s in online_serials()
               if _adb("-s", s, "shell", "getprop", "sys.boot_completed").strip() == "1"]
    if len(serials) >= NUM_EMULATORS:
        return serials[:NUM_EMULATORS]
    log.warning(f"  {len(serials)}/{NUM_EMULATORS} emulator online — eksikler baslatiliyor...")
    return start_all_emulators()


def start_frida_server(serial: str):
    _adb("-s", serial, "shell", "pkill -f frida-server", timeout=5)
    time.sleep(2)
    _adb("-s", serial, "shell", f"su 0 nohup {FRIDA_SERVER} &>/dev/null &", timeout=5)
    time.sleep(4)
    out = _adb("-s", serial, "shell", "ps 2>/dev/null | grep frida-server", timeout=5)
    if "frida-server" in out:
        log.info(f"  [{serial}] frida-server calisiyor.")
    else:
        log.warning(f"  [{serial}] frida-server baslatılamadi!")


def restore_snapshot(serial: str) -> bool:
    log.info(f"  [{serial}] Snapshot restore: '{SNAPSHOT}'")
    _adb("-s", serial, "emu", "avd", "snapshot", "load", SNAPSHOT, timeout=60)
    time.sleep(8)
    for _ in range(24):
        if _adb("-s", serial, "shell", "getprop", "sys.boot_completed").strip() == "1":
            return True
        time.sleep(5)
    return False


def setup_emulator(serial: str):
    """Portrait, animasyonsuz, monkey temizle, frida yeniden baslat."""
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


def setup_all_emulators(serials: list[str]):
    for s in serials:
        setup_emulator(s)


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
        log.warning(f"  Bozuk parquet siliniyor: {out}")
        try:
            out.unlink()
        except Exception:
            pass
        return 0


def build_cmd(year: int, serials: list[str]) -> list[str]:
    return [
        sys.executable, "src/03_dynamic/run_dynamic_parallel.py",
        "--apk-dir",        str(apk_dir(year)),
        "--year",           str(year),
        "--benign",
        "--devices",        *serials,
        "--reset-every",    "25",
        "--snapshot",       SNAPSHOT,
        "--analysis-wait",  str(ANALYSIS_WAIT),
        "--bypass",
        "--output",         str(output_path(year)),
    ]


def subprocess_timeout(total_apks: int, done: int, n_emus: int) -> int:
    """Paralel emulator sayisina gore timeout hesapla."""
    remaining = max(total_apks - done, 1)
    per_emu   = (remaining + n_emus - 1) // n_emus   # tavan bolme
    return int(per_emu * MAX_SECONDS_PER_APK * 1.8)


# ── Ana dongu ─────────────────────────────────────────────

def run_year(year: int):
    total = len(list(apk_dir(year).glob("*.apk")))
    log.info(f"=== Yil {year} basliyor ({total} APK, {NUM_EMULATORS} emulator) ===")

    for attempt in range(1, MAX_RETRIES + 1):
        serials = ensure_all_emulators()
        if not serials:
            log.error("  Hic emulator baslatılamadi! 60s sonra tekrar denenecek.")
            time.sleep(60)
            continue

        n = len(serials)
        setup_all_emulators(serials)

        done_before = count_done(year)
        timeout_s   = subprocess_timeout(total, done_before, n)
        log.info(
            f"  [{year}] Deneme #{attempt} | Tamamlanan: {done_before}/{total} "
            f"| Cihazlar: {serials} | Timeout: {timeout_s//3600}s{(timeout_s%3600)//60}dk"
        )

        t0 = time.time()
        try:
            result = subprocess.run(build_cmd(year, serials), timeout=timeout_s)
            rc = result.returncode
        except subprocess.TimeoutExpired:
            log.error(f"  [{year}] TIMEOUT! Pipeline takilmis. Sert reset yapiliyor.")
            rc = -1

        elapsed  = time.time() - t0
        done_after = count_done(year)
        gained   = done_after - done_before

        if rc == 0 and done_after >= total * 0.95:
            log.info(f"  [{year}] TAMAMLANDI ({done_after}/{total} APK)")
            return

        if rc == 0 and done_after < total * 0.95:
            log.warning(
                f"  [{year}] exit 0 ama sadece {done_after}/{total} APK "
                f"(%{100*done_after//total if total else 0}) — yeniden baslatiliyor"
            )

        log.warning(f"  [{year}] rc={rc} | +{gained} APK | Sure={elapsed:.0f}s")

        need_hard_reset = elapsed < MIN_SANE_DURATION or (elapsed > 120 and gained == 0)
        if need_hard_reset:
            log.warning("  Sert reset: tum emulatorler yeniden baslatiliyor...")
            start_all_emulators()
        else:
            log.info("  Hafif reset: snapshot restore + frida yeniden baslatma...")
            for s in serials:
                ok = restore_snapshot(s)
                if not ok:
                    log.warning(f"  [{s}] Snapshot restore basarisiz, sert reset deneniyor...")
                    start_all_emulators()
                    break
                start_frida_server(s)
            time.sleep(RETRY_DELAY)


def main():
    parser = argparse.ArgumentParser(description="Benign APK paralel dinamik analiz")
    parser.add_argument(
        "--years", nargs="+", type=int, default=DEFAULT_YEARS,
        metavar="YIL",
        help=f"Analiz edilecek yillar (varsayilan: {DEFAULT_YEARS})"
    )
    args = parser.parse_args()
    years = args.years

    log.info(f"Benign analiz basliyor - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    log.info(f"  Yillar: {years} | AVD'ler: {AVD_NAMES} | Analiz: {ANALYSIS_WAIT}s")

    for year in years:
        run_year(year)

    log.info("Tum yillar tamamlandi.")


if __name__ == "__main__":
    main()
