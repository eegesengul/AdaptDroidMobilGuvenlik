"""
Tek komutla tam kurulum ve 2 emülatörle paralel analiz baslatma.
Kullanim: python setup_and_run.py

Yaptiklarimiz:
  1. Android SDK / emulator.exe bul
  2. API-28 system image indir (yoksa)
  3. Pixel_3_1 ve Pixel_3_2 AVD olustur (yoksa)
  4. frida-server indir + her emülatöre push et
  5. Her emülatörde clean snapshot kaydet
  6. run_benign_all.py'yi baslatir (2 emülatörle)
"""

import io
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import lzma
import logging
from pathlib import Path

# ── Sabitler ──────────────────────────────────────────────

NUM_EMULATORS   = 2
AVD_NAMES       = [f"Pixel_3_{i+1}" for i in range(NUM_EMULATORS)]

FRIDA_VERSION   = "17.9.7"
FRIDA_ARCH      = "android-x86_64"
FRIDA_URL       = (
    f"https://github.com/frida/frida/releases/download/{FRIDA_VERSION}/"
    f"frida-server-{FRIDA_VERSION}-{FRIDA_ARCH}.xz"
)
FRIDA_LOCAL     = Path("tools/frida-server")
FRIDA_DEVICE    = "/data/local/tmp/frida-server"

API_LEVEL       = "28"
SYSTEM_IMAGE    = f"system-images;android-{API_LEVEL};google_apis;x86_64"
SNAPSHOT        = "clean"

SDK_ROOT = (
    Path(os.environ.get("ANDROID_SDK_ROOT", ""))
    or Path(os.environ.get("ANDROID_HOME", ""))
    or Path.home() / "AppData/Local/Android/Sdk"
    or Path.home() / "Android/Sdk"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(
        io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    )],
)
log = logging.getLogger()


# ── Yardimci fonksiyonlar ──────────────────────────────────

def sdk_tool(name: str) -> Path | None:
    candidates = [
        SDK_ROOT / "emulator" / name,
        SDK_ROOT / "emulator" / (name + ".exe"),
        SDK_ROOT / "cmdline-tools" / "latest" / "bin" / name,
        SDK_ROOT / "cmdline-tools" / "latest" / "bin" / (name + ".bat"),
        SDK_ROOT / "tools" / "bin" / name,
        SDK_ROOT / "tools" / "bin" / (name + ".bat"),
    ]
    for p in candidates:
        if p.exists():
            return p
    found = shutil.which(name) or shutil.which(name + ".exe") or shutil.which(name + ".bat")
    return Path(found) if found else None


def run(cmd, **kw):
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("timeout", 120)
    r = subprocess.run(cmd, **kw)
    return (r.stdout + r.stderr).strip(), r.returncode


def adb(*args, timeout=30) -> str:
    out, _ = run(["adb"] + list(args), timeout=timeout)
    return out


def online_serials() -> list[str]:
    out = adb("devices")
    return [
        line.split()[0]
        for line in out.splitlines()
        if len(line.split()) == 2
        and line.split()[1] == "device"
        and line.split()[0].startswith("emulator-")
    ]


def wait_all_booted(n: int, timeout=360) -> list[str]:
    log.info(f"  {n} emulator boot bekleniyor...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        serials = online_serials()
        booted = [s for s in serials
                  if adb("-s", s, "shell", "getprop", "sys.boot_completed").strip() == "1"]
        log.info(f"  Boot: {len(booted)}/{n} hazir")
        if len(booted) >= n:
            return booted[:n]
        time.sleep(8)
    booted = [s for s in online_serials()
              if adb("-s", s, "shell", "getprop", "sys.boot_completed").strip() == "1"]
    return booted


def kill_all():
    out = adb("devices")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].startswith("emulator-"):
            adb("-s", parts[0], "emu", "kill", timeout=5)
    time.sleep(4)


# ── Adim 1: SDK kontrol ────────────────────────────────────

def check_sdk() -> Path:
    emu = sdk_tool("emulator")
    if emu is None:
        log.error(
            "Android emulator bulunamadi!\n"
            "Lutfen Android Studio kur veya ANDROID_SDK_ROOT ortam degiskenini ayarla.\n"
            f"Aranan konum: {SDK_ROOT}"
        )
        sys.exit(1)
    log.info(f"SDK bulundu: {SDK_ROOT}")
    return emu


# ── Adim 2: System image ───────────────────────────────────

def ensure_system_image():
    sdkmanager = sdk_tool("sdkmanager")
    if sdkmanager is None:
        log.warning("sdkmanager bulunamadi — system image kontrolu atlaniyor.")
        return
    out, _ = run([str(sdkmanager), "--list_installed"])
    if SYSTEM_IMAGE in out:
        log.info(f"System image zaten kurulu: {SYSTEM_IMAGE}")
        return
    log.info(f"System image indiriliyor: {SYSTEM_IMAGE}  (birkac dakika surabilir...)")
    run([str(sdkmanager), "--install", SYSTEM_IMAGE],
        capture_output=False, timeout=600)


# ── Adim 3: AVD'ler ────────────────────────────────────────

def ensure_avd(avd_name: str, avdmanager: Path | None):
    if avdmanager is None:
        log.warning(f"avdmanager bulunamadi — {avd_name} AVD kontrolu atlaniyor.")
        return
    out, _ = run([str(avdmanager), "list", "avd"])
    if avd_name in out:
        log.info(f"AVD zaten mevcut: {avd_name}")
        return
    log.info(f"AVD olusturuluyor: {avd_name} (API {API_LEVEL})")
    _, rc = run(
        [str(avdmanager), "create", "avd",
         "-n", avd_name,
         "-k", SYSTEM_IMAGE,
         "-d", "pixel_3",
         "--force"],
        capture_output=False, timeout=120,
    )
    if rc != 0:
        log.error(f"AVD olusturulamadi: {avd_name}")
        sys.exit(1)
    log.info(f"AVD olusturuldu: {avd_name}")


# ── Adim 4: frida-server ──────────────────────────────────

def ensure_frida_binary() -> Path:
    FRIDA_LOCAL.parent.mkdir(parents=True, exist_ok=True)
    if FRIDA_LOCAL.exists() and FRIDA_LOCAL.stat().st_size > 1_000_000:
        log.info(f"frida-server binary mevcut: {FRIDA_LOCAL}")
        return FRIDA_LOCAL

    xz_path = FRIDA_LOCAL.with_suffix(".xz")
    log.info(f"frida-server indiriliyor: {FRIDA_URL}")

    def _progress(count, block, total):
        pct = min(100, int(count * block * 100 / total))
        print(f"\r  {pct}%", end="", flush=True)

    urllib.request.urlretrieve(FRIDA_URL, xz_path, reporthook=_progress)
    print()
    log.info("Arsiv aciliyor...")
    with lzma.open(xz_path, "rb") as f_in, open(FRIDA_LOCAL, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    xz_path.unlink(missing_ok=True)
    log.info(f"frida-server hazir: {FRIDA_LOCAL} ({FRIDA_LOCAL.stat().st_size//1024} KB)")
    return FRIDA_LOCAL


def push_frida(serial: str, binary: Path):
    log.info(f"  [{serial}] frida-server push ediliyor...")
    adb("-s", serial, "push", str(binary), FRIDA_DEVICE, timeout=60)
    adb("-s", serial, "shell", f"su 0 chmod 755 {FRIDA_DEVICE}", timeout=10)
    adb("-s", serial, "shell", f"su 0 nohup {FRIDA_DEVICE} &>/dev/null &", timeout=5)
    time.sleep(4)
    out = adb("-s", serial, "shell", "ps 2>/dev/null | grep frida-server", timeout=5)
    if "frida-server" in out:
        log.info(f"  [{serial}] frida-server calisiyor.")
    else:
        log.warning(f"  [{serial}] frida-server baslatılamadi!")


# ── Adim 5: Emülatörleri baslat + snapshot kaydet ────────

def configure_emulator(serial: str):
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
        adb("-s", serial, "shell", cmd, timeout=6)
    log.info(f"  [{serial}] Emulator ayarlari uygulandı.")


def snapshot_exists(serial: str) -> bool:
    return SNAPSHOT in adb("-s", serial, "emu", "avd", "snapshot", "list")


def setup_emulators(emu: Path, frida_binary: Path) -> list[str]:
    """Tum emulatorleri baslat, yapilandir, snapshot kaydet."""
    # Mevcut online emulatorlere bak
    serials = [s for s in online_serials()
               if adb("-s", s, "shell", "getprop", "sys.boot_completed").strip() == "1"]

    if len(serials) >= NUM_EMULATORS:
        log.info(f"Emulatorler zaten online: {serials[:NUM_EMULATORS]}")
        serials = serials[:NUM_EMULATORS]
    else:
        kill_all()
        time.sleep(3)
        for avd in AVD_NAMES:
            log.info(f"  Emulator baslatiliyor: {avd}")
            subprocess.Popen(
                [str(emu), "-avd", avd, "-no-audio", "-no-window", "-no-snapshot-load"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            time.sleep(4)   # port catismasini onle
        time.sleep(8)
        serials = wait_all_booted(NUM_EMULATORS, timeout=420)
        if len(serials) < NUM_EMULATORS:
            log.error(f"Sadece {len(serials)}/{NUM_EMULATORS} emulator basladi!")
            if not serials:
                sys.exit(1)

    # Her emülatör icin: snapshot var mi kontrol et
    for serial in serials:
        if snapshot_exists(serial):
            log.info(f"  [{serial}] Clean snapshot mevcut — yukleniyor...")
            adb("-s", serial, "emu", "avd", "snapshot", "load", SNAPSHOT, timeout=60)
            time.sleep(6)
            out = adb("-s", serial, "shell", "ps 2>/dev/null | grep frida-server")
            if "frida-server" not in out:
                push_frida(serial, frida_binary)
        else:
            log.info(f"  [{serial}] Snapshot yok — ilk kurulum yapiliyor...")
            configure_emulator(serial)
            push_frida(serial, frida_binary)
            log.info(f"  [{serial}] Snapshot kaydediliyor: '{SNAPSHOT}'")
            adb("-s", serial, "emu", "avd", "snapshot", "save", SNAPSHOT, timeout=120)
            log.info(f"  [{serial}] Snapshot kaydedildi.")

    return serials


# ── Adim 6: Pipeline baslat ───────────────────────────────

def run_pipeline():
    log.info("Pipeline baslatiliyor: run_benign_all.py")
    subprocess.run([sys.executable, "run_benign_all.py"])


# ── Ana akis ──────────────────────────────────────────────

def main():
    log.info("=" * 60)
    log.info(f"  AdaptDroid Benign Analiz — {NUM_EMULATORS} Emülatör Kurulum & Baslatma")
    log.info("=" * 60)

    emu          = check_sdk()
    ensure_system_image()
    avdmanager   = sdk_tool("avdmanager")
    for avd in AVD_NAMES:
        ensure_avd(avd, avdmanager)
    frida_binary = ensure_frida_binary()
    serials      = setup_emulators(emu, frida_binary)

    log.info("")
    log.info(f"Kurulum tamamlandi. Aktif emulatorler: {serials}")
    log.info("Pipeline basliyor...")
    log.info("")
    run_pipeline()


if __name__ == "__main__":
    main()
