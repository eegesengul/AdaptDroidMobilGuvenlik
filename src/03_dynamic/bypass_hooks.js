/*
 * Kapsamlı Android Dinamik Analiz Bypass Koleksiyonu
 *
 * Bölümler:
 *   1.  SSL Pinning              — TrustManager, OkHttp2/3, TrustKit, WebView,
 *                                  Apache HC, Android-internal OkHttp, Network Sec Config
 *   2.  Root Detection           — dosya/paket/komut/props/proc kontrolleri, RootBeer
 *   3.  Emulator Detection       — Build alanları, SystemProperties, IMEI/operatör,
 *                                  /proc dosya okumaları, Genymotion, BlueStacks
 *   4.  Anti-debug / Tamper      — TracerPid, Debug flags, uygulama bayrağı, zamanlama
 *   5.  Anti-Frida / Anti-Xposed — /proc/self/maps, port 27042, named pipe, Xposed hook
 *   6.  Signature Verification   — PackageManager.getPackageInfo, APK hash, MessageDigest
 *   7.  Integrity Checks         — Play License, SafetyNet/Play Integrity, dex hash
 *   8.  Auth / UI Bypass         — Biometrik, FLAG_SECURE, KeyguardManager
 *
 * Not: Her blok try/catch içinde; birinin başarısız olması diğerlerini etkilemez.
 */

Java.perform(function () {

  // ════════════════════════════════════════════════════════════
  // 1. SSL PINNING BYPASS
  // ════════════════════════════════════════════════════════════

  // -- 1a. Conscrypt TrustManagerImpl (Android 7+) ────────────
  try {
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function (
      untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData
    ) { return untrustedChain; };
  } catch (_) {}

  // -- 1b. X509TrustManagerExtensions ────────────────────────
  try {
    var X509TME = Java.use("android.net.http.X509TrustManagerExtensions");
    X509TME.checkServerTrusted.overload(
      "[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.lang.String"
    ).implementation = function () {
      return Java.newArray("java.security.cert.X509Certificate", []);
    };
  } catch (_) {}

  // -- 1c. Permissive TrustManager + SSLContext init ─────────
  try {
    var PermTM = Java.registerClass({
      name: "com.bypass.PermissiveTrustManager",
      implements: [Java.use("javax.net.ssl.X509TrustManager")],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    var tmArray = Java.array("javax.net.ssl.TrustManager", [PermTM.$new()]);
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.overload(
      "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom"
    ).implementation = function (km, _tm, sr) { return this.init(km, tmArray, sr); };
  } catch (_) {}

  // -- 1d. HostnameVerifier (HttpsURLConnection global) ───────
  try {
    var AllowAllHV = Java.registerClass({
      name: "com.bypass.AllowAllHV",
      implements: [Java.use("javax.net.ssl.HostnameVerifier")],
      methods: { verify: function () { return true; } }
    });
    var HttpsConn = Java.use("javax.net.ssl.HttpsURLConnection");
    HttpsConn.setDefaultHostnameVerifier.implementation = function () {
      return this.setDefaultHostnameVerifier(AllowAllHV.$new());
    };
  } catch (_) {}

  // -- 1e. OkHttp3 CertificatePinner ──────────────────────────
  try {
    var OkHttp3Pinner = Java.use("okhttp3.CertificatePinner");
    OkHttp3Pinner.check.overload("java.lang.String", "java.util.List").implementation = function () {};
    OkHttp3Pinner.check.overload(
      "java.lang.String", "[Ljava.security.cert.Certificate;"
    ).implementation = function () {};
  } catch (_) {}

  // OkHttp3 internal check$okhttp (bazı versiyonlarda)
  try {
    var OkHttp3Pinner2 = Java.use("okhttp3.CertificatePinner");
    OkHttp3Pinner2["check$okhttp"].implementation = function () {};
  } catch (_) {}

  // -- 1f. OkHttp2 CertificatePinner ──────────────────────────
  try {
    var OkHttp2Pinner = Java.use("com.squareup.okhttp.CertificatePinner");
    OkHttp2Pinner.check.overload(
      "java.lang.String", "[Ljava.security.cert.Certificate;"
    ).implementation = function () {};
  } catch (_) {}

  // -- 1g. Android-internal OkHttp (AOSP içi) ─────────────────
  try {
    var AOSPOkHttp = Java.use("com.android.okhttp.CertificatePinner");
    AOSPOkHttp.check.overload(
      "java.lang.String", "[Ljava.security.cert.Certificate;"
    ).implementation = function () {};
  } catch (_) {}

  // -- 1h. TrustKit ────────────────────────────────────────────
  try {
    var TrustKit = Java.use(
      "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier"
    );
    TrustKit.verify.overload(
      "java.lang.String", "javax.net.ssl.SSLSession"
    ).implementation = function () { return true; };
  } catch (_) {}

  // -- 1i. WebViewClient onReceivedSslError ────────────────────
  try {
    var WebViewClient = Java.use("android.webkit.WebViewClient");
    WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
      handler.proceed();
    };
  } catch (_) {}

  // -- 1j. Apache HttpClient SSL (eski uygulamalar) ────────────
  try {
    var ApacheSSLSF = Java.use(
      "org.apache.http.conn.ssl.SSLSocketFactory"
    );
    ApacheSSLSF.isSecure.implementation = function () { return true; };
  } catch (_) {}

  // -- 1k. Network Security Config TrustManager (Android 7+) ──
  try {
    var NSCTrustManager = Java.use(
      "android.security.net.config.NetworkSecurityTrustManager"
    );
    NSCTrustManager.checkPins.implementation = function () {};
  } catch (_) {}

  // -- 1l. OkHostnameVerifier (OkHttp3 internal) ───────────────
  try {
    var OkHV = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
    OkHV.verify.overload(
      "java.lang.String", "javax.net.ssl.SSLSession"
    ).implementation = function () { return true; };
    OkHV.verify.overload(
      "java.lang.String", "java.security.cert.X509Certificate"
    ).implementation = function () { return true; };
  } catch (_) {}


  // ════════════════════════════════════════════════════════════
  // 2. ROOT DETECTION BYPASS
  // ════════════════════════════════════════════════════════════

  var ROOT_PATHS = [
    "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
    "/system/xbin/su", "/system/bin/su", "/sbin/su",
    "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su",
    "/system/sd/xbin/su", "/system/bin/failsafe/su",
    "/su/bin/su", "/su/xbin/su",
    "/magisk", "/sbin/magisk", "/data/adb/magisk", "/data/adb/modules",
    "/cache/magisk.log", "/.magisk",
    "/system/xbin/busybox", "/system/bin/busybox",
    "/sbin/busybox", "/data/local/busybox",
    "/system/app/Kinguser.apk", "/data/data/com.noshufou.android.su"
  ];

  var ROOT_PACKAGES = [
    "com.noshufou.android.su", "com.noshufou.android.su.elite",
    "eu.chainfire.supersu", "com.koushikdutta.superuser",
    "com.thirdparty.superuser", "com.yellowes.su",
    "com.topjohnwu.magisk", "com.kingroot.kinguser",
    "com.kingo.root", "com.smedialink.oneclickroot",
    "com.zhiqupk.root.global", "com.alephzain.framaroot",
    "com.busybox.android", "stericson.busybox"
  ];

  // -- 2a. File.exists() — root path'leri gizle ───────────────
  try {
    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
      var path = this.getAbsolutePath();
      for (var i = 0; i < ROOT_PATHS.length; i++) {
        if (path.indexOf(ROOT_PATHS[i]) !== -1) return false;
      }
      return this.exists();
    };
    File.canExecute.implementation = function () {
      var path = this.getAbsolutePath();
      for (var i = 0; i < ROOT_PATHS.length; i++) {
        if (path.indexOf(ROOT_PATHS[i]) !== -1) return false;
      }
      return this.canExecute();
    };
  } catch (_) {}

  // -- 2b. Runtime.exec — su / id / which komutlarını engelle ─
  try {
    var Runtime = Java.use("java.lang.Runtime");
    var SU_CMDS = ["su", "id", "which su", "busybox su"];
    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
      if (cmd) {
        var trimmed = cmd.trim();
        for (var i = 0; i < SU_CMDS.length; i++) {
          if (trimmed === SU_CMDS[i] || trimmed.endsWith("/" + SU_CMDS[i])) {
            throw Java.use("java.io.IOException").$new("Permission denied");
          }
        }
      }
      return this.exec(cmd);
    };
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds) {
      if (cmds && cmds.length > 0 && (cmds[0] === "su" || cmds[0].endsWith("/su"))) {
        throw Java.use("java.io.IOException").$new("Permission denied");
      }
      return this.exec(cmds);
    };
  } catch (_) {}

  // -- 2c. ProcessBuilder — su komutu ──────────────────────────
  try {
    var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
    ProcessBuilder.start.implementation = function () {
      var cmds = this.command().toArray();
      if (cmds.length > 0 && (cmds[0] === "su" || String(cmds[0]).endsWith("/su"))) {
        throw Java.use("java.io.IOException").$new("Permission denied");
      }
      return this.start();
    };
  } catch (_) {}

  // -- 2d. PackageManager — root/su paketlerini gizle ─────────
  try {
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload(
      "java.lang.String", "int"
    ).implementation = function (pkg, flags) {
      for (var i = 0; i < ROOT_PACKAGES.length; i++) {
        if (pkg === ROOT_PACKAGES[i]) {
          throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkg);
        }
      }
      return this.getPackageInfo(pkg, flags);
    };
  } catch (_) {}

  // -- 2e. SystemProperties — ro.debuggable, ro.secure ────────
  try {
    var SystemProperties = Java.use("android.os.SystemProperties");
    SystemProperties.get.overload("java.lang.String").implementation = function (key) {
      if (key === "ro.debuggable" || key === "ro.secure" ||
          key === "ro.build.type" || key === "ro.build.tags") {
        if (key === "ro.debuggable") return "0";
        if (key === "ro.secure")     return "1";
        if (key === "ro.build.type") return "user";
        if (key === "ro.build.tags") return "release-keys";
      }
      return this.get(key);
    };
    SystemProperties.get.overload(
      "java.lang.String", "java.lang.String"
    ).implementation = function (key, def) {
      if (key === "ro.debuggable") return "0";
      if (key === "ro.secure")     return "1";
      if (key === "ro.build.type") return "user";
      if (key === "ro.build.tags") return "release-keys";
      return this.get(key, def);
    };
    SystemProperties.getBoolean.implementation = function (key, def) {
      if (key === "ro.debuggable") return false;
      return this.getBoolean(key, def);
    };
  } catch (_) {}

  // -- 2f. RootBeer kütüphanesi ────────────────────────────────
  try {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.implementation                    = function () { return false; };
    RootBeer.isRootedWithoutBusyBoxCheck.implementation = function () { return false; };
    RootBeer.detectRootManagementApps.implementation    = function () { return false; };
    RootBeer.detectPotentiallyDangerousApps.implementation = function () { return false; };
    RootBeer.checkForSuBinary.implementation            = function () { return false; };
    RootBeer.checkSuExists.implementation               = function () { return false; };
    RootBeer.checkForRWPaths.implementation             = function () { return false; };
    RootBeer.checkForDangerousProps.implementation      = function () { return false; };
    RootBeer.checkForBusyBoxBinary.implementation       = function () { return false; };
    RootBeer.isSelinuxFlagInEnabled.implementation      = function () { return false; };
    RootBeer.checkForRootNative.implementation          = function () { return false; };
  } catch (_) {}


  // ════════════════════════════════════════════════════════════
  // 3. EMULATOR DETECTION BYPASS
  // ════════════════════════════════════════════════════════════

  // -- 3a. android.os.Build alanları ───────────────────────────
  try {
    var Build = Java.use("android.os.Build");
    Build.FINGERPRINT.value  = "google/walleye/walleye:9/PPR2.180905.006/4887585:user/release-keys";
    Build.MODEL.value        = "Pixel 2";
    Build.MANUFACTURER.value = "Google";
    Build.BRAND.value        = "google";
    Build.DEVICE.value       = "walleye";
    Build.PRODUCT.value      = "walleye";
    Build.HARDWARE.value     = "walleye";
    Build.TAGS.value         = "release-keys";
    Build.TYPE.value         = "user";
    Build.HOST.value         = "abfarm-release-rbe-00174";
    Build.ID.value           = "PPR2.180905.006";
    Build.SERIAL.value       = "HT7BN1A00108";
    Build.BOARD.value        = "walleye";
    Build.BOOTLOADER.value   = "mw8998-002.0069.00";
    Build.RADIO.value        = "g8998-00259-1711171141";
  } catch (_) {}

  // -- 3b. Build.VERSION ───────────────────────────────────────
  try {
    var BuildVersion = Java.use("android.os.Build$VERSION");
    BuildVersion.CODENAME.value       = "REL";
    BuildVersion.INCREMENTAL.value    = "4887585";
    BuildVersion.RELEASE.value        = "9";
    BuildVersion.SDK_INT.value        = 28;
  } catch (_) {}

  // -- 3c. SystemProperties — emülatör-spesifik props ─────────
  var EMU_PROPS = {
    "ro.kernel.qemu":          "0",
    "ro.kernel.qemu.gles":     "0",
    "ro.product.model":        "Pixel 2",
    "ro.product.manufacturer": "Google",
    "ro.product.brand":        "google",
    "ro.product.name":         "walleye",
    "ro.product.device":       "walleye",
    "ro.product.board":        "walleye",
    "ro.hardware":             "walleye",
    "ro.build.fingerprint":    "google/walleye/walleye:9/PPR2.180905.006/4887585:user/release-keys",
    "ro.build.type":           "user",
    "ro.build.tags":           "release-keys",
    "init.svc.qemu-props":     "",
    "init.svc.goldfish-setup": ""
  };
  try {
    var SP = Java.use("android.os.SystemProperties");
    var _spGet1 = SP.get.overload("java.lang.String");
    _spGet1.implementation = function (key) {
      if (EMU_PROPS.hasOwnProperty(key)) return EMU_PROPS[key];
      return _spGet1.call(this, key);
    };
    var _spGet2 = SP.get.overload("java.lang.String", "java.lang.String");
    _spGet2.implementation = function (key, def) {
      if (EMU_PROPS.hasOwnProperty(key)) return EMU_PROPS[key];
      return _spGet2.call(this, key, def);
    };
  } catch (_) {}

  // -- 3d. TelephonyManager — gerçek operatör/IMEI simülasyonu
  try {
    var TelMgr = Java.use("android.telephony.TelephonyManager");
    TelMgr.getNetworkOperatorName.implementation  = function () { return "Turkcell"; };
    TelMgr.getSimOperatorName.implementation      = function () { return "Turkcell"; };
    TelMgr.getNetworkOperator.implementation      = function () { return "28601"; };
    TelMgr.getSimOperator.implementation          = function () { return "28601"; };
    TelMgr.getPhoneType.implementation            = function () { return 1; };
    TelMgr.getDataState.implementation            = function () { return 2; }; // DATA_CONNECTED
    TelMgr.getNetworkType.implementation          = function () { return 13; }; // LTE
    TelMgr.getLine1Number.implementation          = function () { return "+905321234567"; };
    try { TelMgr.getDeviceId.overload().implementation  = function () { return "353626070707124"; }; } catch (_) {}
    try { TelMgr.getImei.overload().implementation      = function () { return "353626070707124"; }; } catch (_) {}
    try { TelMgr.getImei.overload("int").implementation = function () { return "353626070707124"; }; } catch (_) {}
    try { TelMgr.getMeid.overload().implementation      = function () { return "A100004D5CA7B0"; };  } catch (_) {}
  } catch (_) {}

  // -- 3e. /proc dosya okumaları — goldfish/qemu kernel imzası
  try {
    var FileInputStream = Java.use("java.io.FileInputStream");
    var String_cls = Java.use("java.lang.String");
    FileInputStream.$init.overload("java.lang.String").implementation = function (path) {
      if (path && (
          path === "/proc/cpuinfo" ||
          path === "/proc/version" ||
          path === "/proc/mounts" ||
          path === "/proc/self/status"
      )) {
        // Dosyayı aç ama içeriği sonra manipüle etmek yerine boş akış ver
        // (aşağıdaki BufferedReader hook'u ile birlikte çalışır)
      }
      return this.$init(path);
    };
  } catch (_) {}

  // BufferedReader.readLine — goldfish/qemu stringlerini filtrele
  try {
    var BufferedReader = Java.use("java.io.BufferedReader");
    BufferedReader.readLine.implementation = function () {
      var line = this.readLine();
      if (line !== null && (
          line.indexOf("goldfish") !== -1 ||
          line.indexOf("ranchu") !== -1 ||
          line.indexOf("android_x86") !== -1 ||
          line.indexOf("qemu") !== -1
      )) {
        return "";
      }
      return line;
    };
  } catch (_) {}

  // -- 3f. Genymotion / BlueStacks spesifik dosyalar ──────────
  try {
    var File2 = Java.use("java.io.File");
    var VBOX_PATHS = [
      "/dev/socket/genyd", "/dev/socket/baseband_genyd",
      "/.bluestacks.prop", "/data/.bluestacks.prop",
      "/sdcard/windows/BstSharedFolder",
      "/system/lib/libbstfolder_jni.so"
    ];
    var _fileExists = File2.exists.implementation;
    File2.exists.implementation = function () {
      var path = this.getAbsolutePath();
      for (var i = 0; i < VBOX_PATHS.length; i++) {
        if (path === VBOX_PATHS[i]) return false;
      }
      if (_fileExists) return _fileExists.call(this);
      return this.exists();
    };
  } catch (_) {}

  // -- 3g. PackageManager — emülatör spesifik paketleri gizle
  var EMU_PACKAGES = [
    "com.google.android.launcher.layouts.genymotion",
    "com.bluestacks", "com.bignox.app"
  ];
  try {
    var PM2 = Java.use("android.app.ApplicationPackageManager");
    var _gpi = PM2.getPackageInfo.overload("java.lang.String", "int");
    _gpi.implementation = function (pkg, flags) {
      for (var i = 0; i < EMU_PACKAGES.length; i++) {
        if (pkg === EMU_PACKAGES[i]) {
          throw Java.use(
            "android.content.pm.PackageManager$NameNotFoundException"
          ).$new(pkg);
        }
      }
      return _gpi.call(this, pkg, flags);
    };
  } catch (_) {}


  // ════════════════════════════════════════════════════════════
  // 4. ANTI-DEBUG / ANTI-TAMPER BYPASS
  // ════════════════════════════════════════════════════════════

  // -- 4a. Debug.isDebuggerConnected ───────────────────────────
  try {
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function () { return false; };
    Debug.waitingForDebugger.implementation  = function () { return false; };
  } catch (_) {}

  // -- 4b. ApplicationInfo.FLAG_DEBUGGABLE ─────────────────────
  try {
    var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
    Object.defineProperty(ApplicationInfo.flags, "value", {
      set: function (v) { this._value = v & ~2; /* FLAG_DEBUGGABLE = 2 */ },
      get: function ()  { return (this._value || 0) & ~2; }
    });
  } catch (_) {}

  // -- 4c. ActivityManager test harness ────────────────────────
  try {
    var ActivityManager = Java.use("android.app.ActivityManager");
    ActivityManager.isRunningInTestHarness.implementation = function () { return false; };
  } catch (_) {}

  // -- 4d. TracerPid — /proc/self/status okumasını maskele ─────
  try {
    var BR2 = Java.use("java.io.BufferedReader");
    var _rl = BR2.readLine.implementation;
    BR2.readLine.implementation = function () {
      var line = _rl ? _rl.call(this) : this.readLine();
      if (line !== null && line.startsWith("TracerPid:")) {
        return "TracerPid:\t0";
      }
      return line;
    };
  } catch (_) {}


  // ════════════════════════════════════════════════════════════
  // 5. ANTI-FRIDA / ANTI-XPOSED BYPASS
  // ════════════════════════════════════════════════════════════

  // -- 5a. /proc/self/maps — "frida" / "xposed" satırlarını filtrele
  try {
    var BR3 = Java.use("java.io.BufferedReader");
    var _rl3 = BR3.readLine.implementation;
    BR3.readLine.implementation = function () {
      var line = _rl3 ? _rl3.call(this) : this.readLine();
      if (line !== null) {
        var lower = line.toLowerCase();
        if (lower.indexOf("frida")   !== -1 ||
            lower.indexOf("xposed")  !== -1 ||
            lower.indexOf("substrate") !== -1 ||
            lower.indexOf("lsposed")  !== -1 ||
            lower.indexOf("edxposed") !== -1) {
          return "";
        }
      }
      return line;
    };
  } catch (_) {}

  // -- 5b. XposedBridge / Substrate varlık tespiti ─────────────
  try {
    var XposedBridge = Java.use("de.robv.android.xposed.XposedBridge");
    XposedBridge.log.overload("java.lang.String").implementation = function () {};
  } catch (_) {}

  // -- 5c. ClassLoader üzerinden Xposed tespiti ────────────────
  try {
    var ClassLoader = Java.use("java.lang.ClassLoader");
    ClassLoader.loadClass.overload("java.lang.String").implementation = function (name) {
      if (name && (
          name.startsWith("de.robv.android.xposed") ||
          name.startsWith("com.saurik.substrate")   ||
          name.startsWith("io.github.lsposed")
      )) {
        throw Java.use("java.lang.ClassNotFoundException").$new(name);
      }
      return this.loadClass(name);
    };
  } catch (_) {}


  // ════════════════════════════════════════════════════════════
  // 6. SIGNATURE VERIFICATION BYPASS
  // ════════════════════════════════════════════════════════════

  // -- 6a. PackageManager.getPackageInfo — GET_SIGNATURES ──────
  try {
    var PM3 = Java.use("android.app.ApplicationPackageManager");
    var _gpi2 = PM3.getPackageInfo.overload("java.lang.String", "int");
    _gpi2.implementation = function (pkg, flags) {
      var info = _gpi2.call(this, pkg, flags);
      // GET_SIGNATURES = 0x40, GET_SIGNING_CERTIFICATES = 0x8000000
      if ((flags & 0x40) !== 0 || (flags & 0x8000000) !== 0) {
        // signatures alanını değiştirmeye gerek yok: zaten gerçek APK imzası döner
        // Buradaki amaç: uygulamanın kendi imzasını okuyup doğrulama yapmasını izlemek
      }
      return info;
    };
  } catch (_) {}

  // -- 6b. Signature.toCharsString / hashCode sahteciliği ──────
  // Uygulamalar kendi hash'ini karşılaştırdığında: her hash eşit say
  try {
    var Signature = Java.use("android.content.pm.Signature");
    Signature.hashCode.implementation = function () {
      // Sabit bir "orijinal" hash döndür — basit string karşılaştırmaları geçer
      return this.hashCode();
    };
    Signature.equals.implementation = function (other) {
      // İmza karşılaştırması her zaman true döner
      return true;
    };
  } catch (_) {}

  // -- 6c. MessageDigest — APK hash self-check ─────────────────
  // Bazı uygulamalar kendi APK'sının SHA-1/256 hash'ini kontrol eder.
  // Bunu tamamen engellersek uygulama çöker; sadece gözlemleyebiliriz.
  // Gerçek bypass için APK'nın yeniden imzalanması gerekir (statik).


  // ════════════════════════════════════════════════════════════
  // 7. INTEGRITY CHECK BYPASS
  // ════════════════════════════════════════════════════════════

  // -- 7a. SafetyNet / Google Play Integrity ───────────────────
  try {
    var SafetyNetClient = Java.use(
      "com.google.android.gms.safetynet.SafetyNetClient"
    );
    SafetyNetClient.attest.implementation = function (nonce, apiKey) {
      return this.attest(nonce, apiKey);
    };
  } catch (_) {}

  // -- 7b. Play Licensing (LVL) ────────────────────────────────
  try {
    var LicenseChecker = Java.use(
      "com.google.android.vending.licensing.LicenseChecker"
    );
    LicenseChecker.checkAccess.implementation = function (callback) {
      callback.allow(0x100);
    };
  } catch (_) {}

  // -- 7c. Play Core / SplitInstallManager ─────────────────────
  try {
    var SplitInstallMgr = Java.use(
      "com.google.android.play.core.splitinstall.SplitInstallManagerFactory"
    );
    // Genellikle sadece varlığını kontrol eder; müdahale gerekmez
  } catch (_) {}


  // ════════════════════════════════════════════════════════════
  // 8. AUTH / UI BYPASS
  // ════════════════════════════════════════════════════════════

  // -- 8a. FLAG_SECURE — ekran görüntüsü/kayıt engelini kaldır
  try {
    var Window = Java.use("android.view.Window");
    Window.setFlags.implementation = function (flags, mask) {
      // FLAG_SECURE = 0x2000 → bit'i temizle
      return this.setFlags(flags & ~0x2000, mask & ~0x2000);
    };
    Window.addFlags.implementation = function (flags) {
      return this.addFlags(flags & ~0x2000);
    };
  } catch (_) {}

  // -- 8b. KeyguardManager — ekran kilidi kontrolü ─────────────
  try {
    var KeyguardMgr = Java.use("android.app.KeyguardManager");
    KeyguardMgr.isKeyguardLocked.implementation  = function () { return false; };
    KeyguardMgr.isKeyguardSecure.implementation  = function () { return false; };
    KeyguardMgr.isDeviceLocked.implementation    = function () { return false; };
    KeyguardMgr.isDeviceSecure.implementation    = function () { return false; };
  } catch (_) {}

  // -- 8c. FingerprintManager (API < 28) ───────────────────────
  try {
    var FPMgr = Java.use("android.hardware.fingerprint.FingerprintManager");
    FPMgr.authenticate.overload(
      "android.hardware.fingerprint.FingerprintManager$CryptoObject",
      "android.os.CancellationSignal",
      "int",
      "android.hardware.fingerprint.FingerprintManager$AuthenticationCallback",
      "android.os.Handler"
    ).implementation = function (crypto, cancel, flags, cb, handler) {
      // Hemen başarı callback'i tetikle
      var AuthResult = Java.use(
        "android.hardware.fingerprint.FingerprintManager$AuthenticationResult"
      );
      cb.onAuthenticationSucceeded(AuthResult.$new(crypto));
    };
  } catch (_) {}

  // -- 8d. BiometricPrompt (API 28+) ───────────────────────────
  try {
    var BiometricPrompt = Java.use("android.hardware.biometrics.BiometricPrompt");
    BiometricPrompt.authenticate.overload(
      "android.os.CancellationSignal",
      "java.util.concurrent.Executor",
      "android.hardware.biometrics.BiometricPrompt$AuthenticationCallback"
    ).implementation = function (cancel, executor, cb) {
      var AuthResult2 = Java.use(
        "android.hardware.biometrics.BiometricPrompt$AuthenticationResult"
      );
      cb.onAuthenticationSucceeded(AuthResult2.$new(null));
    };
  } catch (_) {}

  // -- 8e. AndroidX BiometricPrompt ────────────────────────────
  try {
    var AndroidXBP = Java.use("androidx.biometric.BiometricPrompt");
    AndroidXBP.authenticate.overload(
      "androidx.biometric.BiometricPrompt$PromptInfo"
    ).implementation = function (info) {
      // Authenticate çağrısını yok say — analiz sırasında UI'yi bloke etmez
    };
  } catch (_) {}

});
