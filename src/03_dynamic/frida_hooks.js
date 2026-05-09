// AdaptDroid — Frida Runtime Hook Script
// Malware davranışlarını runtime'da yakalar ve send() ile Python'a iletir.

Java.perform(function () {

    // ── Reflection Hook'ları ──────────────────────────────
    var Class = Java.use("java.lang.Class");
    Class.forName.overload("java.lang.String").implementation = function (name) {
        send({ type: "reflection_forName", class: name });
        return this.forName(name);
    };

    var Method = Java.use("java.lang.reflect.Method");
    Method.invoke.overload("java.lang.Object", "[Ljava.lang.Object;").implementation = function (obj, args) {
        send({ type: "reflection_invoke", method: this.getName() });
        return this.invoke(obj, args);
    };

    // ── Runtime DEX Loading Hook'ları ─────────────────────
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.overload(
        "java.lang.String", "java.lang.String",
        "java.lang.String", "java.lang.ClassLoader"
    ).implementation = function (dexPath, optimizedDir, libraryPath, parent) {
        send({ type: "dex_load", dex_path: dexPath });
        return this.$init(dexPath, optimizedDir, libraryPath, parent);
    };

    try {
        var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        InMemoryDexClassLoader.$init.overload(
            "java.nio.ByteBuffer", "java.lang.ClassLoader"
        ).implementation = function (buf, parent) {
            send({ type: "dex_load_inmemory" });
            return this.$init(buf, parent);
        };
    } catch (e) { /* API < 26 */ }

    // ── Crypto Hook'ları ──────────────────────────────────
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload("java.lang.String").implementation = function (algo) {
        send({ type: "crypto_cipher", algorithm: algo });
        return this.getInstance(algo);
    };

    var MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.getInstance.overload("java.lang.String").implementation = function (algo) {
        send({ type: "crypto_digest", algorithm: algo });
        return this.getInstance(algo);
    };

    try {
        var Base64 = Java.use("android.util.Base64");
        Base64.encodeToString.overload("[B", "int").implementation = function (input, flags) {
            send({ type: "base64_encode" });
            return this.encodeToString(input, flags);
        };
    } catch (e) { }

    // ── Network Hook'ları ─────────────────────────────────
    var Socket = Java.use("java.net.Socket");
    Socket.$init.overload("java.lang.String", "int").implementation = function (host, port) {
        send({ type: "network_socket", host: host, port: port });
        return this.$init(host, port);
    };

    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function () {
        send({ type: "network_http", url: this.toString() });
        return this.openConnection();
    };

    // ── Runtime Execution Hook'ları ───────────────────────
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
        send({ type: "runtime_exec", command: cmd });
        return this.exec(cmd);
    };
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds) {
        send({ type: "runtime_exec", command: cmds.join(" ") });
        return this.exec(cmds);
    };

    // ── File I/O Hook'ları ────────────────────────────────
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.$init.overload("java.lang.String").implementation = function (path) {
        send({ type: "file_write", path: path });
        return this.$init(path);
    };

    try {
        var ZipFile = Java.use("java.util.zip.ZipFile");
        ZipFile.$init.overload("java.lang.String").implementation = function (path) {
            send({ type: "zip_open", path: path });
            return this.$init(path);
        };
    } catch (e) { }

    // ── SMS Hook'ları ─────────────────────────────────────
    try {
        var SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.implementation = function (dest, sc, text, sent, delivery) {
            send({ type: "sms_send", destination: dest });
            return this.sendTextMessage(dest, sc, text, sent, delivery);
        };
    } catch (e) { }

    // ── Telephony / Cihaz Kimliği Hook'ları ──────────────
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        try {
            TelephonyManager.getDeviceId.overload().implementation = function () {
                send({ type: "telephony_query", field: "deviceId" });
                return this.getDeviceId();
            };
        } catch (e) { }
        try {
            TelephonyManager.getImei.overload().implementation = function () {
                send({ type: "telephony_query", field: "imei" });
                return this.getImei();
            };
        } catch (e) { }
        try {
            TelephonyManager.getSubscriberId.overload().implementation = function () {
                send({ type: "telephony_query", field: "subscriberId" });
                return this.getSubscriberId();
            };
        } catch (e) { }
        try {
            TelephonyManager.getSimSerialNumber.overload().implementation = function () {
                send({ type: "telephony_query", field: "simSerial" });
                return this.getSimSerialNumber();
            };
        } catch (e) { }
    } catch (e) { }

    // ── Clipboard Hook'ları ───────────────────────────────
    try {
        var ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.getPrimaryClip.implementation = function () {
            send({ type: "clipboard_read" });
            return this.getPrimaryClip();
        };
        ClipboardManager.setPrimaryClip.implementation = function (clip) {
            send({ type: "clipboard_write" });
            return this.setPrimaryClip(clip);
        };
    } catch (e) { }

    // ── Camera Hook'ları ──────────────────────────────────
    try {
        var Camera = Java.use("android.hardware.Camera");
        Camera.open.overload().implementation = function () {
            send({ type: "camera_open" });
            return this.open();
        };
        Camera.open.overload("int").implementation = function (id) {
            send({ type: "camera_open" });
            return this.open(id);
        };
    } catch (e) { }

    // ── Location Hook'ları ────────────────────────────────
    try {
        var LocationManager = Java.use("android.location.LocationManager");
        LocationManager.getLastKnownLocation.overload("java.lang.String").implementation = function (provider) {
            send({ type: "location_request", provider: provider });
            return this.getLastKnownLocation(provider);
        };
    } catch (e) { }

    // ── ContentResolver / Rehber Hook'ları ───────────────
    try {
        var ContentResolver = Java.use("android.content.ContentResolver");
        ContentResolver.query.overload(
            "android.net.Uri",
            "[Ljava.lang.String;",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String"
        ).implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
            var uriStr = uri ? uri.toString() : "";
            if (uriStr.indexOf("contacts") !== -1 || uriStr.indexOf("phone") !== -1) {
                send({ type: "contact_query", uri: uriStr });
            } else if (uriStr.indexOf("sms") !== -1 || uriStr.indexOf("mms") !== -1) {
                send({ type: "sms_read", uri: uriStr });
            } else if (uriStr.indexOf("call_log") !== -1) {
                send({ type: "call_log_read", uri: uriStr });
            }
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
    } catch (e) { }

    // ── SharedPreferences Hook'ları ───────────────────────
    try {
        var SharedPreferencesEditor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        SharedPreferencesEditor.commit.implementation = function () {
            send({ type: "shared_prefs_write" });
            return this.commit();
        };
    } catch (e) { }

    // ── Broadcast Hook'ları ───────────────────────────────
    try {
        var Context = Java.use("android.app.ContextImpl");
        Context.sendBroadcast.overload("android.content.Intent").implementation = function (intent) {
            var action = intent.getAction ? intent.getAction() : "";
            send({ type: "broadcast_send", action: action });
            return this.sendBroadcast(intent);
        };
    } catch (e) { }

    // ── Alarm / Persistence Hook'ları ─────────────────────
    try {
        var AlarmManager = Java.use("android.app.AlarmManager");
        AlarmManager.set.overload("int", "long", "android.app.PendingIntent").implementation = function (type, triggerAtMillis, operation) {
            send({ type: "alarm_set" });
            return this.set(type, triggerAtMillis, operation);
        };
    } catch (e) { }

    // ── Native Library Hook'ları ──────────────────────────
    try {
        var System = Java.use("java.lang.System");
        System.loadLibrary.implementation = function (libname) {
            send({ type: "native_lib_load", lib: libname });
            return this.loadLibrary(libname);
        };
        System.load.implementation = function (filename) {
            send({ type: "native_lib_load", lib: filename });
            return this.load(filename);
        };
    } catch (e) { }

    // ── JSON Hook'ları (C2 iletişimi belirtisi) ───────────
    try {
        var JSONObject = Java.use("org.json.JSONObject");
        JSONObject.$init.overload("java.lang.String").implementation = function (src) {
            send({ type: "json_parse" });
            return this.$init(src);
        };
    } catch (e) { }

    // ── DevicePolicyManager Hook'ları ─────────────────────
    try {
        var DevicePolicyManager = Java.use("android.app.admin.DevicePolicyManager");
        DevicePolicyManager.isAdminActive.implementation = function (who) {
            send({ type: "device_admin_check" });
            return this.isAdminActive(who);
        };
    } catch (e) { }

    // ── PackageManager Hook'ları ──────────────────────────
    try {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getInstalledPackages.overload("int").implementation = function (flags) {
            send({ type: "package_enum" });
            return this.getInstalledPackages(flags);
        };
    } catch (e) { }

});
