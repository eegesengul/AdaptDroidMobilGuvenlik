import Java from "frida-java-bridge";

// Test - mesaj kanalı çalışıyor mu?
send({ type: "script_started" });

Java.perform(() => {
    send({ type: "java_perform_ok" });

    // Reflection
    const Class = Java.use("java.lang.Class");
    Class.forName.overload("java.lang.String").implementation = function (name: string) {
        send({ type: "reflection_forName", class: name });
        return this.forName(name);
    };

    // DEX Loading
    const DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.overload(
        "java.lang.String", "java.lang.String",
        "java.lang.String", "java.lang.ClassLoader"
    ).implementation = function (dexPath: string, optimizedDir: string, libraryPath: string, parent: any) {
        send({ type: "dex_load", dex_path: dexPath });
        return this.$init(dexPath, optimizedDir, libraryPath, parent);
    };

    try {
        const InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        InMemoryDexClassLoader.$init.overload(
            "java.nio.ByteBuffer", "java.lang.ClassLoader"
        ).implementation = function (buf: any, parent: any) {
            send({ type: "dex_load_inmemory" });
            return this.$init(buf, parent);
        };
    } catch (_e) {}

    // Crypto
    const Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload("java.lang.String").implementation = function (algo: string) {
        send({ type: "crypto_cipher", algorithm: algo });
        return this.getInstance(algo);
    };

    const MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.getInstance.overload("java.lang.String").implementation = function (algo: string) {
        send({ type: "crypto_digest", algorithm: algo });
        return this.getInstance(algo);
    };

    try {
        const Base64 = Java.use("android.util.Base64");
        Base64.encodeToString.overload("[B", "int").implementation = function (input: any, flags: number) {
            send({ type: "base64_encode" });
            return this.encodeToString(input, flags);
        };
    } catch (_e) {}

    // Network
    const Socket = Java.use("java.net.Socket");
    Socket.$init.overload("java.lang.String", "int").implementation = function (host: string, port: number) {
        send({ type: "network_socket", host, port });
        return this.$init(host, port);
    };

    const URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function () {
        send({ type: "network_http", url: this.toString() });
        return this.openConnection();
    };

    // Runtime exec
    const Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function (cmd: string) {
        send({ type: "runtime_exec", command: cmd });
        return this.exec(cmd);
    };
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds: string[]) {
        send({ type: "runtime_exec", command: cmds.join(" ") });
        return this.exec(cmds);
    };

    // File I/O
    const FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.$init.overload("java.lang.String").implementation = function (path: string) {
        send({ type: "file_write", path });
        return this.$init(path);
    };

    try {
        const ZipFile = Java.use("java.util.zip.ZipFile");
        ZipFile.$init.overload("java.lang.String").implementation = function (path: string) {
            send({ type: "zip_open", path });
            return this.$init(path);
        };
    } catch (_e) {}

    // SMS
    try {
        const SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.implementation = function (dest: string, sc: any, text: any, sent: any, delivery: any) {
            send({ type: "sms_send", destination: dest });
            return this.sendTextMessage(dest, sc, text, sent, delivery);
        };
    } catch (_e) {}

    // Telephony
    try {
        const TelephonyManager = Java.use("android.telephony.TelephonyManager");
        try {
            TelephonyManager.getDeviceId.overload().implementation = function () {
                send({ type: "telephony_query", field: "deviceId" });
                return this.getDeviceId();
            };
        } catch (_e) {}
        try {
            TelephonyManager.getImei.overload().implementation = function () {
                send({ type: "telephony_query", field: "imei" });
                return this.getImei();
            };
        } catch (_e) {}
        try {
            TelephonyManager.getSubscriberId.overload().implementation = function () {
                send({ type: "telephony_query", field: "subscriberId" });
                return this.getSubscriberId();
            };
        } catch (_e) {}
    } catch (_e) {}

    // Clipboard
    try {
        const ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.getPrimaryClip.implementation = function () {
            send({ type: "clipboard_read" });
            return this.getPrimaryClip();
        };
        ClipboardManager.setPrimaryClip.implementation = function (clip: any) {
            send({ type: "clipboard_write" });
            return this.setPrimaryClip(clip);
        };
    } catch (_e) {}

    // ContentResolver (contacts/sms/call_log)
    try {
        const ContentResolver = Java.use("android.content.ContentResolver");
        ContentResolver.query.overload(
            "android.net.Uri",
            "[Ljava.lang.String;",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String"
        ).implementation = function (uri: any, projection: any, selection: any, selectionArgs: any, sortOrder: any) {
            const uriStr: string = uri ? uri.toString() : "";
            if (uriStr.indexOf("contacts") !== -1 || uriStr.indexOf("phone") !== -1) {
                send({ type: "contact_query", uri: uriStr });
            } else if (uriStr.indexOf("sms") !== -1 || uriStr.indexOf("mms") !== -1) {
                send({ type: "sms_read", uri: uriStr });
            } else if (uriStr.indexOf("call_log") !== -1) {
                send({ type: "call_log_read", uri: uriStr });
            }
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
    } catch (_e) {}

    // SharedPreferences
    try {
        const SharedPreferencesEditor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        SharedPreferencesEditor.commit.implementation = function () {
            send({ type: "shared_prefs_write" });
            return this.commit();
        };
    } catch (_e) {}

    // Broadcast
    try {
        const Context = Java.use("android.app.ContextImpl");
        Context.sendBroadcast.overload("android.content.Intent").implementation = function (intent: any) {
            const action: string = intent.getAction ? intent.getAction() : "";
            send({ type: "broadcast_send", action });
            return this.sendBroadcast(intent);
        };
    } catch (_e) {}

    // AlarmManager
    try {
        const AlarmManager = Java.use("android.app.AlarmManager");
        AlarmManager.set.overload("int", "long", "android.app.PendingIntent").implementation = function (type: number, triggerAtMillis: number, operation: any) {
            send({ type: "alarm_set" });
            return this.set(type, triggerAtMillis, operation);
        };
    } catch (_e) {}

    // Native lib loading
    try {
        const System = Java.use("java.lang.System");
        System.loadLibrary.implementation = function (libname: string) {
            send({ type: "native_lib_load", lib: libname });
            return this.loadLibrary(libname);
        };
        System.load.implementation = function (filename: string) {
            send({ type: "native_lib_load", lib: filename });
            return this.load(filename);
        };
    } catch (_e) {}

    // JSON
    try {
        const JSONObject = Java.use("org.json.JSONObject");
        JSONObject.$init.overload("java.lang.String").implementation = function (src: string) {
            send({ type: "json_parse" });
            return this.$init(src);
        };
    } catch (_e) {}

    // DevicePolicyManager
    try {
        const DevicePolicyManager = Java.use("android.app.admin.DevicePolicyManager");
        DevicePolicyManager.isAdminActive.implementation = function (who: any) {
            send({ type: "device_admin_check" });
            return this.isAdminActive(who);
        };
    } catch (_e) {}

    // PackageManager
    try {
        const PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getInstalledPackages.overload("int").implementation = function (flags: number) {
            send({ type: "package_enum" });
            return this.getInstalledPackages(flags);
        };
    } catch (_e) {}
});
