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

    // ── SMS Hook'ları ─────────────────────────────────────
    try {
        var SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.implementation = function (dest, sc, text, sent, delivery) {
            send({ type: "sms_send", destination: dest });
            return this.sendTextMessage(dest, sc, text, sent, delivery);
        };
    } catch (e) { }

});
