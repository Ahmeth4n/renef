---
title: Frida to Renef
layout: default
nav_order: 11
---

# Frida to Renef

A migration guide for Frida users. This page maps common Frida JavaScript APIs to their Renef Lua equivalents with side-by-side examples.

{: .note }
> Renef uses **Lua 5.4** instead of JavaScript. Key syntax differences: `local` instead of `var/let/const`, `..` for string concatenation, `string.format` instead of template literals, `function(x) end` instead of `(x) => {}`, tables `{}` instead of objects/arrays.

---

## API Mapping

### Module / Process

| Frida (JS) | Renef (Lua) | Notes |
|-------------|-------------|-------|
| `Module.findBaseAddress("libc.so")` | `Module.find("libc.so")` | Returns integer (not NativePointer) |
| `Module.findExportByName("libc.so", "open")` | Manual lookup via `Module.exports()` | See example below |
| `Module.enumerateExports("libc.so")` | `Module.exports("libc.so")` | Returns `{name, offset}` table |
| `Module.enumerateSymbols("libc.so")` | `Module.symbols("libc.so")` | Reads `.symtab` section |
| `Process.enumerateModules()` | `Module.list()` | Returns string, not table |

**Finding an export by name:**

```javascript
// Frida
var open = Module.findExportByName("libc.so", "open");
Interceptor.attach(open, { ... });
```

```lua
-- Renef
for _, sym in ipairs(Module.exports("libc.so")) do
    if sym.name == "open" then
        hook("libc.so", sym.offset, { ... })
        break
    end
end
```

{: .note }
> `Module.exports()` reads `.dynsym` (public symbols). `Module.symbols()` reads `.symtab` (all symbols including internal/static). Use `symbols()` for stripped-away internal functions like linker's `do_dlopen`.

---

### Native Hooks

| Frida (JS) | Renef (Lua) |
|-------------|-------------|
| `Interceptor.attach(ptr(addr), callbacks)` | `hook("lib.so", offset, callbacks)` |
| `Interceptor.detachAll()` | `unhook all` (CLI command) |

{: .highlight }
> Renef hooks take a **library name + offset** pair instead of an absolute address. The offset is relative to the library base.

**Hook a native function:**

```javascript
// Frida
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        console.log("open(" + args[0].readUtf8String() + ")");
    },
    onLeave: function(retval) {
        console.log("fd = " + retval.toInt32());
    }
});
```

```lua
-- Renef
for _, sym in ipairs(Module.exports("libc.so")) do
    if sym.name == "open" then
        hook("libc.so", sym.offset, {
            onEnter = function(args)
                print("open(" .. Memory.readString(args[0]) .. ")")
            end,
            onLeave = function(retval)
                print("fd = " .. retval)
                return retval
            end
        })
        break
    end
end
```

**Modify arguments and return values:**

```javascript
// Frida
Interceptor.attach(addr, {
    onEnter: function(args) {
        args[0] = ptr(0x200);
    },
    onLeave: function(retval) {
        retval.replace(ptr(0x1));
    }
});
```

```lua
-- Renef
hook("libc.so", offset, {
    onEnter = function(args)
        args[0] = 0x200
    end,
    onLeave = function(retval)
        return 0x1  -- return value to replace
    end
})
```

{: .note }
> In Frida, `retval.replace()` modifies in-place. In Renef, you `return` the new value from `onLeave`.

---

### Java Hooks

| Frida (JS) | Renef (Lua) |
|-------------|-------------|
| `Java.perform(fn)` | Not needed |
| `cls.method.implementation = fn` | `hook("class", "method", "sig", callbacks)` |
| Auto-resolved overloads | Explicit JNI signature required |
| `this.method(args)` (call original) | Automatic (original called unless `args.skip = true`) |
| No equivalent | `args.skip = true` (skip original entirely) |

{: .highlight }
> Renef uses `/` separators for class names (JNI format): `"com/example/Class"` instead of `"com.example.Class"`. Java hooks require an explicit JNI signature.

**Hook a Java method:**

```javascript
// Frida
Java.perform(function() {
    var MainActivity = Java.use("com.example.app.MainActivity");
    MainActivity.getSecret.implementation = function(input) {
        console.log("getSecret called with: " + input);
        var result = this.getSecret(input);  // call original
        console.log("returned: " + result);
        return "HOOKED!";
    };
});
```

```lua
-- Renef
hook("com/example/app/MainActivity", "getSecret",
    "(Ljava/lang/String;)Ljava/lang/String;", {
    onEnter = function(args)
        local input = Jni.getStringUTF(args[2])
        print("getSecret called with: " .. tostring(input))
    end,
    onLeave = function(retval)
        local original = Jni.getStringUTF(retval)
        print("returned: " .. tostring(original))
        return Jni.newStringUTF("HOOKED!")
    end
})
```

{: .note }
> **Java hook args layout:** `args[0]` = ArtMethod pointer (internal), `args[1]` = `this` (instance) or first param (static), `args[2..n]` = method parameters. String arguments are raw pointers — use `Jni.getStringUTF()` to read them.

**Skip original method (bypass pattern):**

In Frida, you skip the original by simply not calling `this.method()`. In Renef, use `args.skip = true`:

```javascript
// Frida
Java.perform(function() {
    var TrustManager = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManager.checkServerTrusted.implementation = function() {
        // Don't call original — just return
    };
});
```

```lua
-- Renef
hook("com/android/org/conscrypt/TrustManagerImpl", "checkServerTrusted",
    "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V", {
    onEnter = function(args)
        args.skip = true  -- skip original, no exception thrown
    end
})
```

**Java hook return value options:**

| Return from `onLeave` | Effect |
|---|---|
| `nil` (or no return) | Original return value unchanged |
| integer | Sets x0 register directly |
| boolean (`true`/`false`) | Sets x0 to 1 or 0 |
| `Jni.newStringUTF("...")` | Returns new Java String |
| `{__jni_type="string", value="..."}` | Creates and returns a Java String |
| `{__jni_type="int", value=N}` | Sets x0 to N |

**Jni helpers (for use in hook callbacks):**

| Frida (JS) | Renef (Lua) |
|-------------|-------------|
| `Java.use("java.lang.String").$new("text")` | `Jni.newStringUTF("text")` |
| String args auto-converted | `Jni.getStringUTF(args[2])` — manual read |
| N/A | `Jni.getStringLength(ref)` |
| N/A | `Jni.deleteGlobalRef(ref)` |

---

### Java API (Class Interaction)

| Frida (JS) | Renef (Lua) | Notes |
|-------------|-------------|-------|
| `Java.use("com.example.Class")` | `Java.use("com/example/Class")` | `/` separators, ClassLoader fallback |
| `cls.$new(args)` | `wrapper:new(sig, args)` | Explicit JNI signature |
| `cls.staticMethod(args)` | `wrapper:call("method", sig, args)` | Explicit JNI signature |
| `instance.method(args)` | `instance:call("method", sig, args)` | Explicit JNI signature |
| `Java.registerClass({...})` | `Java.registerClass({...})` | DEX proxy bridge |
| `Java.array("java.lang.String", [...])` | `Java.array("java/lang/String", {...})` | `/` separators |
| N/A | `instance.raw` | Raw ART `mirror::Object*` pointer |

**Create instance and call methods:**

```javascript
// Frida
Java.perform(function() {
    var StringBuilder = Java.use("java.lang.StringBuilder");
    var sb = StringBuilder.$new();
    sb.append("Hello");
    sb.append(" World");
    console.log(sb.toString());
});
```

```lua
-- Renef
local StringBuilder = Java.use("java/lang/StringBuilder")
local sb = StringBuilder:new("()V")
sb:call("append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", "Hello")
sb:call("append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", " World")
print(sb:call("toString", "()Ljava/lang/String;"))
```

**Call static methods:**

```javascript
// Frida
Java.perform(function() {
    var System = Java.use("java.lang.System");
    console.log(System.currentTimeMillis());
});
```

```lua
-- Renef
local System = Java.use("java/lang/System")
print(System:call("currentTimeMillis", "()J"))
```

**Register a custom class:**

```javascript
// Frida
var EmptyTrustManager = Java.registerClass({
    name: "com.frida.EmptyTrustManager",
    implements: [Java.use("javax.net.ssl.X509TrustManager")],
    methods: {
        checkClientTrusted: function(chain, authType) {},
        checkServerTrusted: function(chain, authType) {},
        getAcceptedIssuers: function() { return []; }
    }
});
```

```lua
-- Renef
local EmptyTrustManager = Java.registerClass({
    name = "com.renef.EmptyTrustManager",
    implements = { "javax/net/ssl/X509TrustManager" },
    methods = {
        checkClientTrusted = function(self, args) end,
        checkServerTrusted = function(self, args) end,
        getAcceptedIssuers = function(self, args) return nil end
    }
})
```

**Create Java arrays:**

```javascript
// Frida
var tm_array = Java.array("javax.net.ssl.TrustManager", [emptyTm]);
```

```lua
-- Renef
local tm_array = Java.array("javax/net/ssl/TrustManager", { emptyTm })
-- Use tm_array.raw to pass as hook argument
```

---

### Memory

| Frida (JS) | Renef (Lua) | Notes |
|-------------|-------------|-------|
| `Memory.scan(addr, size, pattern, callbacks)` | `Memory.search("pattern", "lib.so")` | Searches all `.so` regions by default |
| `Memory.scanSync(addr, size, pattern)` | `Memory.scan("pattern")` | Alias for `Memory.search` |
| N/A | `Memory.dump(results)` | Pretty-prints search results |
| `ptr(addr).readU8()` | `Memory.readU8(addr)` | |
| `ptr(addr).readU16()` | `Memory.readU16(addr)` | |
| `ptr(addr).readU32()` | `Memory.readU32(addr)` | |
| `ptr(addr).readU64()` | `Memory.readU64(addr)` | |
| `ptr(addr).readUtf8String()` | `Memory.readString(addr)` | Also: `Memory.readStr()` |
| `ptr(addr).readByteArray(size)` | `Memory.read(addr, size)` | Returns Lua string |
| `ptr(addr).writeU8(val)` | `Memory.writeU8(addr, val)` | |
| `ptr(addr).writeU16(val)` | `Memory.writeU16(addr, val)` | |
| `ptr(addr).writeU32(val)` | `Memory.writeU32(addr, val)` | |
| `ptr(addr).writeU64(val)` | `Memory.writeU64(addr, val)` | |
| `ptr(addr).writeByteArray(bytes)` | `Memory.write(addr, bytes)` | |
| `Memory.patchCode(addr, size, fn)` | `Memory.patch(addr, bytes)` | Auto-handles `mprotect` |

**Memory scan:**

```javascript
// Frida
var ranges = Process.enumerateRanges('r--');
Memory.scan(ranges[0].base, ranges[0].size, "DE AD BE EF", {
    onMatch: function(address, size) {
        console.log("Found at: " + address);
    },
    onComplete: function() {
        console.log("Scan complete");
    }
});
```

```lua
-- Renef (searches all .so regions automatically)
local results = Memory.search("DE AD BE EF")
Memory.dump(results)

-- Or search in a specific library
local results = Memory.search("DE AD BE EF", "libtarget.so")
```

{: .note }
> Renef's `Memory.search` supports `??` wildcards: `Memory.search("FD 7B ?? A9")` matches any ARM64 function prologue.

**Read and write memory:**

```javascript
// Frida
var base = Module.findBaseAddress("libgame.so");
var val = base.add(0x1234).readU32();
console.log("Value: " + val);
base.add(0x1234).writeU32(0xD503201F);
```

```lua
-- Renef
local base = Module.find("libgame.so")
local val = Memory.readU32(base + 0x1234)
print(string.format("Value: 0x%x", val))
Memory.writeU32(base + 0x1234, 0xD503201F)
```

**Patch with mprotect:**

```javascript
// Frida
Memory.patchCode(addr, 4, function(code) {
    var writer = new Arm64Writer(code);
    writer.putNop();
    writer.flush();
});
```

```lua
-- Renef (mprotect handled automatically)
Memory.patch(addr, "\x1f\x20\x03\xd5")  -- ARM64 NOP
```

---

### Thread / NativeFunction

| Frida (JS) | Renef (Lua) |
|-------------|-------------|
| `new NativeFunction(addr, 'int', ['int'])(42)` | `Thread.call(addr, 42)` |

```javascript
// Frida
var malloc = new NativeFunction(
    Module.findExportByName("libc.so", "malloc"),
    'pointer', ['size_t']
);
var buf = malloc(0x100);
```

```lua
-- Renef
local malloc_addr = Module.find("libc.so") + malloc_offset
local buf = Thread.call(malloc_addr, 0x100)
```

---

### File System

Renef provides a built-in `File` API for reading files within the target process. Frida has no direct equivalent for this.

| Frida (JS) | Renef (Lua) |
|-------------|-------------|
| N/A (use `recv`/`send` to proxy) | `File.read(path)` |
| N/A | `File.exists(path)` |
| N/A | `File.readlink(path)` |
| N/A | `File.fdpath(fd)` |

```lua
-- Read /proc/self/maps from target process
local maps = File.read("/proc/self/maps")

-- Resolve file descriptor in a hook
hook("libc.so", read_offset, {
    onEnter = function(args)
        local path = File.fdpath(args[0])
        print("read() on: " .. tostring(path))
    end
})
```

---

### Console / Output

| Frida (JS) | Renef (Lua) |
|-------------|-------------|
| `console.log(msg)` | `print(msg)` or `console.log(msg)` |
| Template literals `` `value: ${x}` `` | `string.format("value: 0x%x", x)` |
| N/A | Color codes: `RED`, `GREEN`, `YELLOW`, `BLUE`, `CYAN`, `MAGENTA`, `WHITE`, `RESET` |

```javascript
// Frida
console.log(`Found at: ${addr}`);
```

```lua
-- Renef
print(string.format("Found at: 0x%x", addr))
print(GREEN .. "Success!" .. RESET)
```

---

### CLI

| Frida | Renef |
|-------|-------|
| `frida -U -f com.example.app` | `./renef -s com.example.app` |
| `frida -U -p 1234` | `./renef -a 1234` |
| `frida -U -f app -l script.js` | `./renef -s app -l script.lua` |
| `frida -U --no-pause -f app` | `./renef -s app` (no pause by default) |
| Separate gadget binary | `./renef -g <pid>` (built-in gadget mode) |
| N/A | `./renef -s app -v` (verbose/logcat debug output) |
| N/A | `hookgen libc.so malloc` (generate hook template) |

---

## Full Script Examples

### SSL Pinning Bypass

```javascript
// Frida
Java.perform(function() {
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.checkServerTrusted.overload(
        "[Ljava.security.cert.X509Certificate;", "java.lang.String"
    ).implementation = function(chain, authType) {
        // Do nothing — skip verification
    };

    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload("java.lang.String", "java.util.List")
        .implementation = function(hostname, peerCerts) {
        // Do nothing
    };
});
```

```lua
-- Renef
hook("com/android/org/conscrypt/TrustManagerImpl", "checkServerTrusted",
    "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V", {
    onEnter = function(args)
        args.skip = true
    end
})

hook("okhttp3/CertificatePinner", "check",
    "(Ljava/lang/String;Ljava/util/List;)V", {
    onEnter = function(args)
        args.skip = true
    end
})
```

### Custom TrustManager Replacement

```javascript
// Frida
Java.perform(function() {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    var EmptyTM = Java.registerClass({
        name: "com.frida.EmptyTrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function() {},
            checkServerTrusted: function() {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var ctx = SSLContext.getInstance("TLS");
    ctx.init(null, [EmptyTM.$new()], null);
});
```

```lua
-- Renef
local EmptyTM = Java.registerClass({
    name = "com.renef.EmptyTrustManager",
    implements = { "javax/net/ssl/X509TrustManager" },
    methods = {
        checkClientTrusted = function(self, args) end,
        checkServerTrusted = function(self, args) end,
        getAcceptedIssuers = function(self, args) return nil end
    }
})

local tm_array = Java.array("javax/net/ssl/TrustManager", { EmptyTM })

hook("javax/net/ssl/SSLContext", "init",
    "(Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V", {
    onEnter = function(args)
        args[3] = tm_array.raw
        print("[*] SSLContext.init: TrustManagers replaced")
    end
})
```

### Function Tracing

```javascript
// Frida
var malloc = Module.findExportByName("libc.so", "malloc");
Interceptor.attach(malloc, {
    onEnter: function(args) {
        this.size = args[0].toInt32();
        console.log("malloc(" + this.size + ")");
    },
    onLeave: function(retval) {
        console.log("  => " + retval);
    }
});
```

```lua
-- Renef
for _, sym in ipairs(Module.exports("libc.so")) do
    if sym.name == "malloc" then
        hook("libc.so", sym.offset, {
            onEnter = function(args)
                print(string.format("malloc(0x%x)", args[0]))
            end,
            onLeave = function(retval)
                print(string.format("  => 0x%x", retval))
                return retval
            end
        })
        break
    end
end
```

### Library Load Monitoring

```javascript
// Frida
var dlopen = Module.findExportByName(null, "android_dlopen_ext");
Interceptor.attach(dlopen, {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
        console.log("[dlopen] " + this.path);
    }
});
```

```lua
-- Renef (hooks internal do_dlopen via .symtab)
local symbols = Module.symbols("linker64")
for _, sym in ipairs(symbols) do
    if sym.name:find("do_dlopen") then
        hook("linker64", sym.offset, {
            onEnter = function(args)
                local path = Memory.readString(args[0])
                if path then
                    print("[dlopen] " .. path)
                end
            end
        })
        break
    end
end
```

### Get Application Info via Java API

```javascript
// Frida
Java.perform(function() {
    var ActivityThread = Java.use("android.app.ActivityThread");
    var app = ActivityThread.currentApplication();
    var pkg = app.getPackageName();
    console.log("Package: " + pkg);
});
```

```lua
-- Renef
local ActivityThread = Java.use("android/app/ActivityThread")
local app = ActivityThread:call("currentApplication", "()Landroid/app/Application;")
local pkg = app:call("getPackageName", "()Ljava/lang/String;")
print("Package: " .. pkg)
```

---

## Key Differences Summary

| | Frida | Renef |
|---|---|---|
| **Language** | JavaScript (V8/QuickJS) | Lua 5.4 |
| **Platform** | Multi-platform (Android, iOS, Windows, macOS, Linux) | Android ARM64 |
| **Java class format** | `com.example.Class` | `com/example/Class` (JNI format) |
| **Java method overloads** | Auto-resolved (`.overload()` for ambiguous) | Explicit JNI signature always required |
| **Java `perform` wrapper** | Required (`Java.perform(fn)`) | Not needed |
| **Hook target** | Absolute address (`ptr(0x...)`) | Library name + offset |
| **Hook return modify** | `retval.replace(val)` | `return val` from `onLeave` |
| **Skip original (Java)** | Don't call `this.method()` | `args.skip = true` |
| **Memory API style** | OOP (`ptr(x).readU32()`) | Functional (`Memory.readU32(x)`) |
| **File system access** | Via `recv`/`send` proxy | Built-in `File` API |
| **Gadget mode** | Separate gadget binary + config | Built-in `-g` flag |
| **Script sharing** | Community repos | [Hookshare](https://hook.renef.io/) |
