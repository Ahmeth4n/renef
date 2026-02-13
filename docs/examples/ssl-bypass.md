---
title: SSL Pinning Bypass
layout: default
parent: Real-World Examples
nav_order: 1
---

# SSL Pinning Bypass

## Flutter SSL Pinning Bypass

Flutter apps use their own SSL implementation bundled in `libflutter.so`. This requires hooking the library at load time since the SSL verification function is not exported.

```lua
-- Flutter SSL Pinning Bypass for RENEF
-- Works for Flutter apps using BoringSSL

print("[*] Flutter SSL Pinning Bypass loading...")

-- Hardcoded offset for ssl_crypto_x509_session_verify_cert_chain
-- This offset may vary per Flutter version - update if needed
local SSL_VERIFY_OFFSET = 0x5dc730

local bypass_installed = false

-- Function to install SSL bypass on libflutter.so
local function install_ssl_bypass()
    if bypass_installed then
        return true
    end

    local flutter_base = Module.find("libflutter.so")
    if not flutter_base then
        return false
    end

    print(string.format("[+] libflutter.so found at: 0x%x", flutter_base))
    print(string.format("[+] Installing hook at offset: 0x%x", SSL_VERIFY_OFFSET))

    -- Install hook to bypass SSL verification
    hook("libflutter.so", SSL_VERIFY_OFFSET, {
        onEnter = function(args)
            print("[*] SSL verify called!")
        end,
        onLeave = function(retval)
            print("[*] SSL verify bypassing, returning 1")
            return 1  -- Return success (1 = verified)
        end
    })

    bypass_installed = true
    print("[+] SSL pinning bypass ACTIVE!")
    return true
end

-- Try to install bypass immediately if libflutter is already loaded
if install_ssl_bypass() then
    print("[+] Bypass installed on existing libflutter.so")
else
    print("[*] libflutter.so not loaded yet, hooking linker...")

    -- Hook android_dlopen_ext which is used to load libraries
    local linker_name = "linker64"
    local linker_base = Module.find(linker_name)

    if not linker_base then
        print("[-] linker64 not found, trying linker")
        linker_name = "linker"
        linker_base = Module.find(linker_name)
    end

    if not linker_base then
        print("[-] Cannot find linker!")
    else
        print(string.format("[+] %s found at: 0x%x", linker_name, linker_base))

        -- Get linker symbols
        local linker_symbols = Module.symbols(linker_name)
        if not linker_symbols then
            print("[-] Cannot get linker symbols (may be stripped)")
            print("[*] Trying exports instead...")
            linker_symbols = Module.exports(linker_name)
        end

        if linker_symbols then
            -- Find __dl__Z9do_dlopenPKciPK17android_dlextinfoPKv or similar
            local dlopen_offset = nil
            for _, sym in ipairs(linker_symbols) do
                if sym.name:find("do_dlopen") then
                    dlopen_offset = sym.offset
                    print(string.format("[+] Found %s at offset 0x%x", sym.name, sym.offset))
                    break
                end
            end

            if dlopen_offset then
                print(string.format("[+] Hooking %s + 0x%x", linker_name, dlopen_offset))

                hook(linker_name, dlopen_offset, {
                    onEnter = function(args)
                        -- args[0] is the library path
                        local path = Memory.readString(args[0])
                        if path and path:find("libflutter") then
                            print("[+] libflutter.so loading: " .. path)
                        end
                    end,
                    onLeave = function(retval)
                        -- After library loads, try to install bypass
                        if not bypass_installed then
                            install_ssl_bypass()
                        end
                    end
                })
                print("[+] Linker hook installed, waiting for libflutter.so...")
            else
                print("[-] do_dlopen not found in linker symbols")
            end
        else
            print("[-] Cannot get linker symbols/exports")
        end
    end
end

print("[+] Flutter SSL Bypass script loaded")
```

### How It Works

1. **Check if loaded** - First tries to hook `libflutter.so` if already loaded
2. **Hook linker** - If not loaded, hooks `do_dlopen` in linker64 to watch for library loads
3. **Install bypass** - When `libflutter.so` loads, hooks `ssl_crypto_x509_session_verify_cert_chain`
4. **Return success** - Always returns 1 (verified) from the SSL verification function

{: .note }
> The offset `0x5dc730` is specific to a particular Flutter version. You may need to find the correct offset for your target app using reverse engineering tools.

### Finding the Correct Offset

```bash
# Extract libflutter.so from APK
unzip -j app.apk lib/arm64-v8a/libflutter.so

# Search for ssl_verify or session_verify patterns
strings libflutter.so | grep -i ssl_verify
```

Or use Renef's memory search:

```bash
exec Memory.dump(Memory.search("session_verify", "libflutter.so"))
```

---

## Java SSL Pinning Bypass

For apps that use Java-level SSL verification (Conscrypt, OkHttp, Network Security Config, etc.), Renef can hook the certificate verification methods directly using Java hooks.

### Quick Start

Renef ships with a comprehensive SSL unpinning script that covers 30+ targets. The script is also available on [Renef Hookshare](https://hook.renef.io/@ahmethan/universal-ssl-pinning-bypass-script).

```bash
renef> spawn com.example.app
renef> l scripts/ssl_unpin.lua
```

### How It Works

Java SSL verification methods like `checkServerTrusted` are void methods that throw exceptions on failure. By using `args.skip = true`, we skip calling the original method entirely — the method returns cleanly without throwing, which the caller interprets as "certificate verified."

```lua
-- Bypass TrustManagerImpl.checkServerTrusted
hook("com/android/org/conscrypt/TrustManagerImpl", "checkServerTrusted",
    "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V", {
    onEnter = function(args)
        args.skip = true
        print("[*] TrustManagerImpl.checkServerTrusted bypassed")
    end
})
```

{: .note }
`args.skip = true` is essential on Android 16+ where calling the original method on nested hooked methods can crash ART's stack walker. See [Hook API - args.skip](/docs/api/hook/) for details.

### Custom TrustManager with Java API

For more control, you can replace the app's TrustManager entirely using `Java.registerClass`:

```lua
local EmptyTrustManager = Java.registerClass({
    name = "com.renef.EmptyTrustManager",
    implements = { "javax/net/ssl/X509TrustManager" },
    methods = {
        checkClientTrusted = function(self, args) end,
        checkServerTrusted = function(self, args) end,
        getAcceptedIssuers = function(self, args) return nil end
    }
})

local tm_array = Java.array("javax/net/ssl/TrustManager", { EmptyTrustManager })

hook("javax/net/ssl/SSLContext", "init",
    "(Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V", {
    onEnter = function(args)
        args[3] = tm_array.raw
        print("[*] SSLContext.init: TrustManagers replaced")
    end
})
```

### Covered Targets (ssl_unpin.lua)

| Target | Method |
|--------|--------|
| **Conscrypt** | `TrustManagerImpl`, `ConscryptEngine`, `Platform`, `OpenSSLSocketImpl` |
| **Network Security Config** | `NetworkSecurityTrustManager`, `RootTrustManager` |
| **OkHttp3** | `CertificatePinner.check`, `OkHostnameVerifier.verify` |
| **OkHttp2 (Squareup)** | `CertificatePinner.check`, `OkHostnameVerifier.verify` |
| **Trustkit** | `PinningTrustManager.checkServerTrusted` |
| **Apache** | `AbstractVerifier.verify`, `Harmony OpenSSLSocketImpl` |
| **WebView** | `WebViewClient.onReceivedSslError` |
| **Chromium Cronet** | `CronetEngine.Builder.enablePublicKeyPinningBypassForLocalTrustAnchors` |
| **Others** | Fabric, Netty, Appcelerator, Boye, Appmattus, CWAC-Netsecurity, Cordova |

### Android 16 Notes

Android 16 changed some Conscrypt method signatures:

| Method | Old Signature | New Signature (Android 16) |
|--------|--------------|---------------------------|
| `ConscryptEngine.verifyCertificateChain` | `([JLjava/lang/String;)V` | `([[BLjava/lang/String;)V` |

The `ssl_unpin.lua` script hooks both variants for maximum compatibility.

---

## Basic SSL Bypass (libssl.so)

For apps using standard OpenSSL/BoringSSL via `libssl.so`:

```lua
-- Hook SSL verification function
local libssl = Module.find("libssl.so")
local exports = Module.exports("libssl.so")

-- Find SSL_CTX_set_verify
for i, exp in ipairs(exports) do
    if exp.name == "SSL_CTX_set_verify" then
        hook("libssl.so", exp.offset, {
            onEnter = function(args)
                print(YELLOW .. "[SSL] Bypassing certificate verification" .. RESET)
                -- Set verify mode to SSL_VERIFY_NONE (0)
                args[1] = 0
            end
        })
        break
    end
end

print(GREEN .. "✓ SSL pinning bypass installed" .. RESET)
```
