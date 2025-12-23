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
