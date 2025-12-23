-- ============================================================
-- Root Detection Bypass Script for Android
-- ============================================================
-- This script hooks common root detection methods and bypasses them
-- by intercepting system calls and returning false positives
-- ============================================================

-- Set hook type to trampoline (more reliable for system calls)
__hook_type__ = "trampoline"

-- Color constants for better logging
local RED = "\27[31m"
local GREEN = "\27[32m"
local YELLOW = "\27[33m"
local BLUE = "\27[34m"
local CYAN = "\27[36m"
local MAGENTA = "\27[35m"
local RESET = "\27[0m"

print(CYAN .. "+========================================================+" .. RESET)
print(CYAN .. "|      Root Detection Bypass Script v1.0                |" .. RESET)
print(CYAN .. "|      Multi-layer Anti-Root Detection                  |" .. RESET)
print(CYAN .. "+========================================================+" .. RESET)
print("")

-- ============================================================
-- Configuration
-- ============================================================
local config = {
    -- Root detection file paths to hide
    root_files = {
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        "/system/xbin/daemonsu",
        "/system/etc/init.d/99SuperSUDaemon",
        "/dev/com.koushikdutta.superuser.daemon/",
        "/system/app/SuperSU",
        "/system/xbin/sugote",
        "/sbin/magisk",
        "/sbin/magiskhide",
        "/system/xbin/magisk",
        "/data/adb/magisk"
    },

    -- Root detection package names
    root_packages = {
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.zachspong.temprootremovejb",
        "com.ramdroid.appquarantine",
        "com.topjohnwu.magisk"
    },

    -- Dangerous properties to spoof
    dangerous_props = {
        "ro.debuggable",
        "ro.secure",
        "ro.build.tags",
        "ro.build.type"
    },

    -- Enable/disable specific bypasses
    enable_file_access_bypass = true,
    enable_exec_bypass = true,
    enable_package_manager_bypass = true,
    enable_system_properties_bypass = true,
    enable_selinux_bypass = true,

    -- Logging
    verbose_logging = true
}

-- ============================================================
-- Helper Functions
-- ============================================================

local function log_info(msg)
    if config.verbose_logging then
        print(BLUE .. "[INFO] " .. RESET .. msg)
    end
end

local function log_success(msg)
    print(GREEN .. "[OK] " .. RESET .. msg)
end

local function log_hook(func_name, lib_name)
    print(YELLOW .. "[HOOK] " .. RESET .. func_name .. MAGENTA .. " @ " .. RESET .. lib_name)
end

local function log_intercept(func_name, action)
    if config.verbose_logging then
        print(CYAN .. "[INTERCEPT] " .. RESET .. func_name .. " -> " .. action)
    end
end

local function is_root_path(path)
    if not path then return false end
    for _, root_file in ipairs(config.root_files) do
        if string.find(path, root_file, 1, true) then
            return true
        end
    end
    return false
end

local function is_root_package(pkg_name)
    if not pkg_name then return false end
    for _, root_pkg in ipairs(config.root_packages) do
        if string.find(pkg_name, root_pkg, 1, true) then
            return true
        end
    end
    return false
end

-- ============================================================
-- libc Hooks - File Access Bypass
-- ============================================================

local function setup_file_access_hooks()
    if not config.enable_file_access_bypass then
        return
    end

    print("")
    print(GREEN .. "=== File Access Hooks ===" .. RESET)

    local libc_base = Module.find("libc.so")
    if not libc_base then
        print(RED .. "[ERROR] Could not find libc.so" .. RESET)
        return
    end

    log_info("libc.so base: " .. string.format("0x%x", libc_base))

    -- Get libc exports
    local exports = Module.exports("libc.so")
    if not exports then
        print(RED .. "[ERROR] Could not get libc exports" .. RESET)
        return
    end

    -- Hook open()
    for i, export in ipairs(exports) do
        if export.name == "open" then
            log_hook("open()", "libc.so")
            local current_path = nil
            hook("libc.so", export.offset, {
                onEnter = function(args)
                    -- args[0] is the file path pointer
                    local success, path = pcall(function() return Memory.readString(args[0]) end)
                    if success and path then
                        current_path = path
                        if is_root_path(path) then
                            log_intercept("open", "BLOCKED: " .. path)
                        end
                    end
                end,
                onLeave = function(retval)
                    -- Return -1 (ENOENT) for root files
                    if current_path and is_root_path(current_path) then
                        current_path = nil
                        return -1
                    end
                    current_path = nil
                    return retval
                end
            })
            log_success("Hooked open()")
            break
        end
    end

    -- Hook access()
    for i, export in ipairs(exports) do
        if export.name == "access" then
            log_hook("access()", "libc.so")
            local current_path = nil
            hook("libc.so", export.offset, {
                onEnter = function(args)
                    local success, path = pcall(function() return Memory.readString(args[0]) end)
                    if success and path then
                        current_path = path
                        if is_root_path(path) then
                            log_intercept("access", "BLOCKED: " .. path)
                        end
                    end
                end,
                onLeave = function(retval)
                    -- Return -1 for root file access checks
                    if current_path and is_root_path(current_path) then
                        current_path = nil
                        return -1
                    end
                    current_path = nil
                    return retval
                end
            })
            log_success("Hooked access()")
            break
        end
    end

    -- Hook stat()
    for i, export in ipairs(exports) do
        if export.name == "stat" or export.name == "__xstat" then
            log_hook("stat()", "libc.so")
            local current_path = nil
            hook("libc.so", export.offset, {
                onEnter = function(args)
                    -- For stat, first arg might be version for __xstat
                    local path_arg = (export.name == "__xstat") and args[1] or args[0]
                    local success, path = pcall(function() return Memory.readString(path_arg) end)
                    if success and path then
                        current_path = path
                        if is_root_path(path) then
                            log_intercept("stat", "BLOCKED: " .. path)
                        end
                    end
                end,
                onLeave = function(retval)
                    -- Return -1 for root file stat checks
                    if current_path and is_root_path(current_path) then
                        current_path = nil
                        return -1
                    end
                    current_path = nil
                    return retval
                end
            })
            log_success("Hooked stat()")
            break
        end
    end

    -- Hook fopen()
    for i, export in ipairs(exports) do
        if export.name == "fopen" then
            log_hook("fopen()", "libc.so")
            local current_path = nil
            hook("libc.so", export.offset, {
                onEnter = function(args)
                    local success, path = pcall(function() return Memory.readString(args[0]) end)
                    if success and path then
                        current_path = path
                        -- Always log to test watch mode
                        print(CYAN .. "[FOPEN] " .. RESET .. path)
                        if is_root_path(path) then
                            log_intercept("fopen", "BLOCKED: " .. path)
                        end
                    end
                end,
                onLeave = function(retval)
                    -- Return NULL for root files
                    if current_path and is_root_path(current_path) then
                        current_path = nil
                        return 0
                    end
                    current_path = nil
                    return retval
                end
            })
            log_success("Hooked fopen()")
            break
        end
    end
end

-- ============================================================
-- Process Execution Bypass
-- ============================================================

local function setup_exec_hooks()
    if not config.enable_exec_bypass then
        return
    end

    print("")
    print(GREEN .. "=== Process Execution Hooks ===" .. RESET)

    local exports = Module.exports("libc.so")
    if not exports then
        return
    end

    -- Hook system()
    for i, export in ipairs(exports) do
        if export.name == "system" then
            log_hook("system()", "libc.so")
            local is_su_command = false
            hook("libc.so", export.offset, {
                onEnter = function(args)
                    local success, cmd = pcall(function() return Memory.readString(args[0]) end)
                    if success and cmd then
                        if string.find(cmd, "su", 1, true) or string.find(cmd, "which su", 1, true) then
                            is_su_command = true
                            log_intercept("system", "BLOCKED: " .. cmd)
                        end
                    end
                end,
                onLeave = function(retval)
                    -- Return non-zero (failure) for su commands
                    if is_su_command then
                        is_su_command = false
                        return 127  -- Command not found
                    end
                    return retval
                end
            })
            log_success("Hooked system()")
            break
        end
    end

    -- Hook popen()
    for i, export in ipairs(exports) do
        if export.name == "popen" then
            log_hook("popen()", "libc.so")
            local is_su_command = false
            hook("libc.so", export.offset, {
                onEnter = function(args)
                    local success, cmd = pcall(function() return Memory.readString(args[0]) end)
                    if success and cmd then
                        if string.find(cmd, "su", 1, true) or string.find(cmd, "which su", 1, true) then
                            is_su_command = true
                            log_intercept("popen", "BLOCKED: " .. cmd)
                        end
                    end
                end,
                onLeave = function(retval)
                    -- Return NULL for su/which su commands
                    if is_su_command then
                        is_su_command = false
                        return 0
                    end
                    return retval
                end
            })
            log_success("Hooked popen()")
            break
        end
    end

    -- Hook execve()
    for i, export in ipairs(exports) do
        if export.name == "execve" then
            log_hook("execve()", "libc.so")
            local is_su_exec = false
            hook("libc.so", export.offset, {
                onEnter = function(args)
                    local success, path = pcall(function() return Memory.readString(args[0]) end)
                    if success and path then
                        if is_root_path(path) or string.find(path, "su", 1, true) then
                            is_su_exec = true
                            log_intercept("execve", "BLOCKED: " .. path)
                        end
                    end
                end,
                onLeave = function(retval)
                    -- Return -1 for su execution attempts
                    if is_su_exec then
                        is_su_exec = false
                        return -1
                    end
                    return retval
                end
            })
            log_success("Hooked execve()")
            break
        end
    end
end

-- ============================================================
-- System Properties Bypass
-- ============================================================

local function setup_properties_hooks()
    if not config.enable_system_properties_bypass then
        return
    end

    print("")
    print(GREEN .. "=== System Properties Hooks ===" .. RESET)

    local libc_base = Module.find("libc.so")
    if not libc_base then
        return
    end

    local exports = Module.exports("libc.so")
    if not exports then
        return
    end

    -- Hook __system_property_get
    for i, export in ipairs(exports) do
        if export.name == "__system_property_get" then
            log_hook("__system_property_get()", "libc.so")
            hook("libc.so", export.offset, {
                onEnter = function(args)
                    -- args[0] is property name, args[1] is output buffer
                    local success, prop = pcall(function() return Memory.readString(args[0]) end)
                    if success and prop then
                        -- Spoof dangerous properties
                        if prop == "ro.debuggable" then
                            Memory.writeString(args[1], "0")
                            log_intercept("__system_property_get", "SPOOFED: ro.debuggable = 0")
                        elseif prop == "ro.secure" then
                            Memory.writeString(args[1], "1")
                            log_intercept("__system_property_get", "SPOOFED: ro.secure = 1")
                        elseif prop == "ro.build.tags" then
                            Memory.writeString(args[1], "release-keys")
                            log_intercept("__system_property_get", "SPOOFED: ro.build.tags = release-keys")
                        elseif prop == "ro.build.type" then
                            Memory.writeString(args[1], "user")
                            log_intercept("__system_property_get", "SPOOFED: ro.build.type = user")
                        end
                    end
                end,
                onLeave = function(retval)
                    return retval
                end
            })
            log_success("Hooked __system_property_get()")
            break
        end
    end
end

-- ============================================================
-- SELinux Bypass
-- ============================================================

local function setup_selinux_hooks()
    if not config.enable_selinux_bypass then
        return
    end

    print("")
    print(GREEN .. "=== SELinux Hooks ===" .. RESET)

    local libselinux_base = Module.find("libselinux.so")
    if not libselinux_base then
        log_info("libselinux.so not found, skipping")
        return
    end

    log_info("libselinux.so base: " .. string.format("0x%x", libselinux_base))

    local exports = Module.exports("libselinux.so")
    if not exports then
        return
    end

    -- Hook is_selinux_enabled
    for i, export in ipairs(exports) do
        if export.name == "is_selinux_enabled" then
            log_hook("is_selinux_enabled()", "libselinux.so")
            hook("libselinux.so", export.offset, {
                onEnter = function(args)
                    log_intercept("is_selinux_enabled", "returning enabled")
                end,
                onLeave = function(retval)
                    -- Return 1 (enabled) to look legitimate
                    return 1
                end
            })
            log_success("Hooked is_selinux_enabled()")
            break
        end
    end

    -- Hook security_getenforce
    for i, export in ipairs(exports) do
        if export.name == "security_getenforce" then
            log_hook("security_getenforce()", "libselinux.so")
            hook("libselinux.so", export.offset, {
                onEnter = function(args)
                    log_intercept("security_getenforce", "returning enforcing")
                end,
                onLeave = function(retval)
                    -- Return 1 (enforcing mode)
                    return 1
                end
            })
            log_success("Hooked security_getenforce()")
            break
        end
    end
end

-- ============================================================
-- Additional Detection Methods
-- ============================================================

local function setup_additional_hooks()
    print("")
    print(GREEN .. "=== Additional Security Hooks ===" .. RESET)

    -- Hook getpwuid (used to check for su user)
    local exports = Module.exports("libc.so")
    if exports then
        for i, export in ipairs(exports) do
            if export.name == "getpwuid" then
                log_hook("getpwuid()", "libc.so")
                hook("libc.so", export.offset, {
                    onEnter = function(args)
                        -- args[0] is uid, 0 is root
                        local uid = tonumber(args[0])
                        if uid == 0 then
                            log_intercept("getpwuid", "BLOCKED: root uid (0)")
                        end
                    end,
                    onLeave = function(retval)
                        -- Return NULL for root uid checks
                        if tonumber(retval) ~= 0 then
                            local success, name = pcall(function()
                                local passwd_ptr = retval
                                local name_ptr = Memory.read(passwd_ptr, 8)  -- first field is pw_name
                                return Memory.readString(name_ptr)
                            end)
                            if success and name and (name == "root" or name == "su") then
                                log_intercept("getpwuid", "SPOOFED: hiding root user")
                                return 0
                            end
                        end
                        return retval
                    end
                })
                log_success("Hooked getpwuid()")
                break
            end
        end
    end
end

-- ============================================================
-- Memory Scanning for Known Root Signatures
-- ============================================================

local function scan_for_signatures()
    print("")
    print(GREEN .. "=== Scanning for Root Signatures ===" .. RESET)

    -- Scan for common root-related strings in memory
    local signatures = {
        "Superuser",
        "SuperSU",
        "Magisk",
        "/system/xbin/su"
    }

    for _, sig in ipairs(signatures) do
        log_info("Scanning for: " .. sig)
        local results = Memory.scan(sig)

        if results and #results > 0 then
            print(YELLOW .. "[!] Found " .. #results .. " occurrence(s) of: " .. sig .. RESET)

            if config.verbose_logging then
                for i, r in ipairs(results) do
                    if i <= 3 then -- Limit output
                        print("    Library: " .. r.library)
                        print("    Offset:  " .. string.format("0x%x", r.offset))
                    end
                end
            end
        end
    end
end

-- ============================================================
-- Main Execution
-- ============================================================

print("")
print(YELLOW .. "Initializing bypass hooks..." .. RESET)
print("")

-- Debug: Check if libc.so is available
print(BLUE .. "[DEBUG] Checking for libc.so..." .. RESET)
local libc_test = Module.find("libc.so")
if libc_test then
    print(GREEN .. "[DEBUG] libc.so found at: " .. string.format("0x%x", libc_test) .. RESET)
else
    print(RED .. "[DEBUG] libc.so NOT FOUND! Hooks will fail." .. RESET)
    print(YELLOW .. "[DEBUG] Listing loaded modules:" .. RESET)
    local mods = Process.modules()
    if mods then
        for i, m in ipairs(mods) do
            if i <= 5 then
                print("  " .. m.name)
            end
        end
    end
end

-- Setup all hooks
setup_file_access_hooks()
setup_exec_hooks()
setup_properties_hooks()
setup_selinux_hooks()
setup_additional_hooks()

-- Optional: Scan for signatures
-- scan_for_signatures()

print("")
print(GREEN .. "+========================================================+" .. RESET)
print(GREEN .. "|      Root Bypass Script Successfully Loaded!          |" .. RESET)
print(GREEN .. "+========================================================+" .. RESET)
print("")
print(CYAN .. "Configuration:" .. RESET)
print("  File Access Bypass:     " .. (config.enable_file_access_bypass and GREEN .. "ON" or RED .. "OFF") .. RESET)
print("  Exec Bypass:            " .. (config.enable_exec_bypass and GREEN .. "ON" or RED .. "OFF") .. RESET)
print("  Package Manager Bypass: " .. (config.enable_package_manager_bypass and GREEN .. "ON" or RED .. "OFF") .. RESET)
print("  System Props Bypass:    " .. (config.enable_system_properties_bypass and GREEN .. "ON" or RED .. "OFF") .. RESET)
print("  SELinux Bypass:         " .. (config.enable_selinux_bypass and GREEN .. "ON" or RED .. "OFF") .. RESET)
print("")
print(MAGENTA .. "Ready to intercept root detection attempts!" .. RESET)
