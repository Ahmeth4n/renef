---
title: Syscall Tracer
layout: default
parent: Real-World Examples
nav_order: 5
---

# Syscall Tracer

## Basic File Activity Monitor

Monitor all file operations in a target application:

```lua
-- Trace file-related syscalls
Syscall.trace({ category = "file" })
```

```
[tid:22137] openat(AT_FDCWD, "/data/data/com.app/shared_prefs/config.xml", O_RDONLY, 0644) = 5
[tid:22137] read(5</data/data/com.app/shared_prefs/config.xml>, 0x7183361000, 4096) = 1024
[tid:22137] close(5) = 0
[tid:22160] openat(AT_FDCWD, "/data/data/com.app/databases/app.db", O_RDWR|O_CREAT, 0644) = 8
[tid:22160] write(8</data/data/com.app/databases/app.db>, 0x7fe42f5488, 512) = 512
```

## Network Activity Monitor

Track all network socket operations:

```lua
-- Monitor network activity
Syscall.trace({ category = "network" })
```

```
[tid:22840] socket(2, 1, 6) = 135
[tid:22840] connect(135<socket:[1670397]>, 0x7fe42f5488, 16) = 0
[tid:22840] sendto(135<socket:[1670397]>, 0x6eb3172388, 256, 0, NULL, 0) = 256
[tid:22840] recvfrom(135<socket:[1670397]>, 0xb400006efbf110d0, 65535, 0, NULL, NULL) = 1024
```

## Custom Filtered Tracer

Log only file opens from a specific library:

```lua
Syscall.trace("openat", {
    caller = "libnative.so",
    onCall = function(info)
        print(GREEN .. "[FILE] " .. info.formatted .. RESET)
    end,
    onReturn = function(info)
        if info.retval < 0 then
            print(RED .. "  FAILED: " .. info.errno_str .. RESET)
        else
            print(CYAN .. "  fd=" .. info.retval .. RESET)
        end
    end
})
```

## Security Audit: Detect Sensitive File Access

Monitor access to sensitive paths:

```lua
local sensitive_paths = {
    "/proc/", "/sys/", "/data/local/tmp/",
    "su", "magisk", "frida"
}

Syscall.trace("openat", "access", "stat", "readlink", {
    onCall = function(info)
        local line = info.formatted
        for _, pattern in ipairs(sensitive_paths) do
            if string.find(line, pattern) then
                print(RED .. "[SECURITY] " .. line .. RESET)
                return
            end
        end
    end
})
```

```
[SECURITY] [tid:22137] openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0644) = 12
[SECURITY] [tid:22137] access("/system/xbin/su", 0) = -1 (No such file or directory)
[SECURITY] [tid:22137] stat("/data/local/tmp/frida-server", 0x7fe42f5488) = -1 (No such file or directory)
```

## Full I/O Session Logger

Combine file and network tracing for complete I/O visibility:

```lua
-- Start tracing
Syscall.trace("openat", "read", "write", "close",
              "connect", "sendto", "recvfrom")

-- ... interact with the app ...

-- Check what's active
Syscall.active()

-- Stop when done
Syscall.stop()
```

{: .tip }
> Use `renef-strace` from the CLI for quick one-shot tracing sessions, and the Lua `Syscall` API for scripted analysis with custom filtering and callbacks.
