---
title: Scripting Guide
layout: default
nav_order: 8
---

# Scripting Guide

## Basic Hook Example

```lua
-- Hook malloc
local libc_base = Module.find("libc.so")
local malloc_offset = 0x12340

hook("libc.so", malloc_offset, {
    onEnter = function(args)
        local size = args[0]
        print(GREEN .. "[+] malloc(" .. size .. ")" .. RESET)
    end,

    onLeave = function(retval)
        print(GREEN .. "[-] malloc returned: " ..
              string.format("0x%x", retval) .. RESET)
        return retval
    end
})
```

## Java Method Hook Example

{: .note }
> Java hooks with `onEnter` and `onLeave` work on **Android 10+** (tested on Android 10-16).

```lua
-- Hook a Java method and modify its return value
hook("com/example/reneftestapp/MainActivity", "hookTest", "(Ljava/lang/String;)Ljava/lang/String;", {
    onEnter = function(args)
        print("[onEnter] hookTest called")
        print("  param1 ref = " .. string.format("0x%x", args[2]))
    end,
    onLeave = function(retval)
        print("[onLeave] Original return: " .. string.format("0x%x", retval))

        -- Create a new Java String to replace the return value
        local newStr = Jni.newStringUTF("HOOKED!")
        print("[onLeave] Returning: 'HOOKED!' (raw ptr: " .. string.format("0x%x", newStr) .. ")")

        return newStr
    end
})

print("[+] Hook installed")
```

## Java Hook — Skipping the Original Method

Use `args.skip = true` to prevent the original Java method from executing. This is useful for void methods that throw exceptions on failure (like certificate verification):

```lua
-- Skip a void method that throws on failure
hook("com/example/security/PinChecker", "verify",
    "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V", {
    onEnter = function(args)
        args.skip = true  -- Original never called, no exception thrown
        print("[*] PinChecker.verify bypassed")
    end
})
```

For boolean-returning methods, use `onLeave` instead:

```lua
-- Override a boolean return value
hook("com/example/security/CertValidator", "isValid",
    "(Ljava/lang/String;)Z", {
    onLeave = function(retval)
        return 1  -- Always return true
    end
})
```

## Memory Scanning Example

```lua
-- Scan for "Java" string signature
local pattern = "\x4A\x61\x76\x61"  -- "Java" in hex
local results = Memory.scan(pattern)

print(YELLOW .. "Found " .. #results .. " matches:" .. RESET)
for i, result in ipairs(results) do
    print(string.format("[%d] %s + 0x%x", i, result.library, result.offset))
end
```

## Memory Patching Example

```lua
-- Find and patch a function
local base = Module.find("libapp.so")
local target = base + 0x5678

-- ARM64 NOP (nop instruction)
local nop = "\x1f\x20\x03\xd5"

-- Patch 4 NOPs
local patch = nop .. nop .. nop .. nop

local success = Memory.patch(target, patch)
if success then
    print(GREEN .. "✓ Patched 16 bytes at " ..
          string.format("0x%x", target) .. RESET)
else
    print(RED .. "✗ Patch failed" .. RESET)
end
```

## Finding Exported Functions

```lua
-- Find malloc in libc
local exports = Module.exports("libc.so")
local malloc_offset = nil

for i, exp in ipairs(exports) do
    if exp.name == "malloc" then
        malloc_offset = exp.offset
        break
    end
end

if malloc_offset then
    print(string.format("malloc @ 0x%x", malloc_offset))

    -- Hook it
    hook("libc.so", malloc_offset, {
        onEnter = function(args)
            print("malloc size: " .. args[0])
        end
    })
end
```

## Multiple Hooks Script

```lua
print(CYAN .. "=== Setting up hooks ===" .. RESET)

-- Hook malloc
hook("libc.so", 0x12340, {
    onEnter = function(args)
        print("[malloc] size: " .. args[0])
    end
})

-- Hook free
hook("libc.so", 0x12380, {
    onEnter = function(args)
        print(string.format("[free] ptr: 0x%x", args[0]))
    end
})

-- Hook custom function
local app_base = Module.find("libapp.so")
if app_base then
    hook("libapp.so", 0x5000, {
        onEnter = function(args)
            print("[custom_func] arg0: " .. args[0])
        end,
        onLeave = function(retval)
            print("[custom_func] returning: " .. retval)
            return retval
        end
    })
end

print(GREEN .. "✓ All hooks installed" .. RESET)
```
