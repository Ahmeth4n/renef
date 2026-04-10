---
title: Hook API
layout: default
parent: Lua API Reference
nav_order: 3
---

# Hook API

{: .note }
> Renef's hook engine writes to memory via `/proc/self/mem` (`pwrite`) instead of `mprotect`. This bypasses SELinux/seccomp restrictions, maintains W^X compliance, and leaves no permission changes visible in `/proc/self/maps`. Falls back to `mprotect` automatically if `/proc/self/mem` is unavailable.

## `hook(library, offset, callbacks)`

Hook a native function by library name and offset.

```lua
hook("libc.so", 0x12340, {
    onEnter = function(args)
        print("[+] malloc called")
        print(string.format("    size: 0x%x", args[0]))

        -- Modify argument
        args[0] = 0x200
    end,

    onLeave = function(retval)
        print(string.format("[-] malloc returning: 0x%x", retval))

        -- Modify return value
        return retval + 0x100
    end
})
```

**Parameters:**
- `library` - Library name (e.g., "libc.so")
- `offset` - Offset from library base (hex number)
- `callbacks` - Table with `onEnter` and/or `onLeave` functions, and optional `caller` field

**Callbacks table fields:**

| Field | Type | Description |
|-------|------|-------------|
| `onEnter` | function | Called before the original function |
| `onLeave` | function | Called after the original function returns |
| `caller` | string or table | Filter: only hook calls from this library (enables PLT/GOT hooking) |

```lua
-- Hook only calls to malloc from libnative.so (PLT/GOT mode)
hook("libc.so", malloc_offset, {
    caller = "libnative.so",
    onEnter = function(args)
        print(string.format("malloc(0x%x) from libnative.so", args[0]))
    end
})

-- Hook calls from multiple libraries
hook("libc.so", open_offset, {
    caller = {"libnative.so", "libutils.so"},
    onEnter = function(args) ... end
})
```

{: .note }
> Without `caller`, a **trampoline hook** is used (patches the target function directly). With `caller`, a **PLT/GOT hook** is used (patches the caller's GOT entries only).

**onEnter arguments:**
- `args` - Table with function arguments (args[0], args[1], ... args[7] for x0-x7)
- Arguments can be modified by assignment

**onLeave arguments:**
- `retval` - Return value from function (x0 register)
- Return a value to replace the original return value

### Stack Trace in Hooks

Use `Thread.backtrace()` inside hook callbacks to see who called the hooked function:

```lua
hook("libc.so", fopen_offset, {
    onEnter = function(args)
        local path = Memory.readString(args[0])
        print("fopen(" .. tostring(path) .. ")")
        print(Thread.backtrace())
    end
})
```

---

## `hook(class, method, signature, callbacks)`

Hook a Java method via JNI.

{: .note }
> **Android 10+ Supported**: Java hooks with `onEnter` and `onLeave` callbacks work on Android 10 (API 29) and later. Tested and verified on Android 10, 11, 12, 13, 14, 15, and 16.

{: .highlight }
> **Nested Hooks Supported** (v0.2.2+): Java hooks can be nested recursively with proper call stack tracking. Hook callbacks can safely call other hooked methods.

```lua
hook("com/example/MainActivity", "getSecret", "(Ljava/lang/String;)Ljava/lang/String;", {
    onEnter = function(args)
        print("[+] MainActivity.getSecret() called")
        print(string.format("    this: 0x%x", args[1]))
        print(string.format("    param1: 0x%x", args[2]))
    end,
    onLeave = function(retval)
        print(string.format("[*] Original return: 0x%x", retval.raw))
        if retval.value then
            print("    String value: " .. retval.value)
        end

        -- Create and return a new string
        local newStr = Jni.newStringUTF("Modified!")
        return newStr
    end
})
```

**Parameters:**
- `class` - Class name with `/` separators (e.g., "com/example/MainActivity")
- `method` - Method name
- `signature` - JNI signature (e.g., "(Ljava/lang/String;)Ljava/lang/String;")
- `callbacks` - Table with `onEnter` and/or `onLeave` functions

**Java hook `onEnter` — `args` table:**

| Key | Type | Description |
|-----|------|-------------|
| `args[0]` | integer | ArtMethod pointer (internal, not useful to scripts) |
| `args[1]` | integer | `this` pointer (instance methods) or first parameter (static methods) |
| `args[2..7]` | integer | Method parameters as raw pointers |
| `args.class` | string | Class name |
| `args.method` | string | Method name |
| `args.signature` | string | JNI signature |
| `args.isStatic` | boolean | Whether method is static |
| `args.skip` | boolean | Set to `true` to skip calling the original method entirely |

Arguments are modifiable: `args[2] = newValue` will change the parameter passed to the original method.

**Java hook `onLeave` — `retval` table:**

| Field | Type | Description |
|-------|------|-------------|
| `retval.raw` | integer | Raw return value (x0 register) |
| `retval.value` | string or nil | Decoded string content (only for methods returning `String`) |

**`args.skip` — Skip Original Method:**

Setting `args.skip = true` in `onEnter` prevents the original Java method from being called. The hook returns immediately with a zero value, and `onLeave` still runs normally.

This is essential for void methods that signal failure by throwing exceptions (e.g., `checkServerTrusted`). Skipping the original avoids both the exception and potential ART stack walk crashes when multiple hooked methods are nested on the same call stack.

```lua
hook("javax/net/ssl/X509TrustManager", "checkServerTrusted",
    "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V", {
    onEnter = function(args)
        args.skip = true  -- Don't call original, method returns cleanly
        print("[*] checkServerTrusted bypassed")
    end
})
```

**Modifying return values (`onLeave`):**

| Return from onLeave | Effect |
|---|---|
| `nil` (or no return) | Original return value unchanged |
| integer | Sets x0 register directly (e.g., `return 1` for true, `return 0` for false) |
| `{__jni_type="string", value="..."}` | Creates a new Java String and returns it |
| `{__jni_type="int", value=N}` | Sets x0 to N |
| `{__jni_type="boolean", value=true}` | Sets x0 to 1 or 0 |
| `Jni.newStringUTF("...")` | Returns raw pointer to new Java String |

```lua
-- Return a modified string
onLeave = function(retval)
    return Jni.newStringUTF("Modified!")
end

-- Return a boolean (for verify() methods)
onLeave = function(retval)
    return 1  -- true
end
```

---

## Jni Namespace

The `Jni` global provides JNI helper functions for working with Java objects in hooks.

### `Jni.newStringUTF(str)`

Create a new Java String from a Lua string. Returns a raw object pointer that can be used as a return value in Java hooks.

```lua
local jstr = Jni.newStringUTF("Hello from Lua!")
return jstr  -- Use in onLeave to replace return value
```

**Parameters:**
- `str` - Lua string to convert

**Returns:** Raw object pointer (integer) for the new Java String

### `Jni.getStringUTF(ref)`

Get the content of a Java String as a Lua string.

```lua
local content = Jni.getStringUTF(args[1])
if content then
    print("String content: " .. content)
end
```

**Parameters:**
- `ref` - Raw object pointer or JNI reference to a String

**Returns:** Lua string with the content, or `nil` if invalid

### `Jni.getStringLength(ref)`

Get the length of a Java String.

```lua
local len = Jni.getStringLength(args[1])
print("String length: " .. len)
```

**Parameters:**
- `ref` - Raw object pointer or JNI reference to a String

**Returns:** Integer length of the string

### `Jni.deleteGlobalRef(ref)`

Delete a global JNI reference to free memory.

```lua
Jni.deleteGlobalRef(globalRef)
```

**Parameters:**
- `ref` - Global reference to delete

---

## JNI Signature Reference

Common JNI type signatures:

| Java Type | JNI Signature |
|-----------|---------------|
| `void` | `V` |
| `boolean` | `Z` |
| `byte` | `B` |
| `char` | `C` |
| `short` | `S` |
| `int` | `I` |
| `long` | `J` |
| `float` | `F` |
| `double` | `D` |
| `String` | `Ljava/lang/String;` |
| `Object` | `Ljava/lang/Object;` |
| `int[]` | `[I` |
| `String[]` | `[Ljava/lang/String;` |

**Method signature format:** `(ParameterTypes)ReturnType`

**Examples:**
```lua
-- void method()
"()V"

-- int method(int x, int y)
"(II)I"

-- String method(String s)
"(Ljava/lang/String;)Ljava/lang/String;"

-- void method(int[] arr, boolean flag)
"([IZ)V"

-- Object method(String name, int count)
"(Ljava/lang/String;I)Ljava/lang/Object;"
```
