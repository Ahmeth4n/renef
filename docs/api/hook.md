---
title: Hook API
layout: default
parent: Lua API Reference
nav_order: 3
---

# Hook API

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
- `callbacks` - Table with `onEnter` and/or `onLeave` functions

**onEnter arguments:**
- `args` - Table with function arguments (args[0], args[1], ...)
- Arguments can be modified by assignment

**onLeave arguments:**
- `retval` - Return value from function
- Return a value to replace the original return value

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
        print(string.format("    this: 0x%x", args[0]))
        print(string.format("    param1: 0x%x", args[1]))
    end,
    onLeave = function(retval)
        print(string.format("[*] Original return: 0x%x", retval))
        
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

**Java hook arguments (`onEnter`):**
- `args[0]` - ArtMethod pointer (internal, not useful to scripts)
- `args[1]` - `this` pointer (instance methods) or first parameter (static methods)
- `args[2..n]` - Method parameters as raw pointers
- `args.class` - Class name (string)
- `args.method` - Method name (string)
- `args.signature` - JNI signature (string)
- `args.isStatic` - Whether method is static (boolean)
- `args.skip` - Set to `true` to skip calling the original method entirely

Arguments are modifiable: `args[2] = newValue` will change the parameter passed to the original method.

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
| integer | Sets x0 register directly |
| boolean (`true`/`false`) | Sets x0 to 1 or 0 |
| `{__jni_type="string", value="..."}` | Creates a new Java String and returns it |
| `{__jni_type="int", value=N}` | Sets x0 to N |
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
