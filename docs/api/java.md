---
title: Java API
layout: default
parent: Lua API Reference
nav_order: 7
---

# Java API

{: .note }
Added in v0.3.1

The `Java` global provides runtime access to Java classes and methods from Lua scripts. It allows you to load classes, create instances, and call both static and instance methods using JNI.

---

## Java.use(class_name)

Load a Java class by name. Returns a class wrapper that can be used to call static methods or create instances.

```lua
local Build = Java.use("android/os/Build")
local String = Java.use("java/lang/String")
local MyClass = Java.use("com/example/app/MyClass")
```

**Parameters:**
- `class_name` - Fully qualified class name with `/` separators (e.g., `"android/os/Build"`)

**Returns:** `JavaClassWrapper` userdata on success, `nil` on failure

{: .note }
Uses `FindClass` first, then falls back to the application's `ClassLoader` for app-specific classes that aren't visible to the system classloader.

---

## wrapper:call(method_name, signature, ...)

Call a static method on a class wrapper.

```lua
local System = Java.use("java/lang/System")

-- No arguments
local time = System:call("currentTimeMillis", "()J")

-- With arguments
local String = Java.use("java/lang/String")
local str = String:call("valueOf", "(I)Ljava/lang/String;", 123)
-- str = "123"

local str2 = String:call("valueOf", "(Z)Ljava/lang/String;", true)
-- str2 = "true"
```

**Parameters:**
- `method_name` - Java method name
- `signature` - JNI method signature
- `...` - Method arguments (matching the signature)

**Returns:** Method return value converted to Lua type

---

## wrapper:new(signature, ...)

Create a new instance of a Java class.

```lua
local StringBuilder = Java.use("java/lang/StringBuilder")

-- Default constructor
local sb = StringBuilder:new("()V")

-- Constructor with arguments
local sb2 = StringBuilder:new("(Ljava/lang/String;)V", "Hello")
```

**Parameters:**
- `signature` - JNI constructor signature (defaults to `"()V"`)
- `...` - Constructor arguments (matching the signature)

**Returns:** `JavaInstance` userdata on success, `nil` on failure

---

## instance:call(method_name, signature, ...)

Call an instance method on a Java object.

```lua
local StringBuilder = Java.use("java/lang/StringBuilder")
local sb = StringBuilder:new("()V")

sb:call("append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", "Hello")
sb:call("append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", " World")

local result = sb:call("toString", "()Ljava/lang/String;")
-- result = "Hello World"
```

**Parameters:**
- `method_name` - Java method name
- `signature` - JNI method signature
- `...` - Method arguments

**Returns:** Method return value converted to Lua type

---

## JNI Signature Reference

JNI signatures describe method parameter types and return type.

**Format:** `(ParameterTypes)ReturnType`

| Signature | Java Type |
|-----------|-----------|
| `Z` | boolean |
| `B` | byte |
| `C` | char |
| `S` | short |
| `I` | int |
| `J` | long |
| `F` | float |
| `D` | double |
| `V` | void |
| `Lclass/name;` | Object |
| `[type` | Array |

**Examples:**

| Signature | Java Method |
|-----------|-------------|
| `()V` | `void method()` |
| `(I)V` | `void method(int)` |
| `()Ljava/lang/String;` | `String method()` |
| `(Ljava/lang/String;)V` | `void method(String)` |
| `(IZ)Ljava/lang/String;` | `String method(int, boolean)` |
| `(Ljava/lang/String;I)J` | `long method(String, int)` |

---

## Type Conversion

### Lua to Java (arguments)

| Lua Type | Java Types |
|----------|-----------|
| `number` (integer) | int, long, byte, short, char |
| `number` (float) | float, double |
| `boolean` | boolean |
| `string` | String |
| `JavaInstance` userdata | Object |

### Java to Lua (return values)

| Java Type | Lua Type |
|-----------|----------|
| int, long, byte, short, char | `integer` |
| float, double | `number` |
| boolean | `boolean` |
| String | `string` |
| Other objects | `JavaInstance` userdata |
| void | (nothing) |
| null | `nil` |

---

## instance.raw

Access the raw ART `mirror::Object*` pointer from a `JavaInstance` userdata. This is useful when you need to pass Java objects as raw pointers to hook callbacks (e.g., modifying arguments via `args[N] = value`).

```lua
local TrustManager = Java.use("javax/net/ssl/X509TrustManager")
local tm = TrustManager:new("()V")
print(string.format("Raw ART pointer: 0x%x", tm.raw))
```

**Returns:** Integer — raw ART `mirror::Object*` pointer (decoded from JNI global reference)

{: .warning }
Raw pointers are only valid while the object is alive. Do not cache them across GC cycles.

---

## Java.registerClass(definition)

Register a new Java class at runtime that implements one or more interfaces. Method calls on the registered class are dispatched to Lua callbacks.

```lua
local EmptyTrustManager = Java.registerClass({
    name = "com.renef.EmptyTrustManager",
    implements = {
        "javax/net/ssl/X509TrustManager"
    },
    methods = {
        checkClientTrusted = function(self, args)
            -- Do nothing (accept all)
        end,
        checkServerTrusted = function(self, args)
            -- Do nothing (accept all)
        end,
        getAcceptedIssuers = function(self, args)
            return nil
        end
    }
})
```

**Parameters:**
- `definition` - Table with:
  - `name` - Fully qualified class name with `.` separators
  - `implements` - Array of interface names with `/` separators
  - `methods` - Table mapping method names to Lua callback functions

**Returns:** `JavaInstance` userdata of the registered class

{: .note }
Uses a bridge DEX with `java.lang.reflect.Proxy` and an `InvocationHandler` that routes calls to the Lua callback registry.

---

## Java.array(type, elements)

Create a Java array from Lua values. Returns a `JavaInstance` userdata holding a `jobjectArray`.

```lua
-- Array of TrustManagers
local tm = EmptyTrustManager
local tm_array = Java.array("javax/net/ssl/TrustManager", { tm })

-- Array of strings
local str_array = Java.array("java/lang/String", { "hello", "world" })
```

**Parameters:**
- `type` - Element type as class name with `/` separators
- `elements` - Lua table (array) of elements. Supports `string`, `JavaInstance`, and `nil`.

**Returns:** `JavaInstance` userdata wrapping the `jobjectArray`

---

## Complete Example

```lua
-- Get application package name
local ActivityThread = Java.use("android/app/ActivityThread")
local app = ActivityThread:call("currentApplication", "()Landroid/app/Application;")
local pkg = app:call("getPackageName", "()Ljava/lang/String;")
print("Package: " .. pkg)

-- StringBuilder example
local StringBuilder = Java.use("java/lang/StringBuilder")
local sb = StringBuilder:new("()V")
sb:call("append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", "Hello")
sb:call("append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", " from Renef!")
local result = sb:call("toString", "()Ljava/lang/String;")
print(result)  -- "Hello from Renef!"

-- Static method with different argument types
local String = Java.use("java/lang/String")
print(String:call("valueOf", "(I)Ljava/lang/String;", 42))       -- "42"
print(String:call("valueOf", "(Z)Ljava/lang/String;", false))    -- "false"
print(String:call("valueOf", "(D)Ljava/lang/String;", 3.14))     -- "3.14"

-- Get system property
local System = Java.use("java/lang/System")
local sdk = System:call("getProperty", "(Ljava/lang/String;)Ljava/lang/String;", "ro.build.version.sdk")
print("SDK: " .. tostring(sdk))
```

{: .warning }
Java objects returned as `JavaInstance` userdata are automatically cleaned up by Lua's garbage collector. Do not store references longer than needed to avoid memory leaks.
