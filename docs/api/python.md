---
title: Python API Reference
layout: default
parent: Lua API Reference
nav_order: 7
---

# Python API Reference

The Python binding provides a complete interface to Renef's functionality via `librenef.so`.

---

## Installation

```bash
# Build the shared library
cd build
cmake ..
make renef_shared

# The library will be at build/librenef.so
```

---

## Quick Start

```python
from renef import Renef

# Initialize
r = Renef()

# Spawn and inject into app
session = r.spawn('com.example.app')
print(f"Attached to PID: {session.pid}")

# Use APIs
base = session.Module.find('libc.so')
print(f"libc.so base: 0x{base:x}")

# Execute Lua code
ok, out, err = session.eval('print("Hello from Lua!")')

# Clean up
session.close()
```

---

## Renef Class

Main entry point for creating sessions.

### `Renef(library_path=None)`

Initialize the Renef client.

```python
from renef import Renef

# Auto-detect library path
r = Renef()

# Or specify path
r = Renef('/path/to/librenef.so')
```

**Parameters:**
- `library_path` (optional) - Path to librenef.so. Auto-detected if not provided.

---

### `Renef.spawn(package, hook_type=0)`

Spawn app and inject agent.

```python
session = r.spawn('com.example.app')
session = r.spawn('com.example.app', hook_type=1)  # PLT hook
```

**Parameters:**
- `package` - Package name (e.g. "com.example.app")
- `hook_type` - 0=trampoline (default), 1=PLT

**Returns:** `RenefSession` or `None` on failure

---

### `Renef.attach(pid, hook_type=0)`

Attach to running process.

```python
session = r.attach(12345)
```

**Parameters:**
- `pid` - Process ID
- `hook_type` - 0=trampoline (default), 1=PLT

**Returns:** `RenefSession` or `None` on failure

---

## RenefSession Class

Represents an active session with a target process.

### Properties

#### `session.pid`

Get target process ID.

```python
print(f"Target PID: {session.pid}")
```

#### `session.Module`

Access Module API.

```python
base = session.Module.find('libc.so')
```

#### `session.Memory`

Access Memory API.

```python
val = session.Memory.read_u32(0x12345678)
```

#### `session.Thread`

Access Thread API.

```python
tid = session.Thread.id()
```

---

### Methods

#### `session.eval(lua_code)`

Execute Lua code on the target.

```python
ok, output, error = session.eval('print(1 + 1)')
if ok:
    print(f"Output: {output}")
else:
    print(f"Error: {error}")
```

**Parameters:**
- `lua_code` - Lua code to execute

**Returns:** Tuple of `(success: bool, output: str, error: str)`

---

#### `session.load_script(path)`

Load and execute a Lua script file.

```python
ok, out, err = session.load_script('scripts/ssl_bypass.lua')
```

**Parameters:**
- `path` - Path to Lua script file

**Returns:** Tuple of `(success: bool, output: str, error: str)`

---

#### `session.memscan(pattern)`

Scan memory for hex pattern.

```python
ok, results, err = session.memscan('FD 7B ?? A9')
```

**Parameters:**
- `pattern` - Hex pattern with `??` wildcards

**Returns:** Tuple of `(success: bool, output: str, error: str)`

---

#### `session.hook(lib, offset, on_enter=None, on_leave=None)`

Install native hook.

```python
# Hook with onEnter
session.hook('libc.so', 0x1234, on_enter='print(args[0])')

# Hook with both callbacks
session.hook('libc.so', 0x1234,
    on_enter='print("enter:", args[0])',
    on_leave='print("leave:", retval)'
)
```

**Parameters:**
- `lib` - Library name
- `offset` - Offset from library base
- `on_enter` - Lua code for onEnter callback
- `on_leave` - Lua code for onLeave callback

**Returns:** `0` on success, `-1` on failure

---

#### `session.hook_java(class_name, method_name, signature, on_enter=None, on_leave=None)`

Install Java method hook.

```python
session.hook_java(
    'com/example/MainActivity',
    'secretMethod',
    '(Ljava/lang/String;)V',
    on_enter='print("Method called!")'
)
```

**Parameters:**
- `class_name` - Java class in JNI format (e.g. "com/example/Class")
- `method_name` - Method name
- `signature` - JNI method signature
- `on_enter` - Lua code for onEnter callback
- `on_leave` - Lua code for onLeave callback

**Returns:** `0` on success, `-1` on failure

---

#### `session.unhook(hook_id)`

Remove hook by ID.

```python
session.unhook(0)
```

**Returns:** `0` on success, `-1` on failure

---

#### `session.hooks()`

List active hooks.

```python
print(session.hooks())
```

**Returns:** String listing all active hooks

---

#### `session.close()`

Close the session.

```python
session.close()
```

---

## Module API

Access loaded libraries/modules.

### `session.Module.find(name)`

Find module base address.

```python
base = session.Module.find('libc.so')
if base:
    print(f"libc.so @ 0x{base:x}")
```

**Returns:** Base address as `int`, or `0` if not found

---

### `session.Module.list()`

List all loaded modules.

```python
modules = session.Module.list()
for m in modules:
    print(f"0x{m['base']:x} {m['name']}")
```

**Returns:** List of dicts with `base` and `name` keys

---

### `session.Module.exports(name)`

Get exported symbols from module.

```python
exports = session.Module.exports('libc.so')
for e in exports[:10]:
    print(f"0x{e['offset']:x} {e['name']}")
```

**Returns:** List of dicts with `offset` and `name` keys

---

### `session.Module.symbols(name)`

Get all symbols from module.

```python
symbols = session.Module.symbols('libc.so')
```

**Returns:** List of dicts with `offset` and `name` keys

---

## Memory API

Read and write target process memory.

### Read Functions

#### `session.Memory.read(addr, size)`

Read raw bytes.

```python
data = session.Memory.read(0x7f8a1c2b0, 16)
if data:
    print(data.hex())
```

**Returns:** `bytes` or `None`

---

#### `session.Memory.read_u8(addr)` / `read_u16` / `read_u32` / `read_u64`

Read unsigned integers.

```python
byte = session.Memory.read_u8(addr)
word = session.Memory.read_u16(addr)
dword = session.Memory.read_u32(addr)
qword = session.Memory.read_u64(addr)
```

**Returns:** Integer value

---

#### `session.Memory.read_string(addr, max_len=256)`

Read null-terminated string.

```python
s = session.Memory.read_string(0x7f8a1c2b0)
s = session.Memory.read_string(0x7f8a1c2b0, max_len=1024)
```

**Returns:** String or `None`

---

### Write Functions

#### `session.Memory.write(addr, data)`

Write raw bytes.

```python
session.Memory.write(addr, b'\x90\x90\x90\x90')
```

**Returns:** Number of bytes written, or `-1` on error

---

#### `session.Memory.write_u8(addr, val)` / `write_u16` / `write_u32` / `write_u64`

Write unsigned integers.

```python
session.Memory.write_u8(addr, 0x90)
session.Memory.write_u32(addr, 0xDEADBEEF)
```

**Returns:** `0` on success, `-1` on failure

---

### `session.Memory.scan(pattern)`

Scan memory for pattern.

```python
ok, results, err = session.Memory.scan('DE AD BE EF')
```

**Returns:** Tuple of `(success, output, error)`

---

## Thread API

Thread-related functions.

### `session.Thread.id()`

Get current thread ID.

```python
tid = session.Thread.id()
print(f"Thread ID: {tid}")
```

**Returns:** Thread ID as `int`

---

### `session.Thread.backtrace()`

Get stack backtrace.

```python
frames = session.Thread.backtrace()
for frame in frames:
    print(frame)
```

**Returns:** List of frame strings

---

## Examples

### SSL Pinning Bypass

```python
from renef import Renef

r = Renef()
session = r.spawn('com.example.app')

# Load bypass script
session.load_script('scripts/ssl_bypass.lua')

# Or hook directly
session.hook_java(
    'com/example/CertPinner',
    'check',
    '(Ljava/lang/String;)Z',
    on_leave='return 1'  # Always return true
)
```

### Memory Patching

```python
from renef import Renef

r = Renef()
session = r.spawn('com.example.game')

# Find library
base = session.Module.find('libgame.so')

# Read original value
original = session.Memory.read_u32(base + 0x1234)
print(f"Original: 0x{original:x}")

# Patch to NOP (ARM64)
session.Memory.write_u32(base + 0x1234, 0xD503201F)
```

### Function Hooking

```python
from renef import Renef

r = Renef()
session = r.spawn('com.example.app')

# Find function offset
exports = session.Module.exports('libtarget.so')
for e in exports:
    if 'encrypt' in e['name'].lower():
        print(f"Found: {e['name']} @ 0x{e['offset']:x}")

        # Hook it
        session.hook('libtarget.so', e['offset'],
            on_enter='print("encrypt called with:", args[0])',
            on_leave='print("encrypt returned:", retval)'
        )
        break
```

### Context Manager

```python
from renef import Renef

r = Renef()

# Auto-close on exit
with r.spawn('com.example.app') as session:
    base = session.Module.find('libc.so')
    print(f"libc @ 0x{base:x}")
# Session automatically closed here
```

### Batch Module Analysis

```python
from renef import Renef

r = Renef()
session = r.spawn('com.example.app')

# List all modules
modules = session.Module.list()
print(f"Loaded {len(modules)} modules\n")

# Find interesting libraries
for m in modules:
    if 'target' in m['name'] or 'crypto' in m['name']:
        print(f"\n=== {m['name']} ===")
        print(f"Base: 0x{m['base']:x}")

        exports = session.Module.exports(m['name'])
        print(f"Exports: {len(exports)}")
        for e in exports[:5]:
            print(f"  0x{e['offset']:x} {e['name']}")
```
