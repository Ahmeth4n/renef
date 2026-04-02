---
title: Memory API
layout: default
parent: Lua API Reference
nav_order: 2
---

# Memory API

The `Memory` global provides memory search, read, write, and patch functions.

---

## Search Functions

### `Memory.search(pattern, [lib])`

Search memory for string or hex pattern with wildcard support.

```lua
-- String search
local results = Memory.search("native")

-- Hex pattern search (IDA-style with wildcards)
local results = Memory.search("FD 7B ?? A9")  -- ARM64 function prologue

-- Search in specific library only
local results = Memory.search("C0 03 5F D6", "libc.so")  -- ret instruction in libc
```

**Parameters:**
- `pattern` - String or hex pattern (use `??` for wildcard bytes)
- `lib` (optional) - Library name to limit search scope

**Returns:** Table of results with fields:
- `library` - Full library path
- `addr` - Absolute memory address
- `offset` - Offset from library base
- `hex` - Hex dump with context (matched pattern in brackets)
- `ascii` - ASCII representation

**Common ARM64 Patterns:**
```lua
-- Function prologue (stp x29, x30, [sp, #?])
Memory.search("FD 7B ?? A9")

-- Return instruction
Memory.search("C0 03 5F D6")

-- NOP instruction
Memory.search("1F 20 03 D5")

-- Branch with link
Memory.search("?? ?? ?? 94")
```

---

### `Memory.scan(pattern, [lib])`

Alias for `Memory.search()`.

```lua
local results = Memory.scan("DEADBEEF")
```

---

### `Memory.dump(results)`

Pretty print search results to console.

```lua
local r = Memory.search("native")
Memory.dump(r)
```

**Output:**
```
[1] libandroid_runtime.so + 0x789de (0x724823a9de)
    69 6D 65 6F 75 74 [6E 61 74 69 76 65 ] 44 69 73 61
[2] libandroid_runtime.so + 0x78a18 (0x724823aa18)
    63 6F 70 65 64 [6E 61 74 69 76 65 ] 5F 67 65 74
```

---

## Hexdump

### `hexdump(target [, length])`

Frida-style hexdump. Works with any variable type. Also available as `Memory.hexdump()`.

```lua
-- Memory address + length
print(hexdump(0x7f000000, 128))

-- Binary string data
local data = Memory.read(addr, 256)
print(hexdump(data))

-- Hook argument (register value = address)
hook("libc.so", open_offset, {
    onEnter = function(args)
        print(hexdump(args[1], 64))  -- dump path string memory
    end
})

-- Java raw pointer
local obj = Java.use("android/app/ActivityThread")
    :call("currentApplication", "()Landroid/app/Application;")
print(hexdump(obj.raw, 128))

-- Byte table
print(hexdump({0x52, 0x45, 0x4e, 0x45, 0x46}))

-- With length limit on string
print(hexdump(long_string, 32))  -- only first 32 bytes
```

**Parameters:**
- `target` - Data to hexdump. Accepted types:
  - **integer** - Memory address (reads `length` bytes from this address)
  - **string** - Binary data (dumps the string contents)
  - **userdata** - Dereferences inner pointer (e.g. Java `instance.raw`)
  - **table** - Byte array `{0x41, 0x42, ...}`
- `length` (optional) - Number of bytes to dump (default: 256, max: 64KB)

**Returns:** Formatted string (does not print automatically -use `print()`)

**Output format:**
```
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
7f000000  48 65 6c 6c 6f 20 57 6f  72 6c 64 00 00 00 00 00  Hello World.....
7f000010  01 02 03 ff fe fd 00 00  00 00 00 00 00 00 00 00  ................
```

### `Memory.hexdump(target [, length])`

Alias for global `hexdump()`.

```lua
print(Memory.hexdump(addr, 64))
```

---

## Read Functions

### `Memory.read(address, size)`

Read raw bytes from memory.

```lua
local data = Memory.read(0x7f8a1c2b0, 16)

-- Print as hex
for i = 1, #data do
    io.write(string.format("%02X ", string.byte(data, i)))
end
```

**Returns:** String containing raw bytes (max 1MB)

---

### `Memory.readU8(address)` / `Memory.readU16(address)` / `Memory.readU32(address)` / `Memory.readU64(address)`

Read unsigned integer from memory.

```lua
local byte = Memory.readU8(addr)      -- 1 byte
local word = Memory.readU16(addr)     -- 2 bytes
local dword = Memory.readU32(addr)    -- 4 bytes
local qword = Memory.readU64(addr)    -- 8 bytes

print(string.format("Value: 0x%X", dword))
```

---

### `Memory.readStr(address, [maxLen])`

Read null-terminated string from memory.

```lua
local str = Memory.readStr(0x7f8a1c2b0)
local str = Memory.readStr(0x7f8a1c2b0, 512)  -- max 512 bytes

print("String: " .. str)
```

**Parameters:**
- `address` - Memory address to read from
- `maxLen` (optional) - Maximum length to read (default: 256)

**Returns:** String up to null terminator

---

### `Memory.readString(address, [maxLen])`

Alias for `Memory.readStr()`.

```lua
local str = Memory.readString(0x7f8a1c2b0)
```

**Returns:** String up to null terminator (max 1024 bytes) or `nil` if address is 0

---

## Write Functions

### `Memory.write(address, bytes)`

Write raw bytes to memory.

```lua
-- Write NOP instruction
Memory.write(0x7f8a1c2b0, "\x1f\x20\x03\xd5")

-- Write multiple bytes
Memory.write(addr, "\x00\x00\x00\x00")
```

**Returns:** `true` on success

---

### `Memory.writeU8(address, value)` / `Memory.writeU16(address, value)` / `Memory.writeU32(address, value)` / `Memory.writeU64(address, value)`

Write unsigned integer to memory.

```lua
Memory.writeU8(addr, 0x90)
Memory.writeU16(addr, 0x9090)
Memory.writeU32(addr, 0xDEADBEEF)
Memory.writeU64(addr, 0x123456789ABCDEF0)
```

---

### `Memory.patch(address, bytes)`

Patch memory at address. Automatically handles mprotect().

```lua
local addr = 0x7f8a1c2b0
local patch = "\x1f\x20\x03\xd5"  -- ARM64 NOP

local success, err = Memory.patch(addr, patch)
if success then
    print("Patched successfully")
else
    print("Patch failed: " .. err)
end
```

**Returns:** `true` on success, or `false, error_message` on failure

---

## Examples

### Find and patch function

```lua
-- Find all ret instructions in target library
local rets = Memory.search("C0 03 5F D6", "libtarget.so")
print("Found " .. #rets .. " ret instructions")
Memory.dump(rets)

-- Patch first one to NOP
if #rets > 0 then
    Memory.writeU32(rets[1].addr, 0xD503201F)  -- NOP
    print("Patched!")
end
```

### Read structure from memory

```lua
local base = Module.find("libtarget.so")
local struct_ptr = base + 0x1000

local field1 = Memory.readU32(struct_ptr)
local field2 = Memory.readU32(struct_ptr + 4)
local name = Memory.readStr(struct_ptr + 8)

print(string.format("Field1: %d, Field2: %d, Name: %s", field1, field2, name))
```

### Search for encrypted strings

```lua
-- Search for XOR key pattern
local results = Memory.search("DE AD BE EF")
for _, r in ipairs(results) do
    -- Read surrounding context
    local context = Memory.read(r.addr - 16, 48)
    print(string.format("Found at %s + 0x%x", r.library, r.offset))
end
```
