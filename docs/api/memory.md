---
title: Memory API
layout: default
parent: Lua API Reference
nav_order: 2
---

# Memory API

RENEF provides two memory APIs: the modern `mem` global and the legacy `Memory` global.

---

## mem API (Recommended)

The `mem` global provides advanced memory search and manipulation functions.

### `mem.search(pattern, [lib])`

Search memory for string or hex pattern with wildcard support.

```lua
-- String search
local results = mem.search("native")

-- Hex pattern search (IDA-style with wildcards)
local results = mem.search("FD 7B ?? A9")  -- ARM64 function prologue

-- Search in specific library only
local results = mem.search("C0 03 5F D6", "libc.so")  -- ret instruction in libc
```

**Parameters:**
- `pattern` - String or hex pattern (use `??` for wildcard bytes)
- `lib` (optional) - Library name to limit search scope

**Returns:** Table of results with fields:
- `lib` - Full library path
- `addr` - Absolute memory address
- `offset` - Offset from library base
- `hex` - Hex dump with context (matched pattern in brackets)
- `ascii` - ASCII representation

**Common ARM64 Patterns:**
```lua
-- Function prologue (stp x29, x30, [sp, #?])
mem.search("FD 7B ?? A9")

-- Return instruction
mem.search("C0 03 5F D6")

-- NOP instruction
mem.search("1F 20 03 D5")

-- Branch with link
mem.search("?? ?? ?? 94")
```

---

### `mem.dump(results)`

Pretty print search results to console.

```lua
local r = mem.search("native")
mem.dump(r)
```

**Output:**
```
[1] libandroid_runtime.so + 0x789de (0x724823a9de)
    69 6D 65 6F 75 74 [6E 61 74 69 76 65 ] 44 69 73 61
[2] libandroid_runtime.so + 0x78a18 (0x724823aa18)
    63 6F 70 65 64 [6E 61 74 69 76 65 ] 5F 67 65 74
```

---

### `mem.read(address, size)`

Read raw bytes from memory.

```lua
local data = mem.read(0x7f8a1c2b0, 16)

-- Print as hex
for i = 1, #data do
    io.write(string.format("%02X ", string.byte(data, i)))
end
```

**Returns:** String containing raw bytes (max 1MB)

---

### `mem.write(address, bytes)`

Write raw bytes to memory.

```lua
-- Write NOP instruction
mem.write(0x7f8a1c2b0, "\x1f\x20\x03\xd5")

-- Write multiple bytes
mem.write(addr, "\x00\x00\x00\x00")
```

**Returns:** `true` on success

---

### `mem.readU8(address)` / `mem.readU16(address)` / `mem.readU32(address)` / `mem.readU64(address)`

Read unsigned integer from memory.

```lua
local byte = mem.readU8(addr)      -- 1 byte
local word = mem.readU16(addr)     -- 2 bytes
local dword = mem.readU32(addr)    -- 4 bytes
local qword = mem.readU64(addr)    -- 8 bytes

print(string.format("Value: 0x%X", dword))
```

---

### `mem.writeU8(address, value)` / `mem.writeU16(address, value)` / `mem.writeU32(address, value)` / `mem.writeU64(address, value)`

Write unsigned integer to memory.

```lua
mem.writeU8(addr, 0x90)
mem.writeU16(addr, 0x9090)
mem.writeU32(addr, 0xDEADBEEF)
mem.writeU64(addr, 0x123456789ABCDEF0)
```

---

### `mem.readStr(address, [maxLen])`

Read null-terminated string from memory.

```lua
local str = mem.readStr(0x7f8a1c2b0)
local str = mem.readStr(0x7f8a1c2b0, 512)  -- max 512 bytes

print("String: " .. str)
```

**Parameters:**
- `address` - Memory address to read from
- `maxLen` (optional) - Maximum length to read (default: 256)

**Returns:** String up to null terminator

---

## Legacy Memory API

The `Memory` global provides basic memory operations for compatibility.

### `Memory.scan(pattern)`

Scan memory for exact byte pattern.

```lua
local pattern = "\xDE\xAD\xBE\xEF"
local results = Memory.scan(pattern)

for i, result in ipairs(results) do
    print(string.format("[%d] %s + 0x%x", i, result.library, result.offset))
end
```

**Returns:** Table with fields: `library`, `offset`, `hex`, `ascii`

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

### `Memory.read(address, size)`

Read raw bytes from memory.

```lua
local data = Memory.read(0x7f8a1c2b0, 16)
```

**Returns:** String containing raw bytes (max 4096 bytes)

---

### `Memory.readString(address)`

Read null-terminated string.

```lua
local str = Memory.readString(0x7f8a1c2b0)
```

**Returns:** String up to null terminator (max 1024 bytes) or `nil` if address is 0

---

## Examples

### Find and patch function

```lua
-- Find all ret instructions in target library
local rets = mem.search("C0 03 5F D6", "libtarget.so")
print("Found " .. #rets .. " ret instructions")
mem.dump(rets)

-- Patch first one to NOP
if #rets > 0 then
    mem.writeU32(rets[1].addr, 0xD503201F)  -- NOP
    print("Patched!")
end
```

### Read structure from memory

```lua
local base = Module.find("libtarget.so")
local struct_ptr = base + 0x1000

local field1 = mem.readU32(struct_ptr)
local field2 = mem.readU32(struct_ptr + 4)
local name = mem.readStr(struct_ptr + 8)

print(string.format("Field1: %d, Field2: %d, Name: %s", field1, field2, name))
```

### Search for encrypted strings

```lua
-- Search for XOR key pattern
local results = mem.search("DE AD BE EF")
for _, r in ipairs(results) do
    -- Read surrounding context
    local context = mem.read(r.addr - 16, 48)
    print(string.format("Found at %s + 0x%x", r.lib, r.offset))
end
```
