---
title: Memory Operations
layout: default
parent: Command Reference
nav_order: 4
---

# Memory Operations (CLI)

## `ms <pattern>`

Scan memory for hex pattern or string in all readable .so regions.

```bash
# Scan for hex bytes
ms DEADBEEF

# Scan for ARM64 ret instruction
ms C0035FD6

# Scan for string (as hex)
ms 4A617661    # "Java"
```

**Output:**
```
Found 2 match(es):
------------------------------------------------------------
[1] /system/lib64/libc.so + 0x1a2b0 (addr: 0x7f8a1c2b0)
    Hex:   01 02 03 [DE AD BE EF] 90 90 90 90
    ASCII: ....[....]....
[2] /data/app/com.example/lib/arm64/libapp.so + 0x5f80 (addr: 0x7f9b3f80)
    Hex:   FF FF [DE AD BE EF] 00 00
    ASCII: ..[....]..
------------------------------------------------------------
```

---

## `msi <pattern>`

Interactive memory scan with TUI. Allows selecting results and performing actions.

```bash
msi DEADBEEF
```

**Interactive Interface:**
```
Memory Scan Results (2 matches)
────────────────────────────────────────
[1] libc.so + 0x1a2b0
[2] libapp.so + 0x5f80
────────────────────────────────────────
Actions: [d]ump [p]atch [w]atch [c]opy [q]uit
```

**Actions:**
- `d` - Dump memory at selected address
- `p` - Patch bytes at selected address
- `w` - Watch memory for changes
- `c` - Copy address to clipboard
- `q` - Quit interactive mode

---

## `md <address> <size> [-d]`

Dump memory at address. Use `-d` flag to disassemble as ARM64 code.

```bash
# Hex dump (256 bytes)
md 0x7f8a1c2b0 256

# Disassemble as ARM64
md 0x7f8a1c2b0 64 -d
```

**Hex Dump Output:**
```
Memory at 0x7f8a1c2b0 (256 bytes):
0x7f8a1c2b0:  01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10  |................|
0x7f8a1c2c0:  de ad be ef 90 90 90 90 00 00 00 00 ff ff ff ff  |................|
0x7f8a1c2d0:  fd 7b bf a9 fd 03 00 91 00 00 00 94 fd 7b c1 a8  |.{...........{..|
```

**Disassembly Output:**
```
Memory at 0x7f8a1c2b0 (64 bytes):
0x7f8a1c2b0:  fd 7b bf a9    stp x29, x30, [sp, #-0x10]!
0x7f8a1c2b4:  fd 03 00 91    mov x29, sp
0x7f8a1c2b8:  00 00 00 94    bl #0x7f8a1d000
0x7f8a1c2bc:  fd 7b c1 a8    ldp x29, x30, [sp], #0x10
0x7f8a1c2c0:  c0 03 5f d6    ret
```

---

## Lua Script Integration

For more advanced memory operations, use the `exec` command with Lua scripts:

```bash
# String search with wildcards
exec r = mem.search("native") mem.dump(r)

# Pattern search (ARM64)
exec r = mem.search("FD 7B ?? A9") mem.dump(r)

# Search in specific library
exec r = mem.search("C0 03 5F D6", "libc.so") mem.dump(r)

# Read memory
exec print(string.format("0x%X", mem.readU32(0x7f8a1c2b0)))

# Write memory
exec mem.writeU32(0x7f8a1c2b0, 0xD503201F)
```

See [Lua Memory API](../lua-api/memory.md) for full documentation.

---

## Common ARM64 Patterns

| Pattern | Description |
|---------|-------------|
| `FD7B??A9` | Function prologue (`stp x29, x30, [sp, #?]`) |
| `C0035FD6` | Return instruction (`ret`) |
| `1F2003D5` | NOP instruction |
| `??????94` | Branch with link (`bl`) |
| `??????97` | Branch with link (`bl`, different range) |
| `00000014` | Unconditional branch (`b`) |

---

## Tips

1. **Hex vs String**: The CLI `ms` command expects hex. For string search, convert to hex first or use Lua:
   ```bash
   exec mem.dump(mem.search("mystring"))
   ```

2. **Large Searches**: Pattern search is limited to 50MB to prevent timeout. Use library filter for large apps:
   ```bash
   exec mem.dump(mem.search("pattern", "libtarget.so"))
   ```

3. **Address Format**: All addresses are displayed and expected in hexadecimal with `0x` prefix.

4. **Wildcards**: Only available via Lua API. Use `??` for any byte:
   ```bash
   exec mem.dump(mem.search("FD 7B ?? A9"))
   ```
