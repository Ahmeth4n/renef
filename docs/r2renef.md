---
title: r2renef
layout: default
nav_order: 11.5
---

# r2renef

[r2renef](https://github.com/ahmeth4n/r2renef) is a Radare2 IO plugin that connects Radare2 to Renef, enabling live static analysis on Android processes. Use all of r2's disassembly, hex dump, and scripting capabilities on a running Android process through Renef's dynamic instrumentation.

---

## Features

- **Live Memory Analysis** — Read/write process memory through Radare2
- **Full r2 Integration** — Use `pd`, `px`, `pf`, `/x` and all r2 commands on live processes
- **Renef Command Passthrough** — Access Renef's Lua API and CLI commands via `:` prefix
- **Script Loading** — Load Lua hook scripts directly from r2
- **Hook Watch** — Monitor hook callbacks in real-time
- **Spawn/Attach** — Support both spawning new processes and attaching by PID

---

## Installation

### Requirements

- Radare2 >= 5.8.0
- Renef server running on target Android device
- ADB for port forwarding

### Build & Install

```bash
git clone https://github.com/ahmeth4n/r2renef
cd r2renef
make
make install
```

Or with Meson:

```bash
meson setup build
ninja -C build
ninja -C build install
```

The plugin is installed to your Radare2 user plugins directory automatically.

---

## Quick Start

```bash
# 1. Start Renef server on Android device
adb shell /data/local/tmp/renef_server

# 2. Setup port forwarding
adb forward tcp:1907 tcp:1907

# 3. Open target app in r2
r2 renef://spawn/com.example.app

# Or attach to a running process
r2 renef://attach/12345
```

### URI Format

```
renef://spawn/<package-name>
renef://attach/<pid>
```

---

## Radare2 Commands

Once connected, standard r2 commands work on the live process memory:

```bash
# Seek to an address
[0x00000000]> s 0x7f8a1c000

# Disassemble 20 instructions
[0x7f8a1c000]> pd 20

# Print 64 bytes hex dump
[0x7f8a1c000]> px 64

# Disassemble current function
[0x7f8a1c000]> pdf

# Search for hex pattern
[0x7f8a1c000]> /x 504b0304

# Write bytes
[0x7f8a1c000]> w \x1f\x20\x03\xd5
```

---

## Renef Commands

Renef-specific commands are prefixed with `:` in the r2 shell:

```bash
# List installed apps
[0x00000000]> :la

# List loaded modules
[0x00000000]> :exec Module.list()

# Find a library base address
[0x00000000]> :exec Module.find("libc.so")

# Memory dump
[0x00000000]> :md 0x7f8a1c2b0 64

# Memory search
[0x00000000]> :ms DEADBEEF

# Execute any Lua code
[0x00000000]> :exec print("Hello from r2!")
```

### Loading Scripts

Load Lua hook scripts from r2:

```bash
# Load a script
[0x00000000]> :l /path/to/hook.lua

# Load SSL bypass
[0x00000000]> :l scripts/ssl_unpin.lua
```

### Watching Hook Output

Monitor hook callbacks in real-time:

```bash
[0x00000000]> :watch
📡 Watching hook output...
[+] malloc called
    size: 0x100
[-] Returning: 0x7f9b4000
# Press Ctrl+C to stop watching
```

---

## Example Workflow

### Analyzing a Native Library

```bash
# Spawn target app
$ r2 renef://spawn/com.example.app

# Find the target library
[0x00000000]> :exec Module.find("libtarget.so")
0x7f8a1c000

# Seek to library base
[0x00000000]> s 0x7f8a1c000

# Disassemble the first function
[0x7f8a1c000]> pd 30

# Look for interesting patterns
[0x7f8a1c000]> /x FD7BBFA9    # ARM64 function prologues

# Dump hex around a match
[0x7f8a1c100]> px 128
```

### Hooking and Patching

```bash
# Find a function, disassemble it
[0x7f8a1c000]> s 0x7f8a1c000 + 0x5678
[0x7f8a21678]> pdf

# Load a hook script
[0x7f8a21678]> :l hooks/trace_func.lua

# Watch hook output
[0x7f8a21678]> :watch

# Patch a branch to NOP
[0x7f8a21678]> w \x1f\x20\x03\xd5

# Verify the patch
[0x7f8a21678]> pd 1
```

### Combining r2 Analysis with Renef Hooking

```bash
# List exports of a library
[0x00000000]> :exec for _, s in ipairs(Module.exports("libtarget.so")) do print(string.format("0x%x %s", s.offset, s.name)) end

# Seek to an exported function
[0x00000000]> s 0x7f8a1c000 + 0x1234

# Disassemble it
[0x7f8a1d234]> pdf

# Hook it from r2
[0x7f8a1d234]> :exec hook("libtarget.so", 0x1234, { onEnter = function(args) print("called!") end })

# Watch the output
[0x7f8a1d234]> :watch
```

---

## Comparison: r2renef vs r2frida

| | r2renef | r2frida |
|---|---|---|
| **Backend** | Renef | Frida |
| **Platform** | Android ARM64 | Multi-platform |
| **Scripting** | Lua | JavaScript |
| **Hook commands** | `:exec hook(...)` | `\di`, `\dif` |
| **Memory read** | Native r2 IO | Native r2 IO |
| **Java hooks** | `:exec hook("class", ...)` | `\dij` |
| **Root required** | Yes (or gadget mode) | Yes (or gadget) |

---

## Roadmap

- [x] Basic IO (read/seek)
- [x] Renef command passthrough
- [x] Script loading
- [x] Hook watch
- [x] Memory write support
- [ ] Debug plugin (breakpoints, stepping)
- [ ] Register access
- [ ] Maps/sections integration
