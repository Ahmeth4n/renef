---
title: Thread API
layout: default
parent: Lua API Reference
nav_order: 4
---

# Thread API

The `Thread` global provides thread information and stack unwinding for the current thread. `Thread.backtrace()` automatically detects hook context — when called from an `onEnter`/`onLeave` callback, it returns the **caller's** stack trace (skipping hook infrastructure frames).

{: .note }
> On ARM64 devices with PAC (Pointer Authentication Code) enabled (ARMv8.3+, Android 12+), return addresses on the stack contain cryptographic signature bits. Renef automatically strips PAC bits to produce clean addresses for `dladdr()` symbol resolution.

---

## `Thread.backtrace()`

Returns the current call stack as a table of frames. When called inside a hook callback (`onEnter`/`onLeave`), it automatically starts from the **hooked function's caller** — not from the hook handler itself.

```lua
-- Simple: print() automatically formats the backtrace
hook("libc.so", fopen_offset, {
    onEnter = function(args)
        print(Thread.backtrace())
    end
})

-- Programmatic: use as a table for filtering, searching, etc.
hook("libc.so", fopen_offset, {
    onEnter = function(args)
        local bt = Thread.backtrace()
        for _, f in ipairs(bt) do
            if f.module == "libnative.so" then
                print("Called from libnative.so at offset " .. string.format("0x%x", f.offset))
            end
        end
    end
})
```

**Output:**
```
  #01  libsrv_um.so  +0x36a98
  #02  libsrv_um.so  PVRSRVCreateAppHintState
  #03  vulkan.powervr.so  +0xa5fe8
  #04  libhwui.so  +0x36e198
  #05  libhwui.so  +0x36f86c
  #06  libutils.so  _ZN7android6Thread11_threadLoopEPv
  #07  libc.so  +0x8a318
  #08  libc.so  +0x7b1f8
```

**Parameters:**
- `fp` (optional) - Frame pointer address to start unwinding from. If omitted:
  - Inside hook callback → starts from caller's frame pointer (automatic)
  - Outside hook → starts from current thread's frame pointer

**Returns:** Array table of frame tables, each containing:

| Field | Type | Description |
|-------|------|-------------|
| `index` | integer | Frame number (1-based) |
| `pc` | integer | Program counter (return address, PAC-stripped) |
| `symbol` | string or nil | Function name (if resolved via `dladdr`) |
| `module` | string or nil | Library filename (e.g., `libc.so`) |
| `path` | string or nil | Full library path |
| `base` | integer or nil | Library base address |
| `offset` | integer or nil | Offset from library base |

{: .note }
> `symbol` is only available for exported/dynamic symbols. Stripped binaries will show `nil`. Use `module + offset` for reliable identification — these can be used directly with `addr2line` or IDA.

---

### Works with all hook types

`Thread.backtrace()` works in native hooks, Java hooks, and syscall trace callbacks:

```lua
-- Native hook
hook("libc.so", offset, {
    onEnter = function(args)
        print(Thread.backtrace())
    end
})

-- Syscall trace
Syscall.trace("openat", {
    onCall = function(info)
        print(info.formatted)
        print(Thread.backtrace())
    end
})
```

---

## `Thread.id()`

Returns the current thread ID.

```lua
local tid = Thread.id()
print("Current thread: " .. tid)
```

**Returns:** Integer (thread ID via `gettid` syscall)
