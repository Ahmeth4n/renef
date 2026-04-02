---
title: Syscall API
layout: default
parent: Lua API Reference
nav_order: 8
---

# Syscall API

The `Syscall` global provides a programmatic interface for tracing syscalls from Lua scripts. It uses PLT/GOT hooking to intercept libc function calls without ptrace.

## `Syscall.trace(...)`

Start tracing one or more syscalls by name. Supports optional configuration table for caller filtering and custom callbacks.

```lua
-- Trace specific syscalls
Syscall.trace("openat", "read", "write", "close")

-- Filter by caller library
Syscall.trace("openat", "read", { caller = "libnative.so" })

-- Trace by category
Syscall.trace({ category = "file" })
Syscall.trace({ category = "network" })
```

**Parameters:**
- `...` - One or more syscall names as strings
- Last argument can be a config table with:
  - `caller` - Filter traces to calls from a specific library
  - `category` - Trace all syscalls in a category (`file`, `network`, `memory`, `process`, `ipc`)
  - `onCall` - Custom Lua callback for syscall entry
  - `onReturn` - Custom Lua callback for syscall return

**Default output** (when no callbacks are set):
```
[tid:22137] openat(AT_FDCWD, "/data/data/com.app/file.txt", O_RDONLY, 0644) = 3
[tid:22137] read(3</data/data/com.app/file.txt>, 0x7fe42f5488, 4096) = 128
[tid:22137] close(3) = 0
```

---

## `Syscall.trace()` with Custom Callbacks

```lua
Syscall.trace("openat", {
    onCall = function(info)
        -- info.name      = "openat"
        -- info.tid       = thread ID
        -- info.formatted = full formatted string
        -- info.args      = {arg1, arg2, ...} raw values
        print(info.formatted)
    end,
    onReturn = function(info)
        -- info.name    = "openat"
        -- info.tid     = thread ID
        -- info.retval  = return value
        -- info.errno_str = error string (only if retval < 0)
        if info.retval < 0 then
            print("FAILED: " .. info.errno_str)
        end
    end
})
```

**`onCall` info table:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Syscall name |
| `tid` | integer | Thread ID |
| `formatted` | string | Pre-formatted output string |
| `args` | table | Raw argument values (integer array) |

**`onReturn` info table:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Syscall name |
| `tid` | integer | Thread ID |
| `retval` | integer | Return value |
| `errno_str` | string | Error description (only when retval < 0) |

### Argument Mutation

Modify syscall arguments before execution by writing to `info.args`:

```lua
Syscall.trace("ioctl", {
    onCall = function(info)
        local orig_cmd = info.args[2]
        info.args[2] = 0x1234  -- replace ioctl command
        print(string.format("ioctl cmd 0x%x -> 0x1234", orig_cmd))
    end
})
```

### Skip Original Syscall

Prevent the original syscall from executing by setting `info.skip = true`. You can also set a fake return value:

```lua
Syscall.trace("access", {
    onCall = function(info)
        info.skip = true    -- don't execute the real syscall
        info.retval = 0     -- fake success return value
        print("access() skipped, returning 0")
    end
})
```

{: .note }
> When `skip = true`, the syscall never reaches the kernel. The `onReturn` callback still fires with the fake `retval`.

### Return Value Override

Override the return value from `onReturn` by returning a value:

```lua
Syscall.trace("access", {
    onReturn = function(info)
        if info.retval < 0 then
            print("access() failed, overriding to success")
            return 0  -- override return value
        end
    end
})
```

**`onCall` info table (extended):**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Syscall name |
| `tid` | integer | Thread ID |
| `formatted` | string | Pre-formatted output string |
| `args` | table | Raw argument values (read/write) |
| `skip` | boolean | Set to `true` to skip original syscall |
| `retval` | integer | Fake return value (only used when `skip = true`) |

**`onReturn` info table (extended):**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Syscall name |
| `tid` | integer | Thread ID |
| `retval` | integer | Actual (or fake) return value |
| `errno_str` | string | Error description (only when retval < 0) |

Return an integer from `onReturn` to override the return value. Return `nil` (or nothing) to keep the original.

---

### Stack Trace in Syscall Callbacks

Use `Thread.backtrace()` inside `onCall`/`onReturn` callbacks to see who triggered the syscall:

```lua
Syscall.trace("openat", {
    onCall = function(info)
        print(info.formatted)
        print(Thread.backtrace())
    end
})
```

---

## `Syscall.traceAll()`

Trace all supported syscalls at once.

```lua
Syscall.traceAll()
```

{: .warning }
> Tracing all syscalls generates a large volume of output and may impact application performance. Use category or specific syscall tracing when possible.

---

## `Syscall.untrace(name, ...)`

Stop tracing one or more syscalls. Restores the original GOT entries.

```lua
Syscall.untrace("openat")
Syscall.untrace("openat", "read", "write")
```

**Parameters:**
- `name, ...` - One or more syscall names to stop tracing

**Returns:** Integer (number of traces removed)

---

## `Syscall.stop()`

Stop all active syscall tracing. Restores all GOT entries and frees hook resources.

```lua
Syscall.stop()
```

**Output:**
```
Syscall tracing stopped
```

---

## `Syscall.list([category])`

List all supported syscall definitions, optionally filtered by category.

```lua
-- List all
Syscall.list()

-- List by category
Syscall.list("file")
Syscall.list("network")
```

---

## `Syscall.active()`

Show the number of currently active syscall traces.

```lua
Syscall.active()
```

**Output:**
```
Active traces: 3
```

---

## Supported Categories

| Category | Description | Syscalls |
|----------|-------------|----------|
| `file` | File I/O operations | openat, open, close, read, write, lseek, pread64, pwrite64, fstat, stat, access, readlink, rename, unlink, mkdir, chmod |
| `network` | Network socket operations | socket, connect, bind, listen, accept4, sendto, recvfrom |
| `memory` | Memory management | mmap, munmap, mprotect |
| `process` | Process lifecycle | fork, execve, kill, getpid, getuid, exit_group |
| `ipc` | Inter-process communication | ioctl, fcntl, dup, dup2, pipe |

---

## Usage with `watch`

Since syscall tracing outputs asynchronously (from any thread in the target process), use the `watch` command in the renef shell to see output in real-time:

```bash
renef> exec Syscall.trace("openat", "read", "write", "close")
Tracing 4 syscall(s)
renef> watch
[tid:22137] openat(AT_FDCWD, "/data/data/com.app/config.json", O_RDONLY, 0644) = 5
[tid:22137] read(5</data/data/com.app/config.json>, 0x7183361000, 4096) = 256
[tid:22137] close(5) = 0
# Press 'q' to exit watch
renef> exec Syscall.stop()
```
