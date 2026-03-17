---
title: renef-strace
layout: default
nav_order: 11.6
---

# renef-strace

`renef-strace` is a standalone syscall tracer for Android processes. It uses PLT/GOT hooking to intercept libc function calls in real-time — no ptrace required.

Also available as a built-in command in the renef shell and as a [Lua API]({% link docs/api/syscall.md %}).

---

## Build

```bash
make renef-strace
```

The binary will be at `build/renef-strace`.

---

## Standalone Usage

```bash
# Trace specific syscalls
renef-strace -p <pid> open,read,write,close

# Trace by category
renef-strace -p <pid> -c file
renef-strace -p <pid> -c network

# Trace all supported syscalls
renef-strace -p <pid> -a

# Filter by caller library
renef-strace -p <pid> open,read,write -f libnative.so

# List available syscalls
renef-strace -p <pid> --list

# Stop tracing
renef-strace -p <pid> --stop
```

Press `Ctrl+C` to stop tracing gracefully. Hooks are automatically cleaned up on exit.

---

## Shell Usage

When connected to a target via the renef shell, use as a built-in command (no `-p` needed):

```bash
# Trace specific syscalls
renef-strace open,read,write,close

# Trace by category
renef-strace -c file
renef-strace -c network
renef-strace -c memory
renef-strace -c process
renef-strace -c ipc

# Trace all
renef-strace -a

# Filter by caller library
renef-strace open,read,write -f libnative.so

# List supported syscalls
renef-strace --list

# Show active traces
renef-strace --active

# Stop tracing
renef-strace --stop
```

---

## Output

```
Tracing syscalls... (press Ctrl+C or send any key to stop)
[tid:22137] openat(AT_FDCWD, "/data/data/com.app/file.txt", O_RDONLY, 0644) = 3
[tid:22137] read(3</data/data/com.app/file.txt>, 0x7fe42f5488, 4096) = 128
[tid:22137] write(101<anon_inode:[eventfd]>, 0x7fe42f5398, 8) = 8
[tid:22137] close(3) = 0
```

Each trace line follows the format:

```
[tid:<thread_id>] syscall_name(arg1, arg2, ...) = return_value
```

**Argument formatting:**
- **File descriptors** resolve to paths: `3</data/data/com.app/file.txt>`
- **AT_FDCWD** shown for directory-relative calls: `AT_FDCWD`
- **Strings** shown quoted with truncation: `"/data/data/com.app/..."` (max 64 chars)
- **Open flags** decoded: `O_RDONLY|O_CREAT|O_TRUNC`
- **Mode** shown as octal: `0644`
- **Pointers** shown as hex: `0x7fe42f5488`
- **Error returns** include errno: `= -1 (Permission denied)`

{: .note }
> Uses PLT/GOT hooking under the hood — hooks are installed per-library across all loaded shared objects.

---

## Supported Syscalls

| Category | Syscalls |
|----------|----------|
| **file** | `openat`, `open`, `close`, `read`, `write`, `lseek`, `pread64`, `pwrite64`, `fstat`, `stat`, `access`, `readlink`, `rename`, `unlink`, `mkdir`, `chmod` |
| **network** | `socket`, `connect`, `bind`, `listen`, `accept4`, `sendto`, `recvfrom` |
| **memory** | `mmap`, `munmap`, `mprotect` |
| **process** | `fork`, `execve`, `kill`, `getpid`, `getuid`, `exit_group` |
| **ipc** | `ioctl`, `fcntl`, `dup`, `dup2`, `pipe` |

---

## Lua API

For programmatic usage from scripts, see the [Syscall API]({% link docs/api/syscall.md %}).

```lua
-- Basic tracing
Syscall.trace("openat", "read", "write", "close")

-- With custom callbacks
Syscall.trace("openat", {
    onCall = function(info)
        print(info.formatted)
        print(Thread.backtrace())
    end
})

-- Stop
Syscall.stop()
```
