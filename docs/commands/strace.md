---
title: Syscall Tracing
layout: default
parent: Command Reference
nav_order: 7
---

# Syscall Tracing

## `renef-strace <syscalls>`

Trace syscalls in the target process in real-time (strace-like). Available both as a built-in command in the renef shell and as a standalone binary.

```bash
# Trace specific syscalls
renef-strace open,read,write,close

# Trace by category
renef-strace -c file
renef-strace -c network
renef-strace -c memory
renef-strace -c process
renef-strace -c ipc

# Trace all supported syscalls
renef-strace -a

# Filter by caller library
renef-strace open,read,write -f libnative.so
```

**Output:**
```
Tracing syscalls... (press Ctrl+C or send any key to stop)
[tid:22137] openat(AT_FDCWD, "/data/data/com.app/file.txt", O_RDONLY, 0644) = 3
[tid:22137] read(3</data/data/com.app/file.txt>, 0x7fe42f5488, 4096) = 128
[tid:22137] write(101<anon_inode:[eventfd]>, 0x7fe42f5398, 8) = 8
[tid:22137] close(3) = 0
```

{: .note }
> Uses PLT/GOT hooking under the hood — no ptrace required. Hooks are installed per-library across all loaded shared objects.

---

## `renef-strace --list`

List all supported syscalls and their categories.

```bash
renef-strace --list
```

---

## `renef-strace --active`

Show currently active syscall traces.

```bash
renef-strace --active
```

**Output:**
```
Active traces: 3
```

---

## `renef-strace --stop`

Stop all active syscall tracing and restore original GOT entries.

```bash
renef-strace --stop
```

**Output:**
```
Syscall tracing stopped
Active traces: 0
```

---

## Standalone Binary

`renef-strace` is also available as a standalone executable for use outside the renef shell:

```bash
# Trace syscalls on a running process
renef-strace -p <pid> open,read,write,close

# Category-based tracing
renef-strace -p <pid> -c network

# Trace all
renef-strace -p <pid> -a

# Stop tracing
renef-strace -p <pid> --stop

# List available syscalls
renef-strace -p <pid> --list
```

Press `Ctrl+C` to stop tracing gracefully. Hooks are automatically cleaned up on exit.

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

## Output Format

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
