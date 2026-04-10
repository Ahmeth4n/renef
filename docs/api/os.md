---
title: OS API
layout: default
parent: Lua API Reference
nav_order: 10
---

# OS API

The `OS` global provides basic operating system utilities for process management and filesystem listing.

---

## `OS.getpid()`

Returns the PID of the current process.

```lua
local pid = OS.getpid()
print("Current PID: " .. pid)
```

**Returns:** Integer (process ID)

---

## `OS.kill(pid, sig)`

Send a signal to a process.

```lua
-- Send SIGTERM (15) to process
OS.kill(1234, 15)

-- Send SIGKILL (9) to process
OS.kill(1234, 9)

-- Check if process exists (signal 0)
local ret = OS.kill(1234, 0)
if ret == 0 then
    print("Process exists")
end
```

**Parameters:**
- `pid` - Target process ID
- `sig` - Signal number (e.g., 9 for SIGKILL, 15 for SIGTERM)

**Returns:** Integer (`0` on success, `-1` on error)

---

## `OS.tgkill(tgid, tid, sig)`

Send a signal to a specific thread within a thread group. This is the thread-safe way to send signals to individual threads.

```lua
-- Kill a specific thread
local pid = OS.getpid()
OS.tgkill(pid, tid, 9)

-- Send SIGUSR1 to a thread
OS.tgkill(tgid, tid, 10)
```

**Parameters:**
- `tgid` - Thread group ID (usually the main process PID)
- `tid` - Target thread ID
- `sig` - Signal number

**Returns:** Integer (`0` on success, `-1` on error)

---

## `OS.listdir(path)`

List contents of a directory. Entries starting with `.` are excluded.

```lua
-- List files in /data/local/tmp
local files = OS.listdir("/data/local/tmp")
if files then
    for i, name in ipairs(files) do
        print(name)
    end
end

-- List threads of current process
local threads = OS.listdir("/proc/self/task")
if threads then
    print("Thread count: " .. #threads)
    for _, tid in ipairs(threads) do
        print("  TID: " .. tid)
    end
end
```

**Parameters:**
- `path` - Directory path to list

**Returns:** Table of filename strings, or `nil` if directory cannot be opened

---

## Examples

### Kill all threads except main

```lua
local pid = OS.getpid()
local threads = OS.listdir("/proc/self/task")
if threads then
    for _, tid in ipairs(threads) do
        tid = tonumber(tid)
        if tid ~= pid then
            OS.tgkill(pid, tid, 9)
        end
    end
end
```

### Check if a process is alive

```lua
local function is_alive(pid)
    return OS.kill(pid, 0) == 0
end

if is_alive(1234) then
    print("Process 1234 is running")
end
```
