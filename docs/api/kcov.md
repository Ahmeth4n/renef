---
title: KCov API
layout: default
parent: Lua API Reference
nav_order: 9
---

# KCov API

The `KCov` global provides kernel code coverage collection for coverage-guided fuzzing. It uses Linux's KCOV facility to record which kernel functions are executed during syscalls.

{: .warning }
> Requires a kernel compiled with `CONFIG_KCOV=y`. This is **not** enabled on stock Android devices. Check with: `adb shell "zcat /proc/config.gz | grep KCOV"`. Root access and debugfs are also required.

---

## `KCov.open([buf_size])`

Open the KCOV device and prepare the shared buffer.

```lua
local cov = KCov.open()           -- default: 256K entries (2MB RAM)
local cov = KCov.open(65536)      -- 64K entries (512KB RAM)
```

**Parameters:**
- `buf_size` (optional) - Number of PC entries to hold (default: 262144). Each entry is 8 bytes.

**Returns:** KCov userdata object with methods below.

{: .note }
> The buffer is shared with the kernel via mmap — zero-copy, no overhead. Lua GC will automatically clean up if you forget to call `close()`.

---

## `cov:enable()`

Start kernel coverage recording for the current thread.

```lua
cov:enable()
-- ... make syscalls ...
cov:disable()
```

{: .warning }
> KCOV is **thread-local**. Only the thread that calls `enable()` is traced. For multi-threaded coverage, each thread needs its own `KCov.open()` + `enable()`.

---

## `cov:disable()`

Stop coverage recording. Data in the buffer is preserved and can be read with `collect()`.

```lua
cov:disable()
```

---

## `cov:count()`

Return the number of kernel function hits (without copying the buffer).

```lua
local hits = cov:count()
print(string.format("Kernel functions hit: %d", hits))
```

**Returns:** Integer — number of PC entries recorded.

---

## `cov:collect([max])`

Read kernel PC addresses from the buffer as a Lua table.

```lua
local pcs = cov:collect()       -- up to 8192 entries
local pcs = cov:collect(20)     -- first 20 entries only

for i, pc in ipairs(pcs) do
    print(string.format("[%d] 0x%x", i, pc))
end
```

**Parameters:**
- `max` (optional) - Maximum entries to read (default: 8192)

**Returns:** Table of integers `{0xffffffc0103a5e20, 0xffffffc0103a5e48, ...}` — each is a kernel function address.

{: .tip }
> Resolve addresses to function names with `/proc/kallsyms`: `adb shell "cat /proc/kallsyms | grep ffffffc0103a5e20"`

---

## `cov:reset()`

Reset the buffer for a new measurement. Sets the entry count to 0.

```lua
cov:reset()
cov:enable()
-- ... new measurement ...
cov:disable()
```

---

## `cov:edges()`

Generate unique edge hashes from consecutive PC pairs. This is the core of coverage-guided fuzzing — AFL-style edge coverage.

```lua
cov:reset()
cov:enable()
-- ... syscall ...
cov:disable()

local edges = cov:edges()

local count = 0
for _ in pairs(edges) do count = count + 1 end
print(string.format("Unique edges: %d", count))
```

**Returns:** Table `{[edge_hash] = hit_count, ...}` where `edge_hash` is a 20-bit hash of consecutive PC pairs.

**How it works:**
- For each consecutive PC pair `(pc[i], pc[i+1])`, computes `hash = (pc[i] >> 1) XOR pc[i+1]`
- Uses 20-bit hash (1M slots) — same approach as AFL
- Same function called from different paths produces different edges

---

## `cov:diff(old_edges)`

Count newly discovered edges compared to a previous edge set. This is how a fuzzer decides whether a mutated input is "interesting".

```lua
-- Baseline measurement
cov:reset(); cov:enable()
syscall_1()
cov:disable()
local baseline = cov:edges()

-- Mutated measurement
cov:reset(); cov:enable()
syscall_2()
cov:disable()

local new_count = cov:diff(baseline)
if new_count > 0 then
    print(string.format("Found %d new edges! Keeping this input.", new_count))
end
```

**Parameters:**
- `old_edges` - Edge table from a previous `cov:edges()` call

**Returns:** Integer — number of edges in the current measurement that don't exist in `old_edges`.

---

## `cov:close()`

Close KCOV, munmap the buffer, and close the file descriptor. Also called automatically by Lua GC.

```lua
cov:close()
```

---

## Complete Fuzzing Example

A minimal coverage-guided syscall fuzzer:

```lua
local cov = KCov.open()
local corpus = {}
local baseline = nil

-- Measure baseline
cov:reset(); cov:enable()
io.open("/proc/self/maps", "r"):read("*a")
cov:disable()
baseline = cov:edges()

-- Fuzzing loop
local paths = {"/proc/self/status", "/proc/self/stat",
               "/proc/self/cmdline", "/proc/self/environ"}

for i, path in ipairs(paths) do
    cov:reset()
    cov:enable()

    local f = io.open(path, "r")
    if f then f:read("*a"); f:close() end

    cov:disable()

    local new = cov:diff(baseline)
    local hits = cov:count()

    if new > 0 then
        table.insert(corpus, path)
        baseline = cov:edges()  -- update baseline
        print(GREEN .. string.format("[+] %s: %d hits, %d new edges", path, hits, new) .. RESET)
    else
        print(string.format("[-] %s: %d hits, 0 new edges (skip)", path, hits))
    end
end

print(string.format("\nCorpus: %d interesting inputs", #corpus))
cov:close()
```

---

## Method Summary

| Method | Returns | Description |
|--------|---------|-------------|
| `KCov.open([size])` | userdata | Open KCOV device, create shared buffer |
| `cov:enable()` | — | Start recording for this thread |
| `cov:disable()` | — | Stop recording |
| `cov:count()` | integer | Number of kernel function hits (fast) |
| `cov:collect([max])` | table | Read PC addresses as Lua table |
| `cov:reset()` | — | Clear buffer for new measurement |
| `cov:edges()` | table | Generate AFL-style edge hashes |
| `cov:diff(old)` | integer | Count new edges vs previous run |
| `cov:close()` | — | Cleanup (also called by GC) |
