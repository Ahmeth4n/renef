-- KCov Test Script
-- After injecting into Renef: l scripts/examples/kcov_test.lua
--
-- Requirement: kernel CONFIG_KCOV=y
-- Check: adb shell "ls /sys/kernel/debug/kcov"

print(CYAN .. "=== KCov Test ===" .. RESET)

-----------------------------------------------
-- Test 1: Can it be opened?
-----------------------------------------------
print("\n[1] KCov.open() test...")

local ok, cov = pcall(KCov.open)
if not ok then
    print(RED .. "  FAIL: " .. tostring(cov) .. RESET)
    print(RED .. "  Kernel does not support CONFIG_KCOV=y." .. RESET)
    print(YELLOW .. "  Check: adb shell ls /sys/kernel/debug/kcov" .. RESET)
    return
end
print(GREEN .. "  OK: KCov opened" .. RESET)

-----------------------------------------------
-- Test 2: enable/disable cycle
-----------------------------------------------
print("\n[2] enable/disable test...")

cov:reset()
cov:enable()

-- make a simple syscall to trigger kernel paths
local f = io.open("/proc/self/maps", "r")
if f then
    local _ = f:read(100)
    f:close()
end

cov:disable()

local count = cov:count()
print(string.format("  Hit: %d kernel functions", count))

if count > 0 then
    print(GREEN .. "  OK: Coverage recorded" .. RESET)
else
    print(YELLOW .. "  WARN: 0 hits - KCOV may not be active" .. RESET)
end

-----------------------------------------------
-- Test 3: collect() - PC addresses
-----------------------------------------------
print("\n[3] collect() test...")

local pcs = cov:collect(20) -- first 20 entries
print(string.format("  Total: %d PCs, showing first %d:", count, #pcs))

for i, pc in ipairs(pcs) do
    print(string.format("    [%2d] 0x%x", i, pc))
end

-----------------------------------------------
-- Test 4: reset + new measurement
-----------------------------------------------
print("\n[4] reset + new measurement test...")

cov:reset()
assert(cov:count() == 0, "count should be 0 after reset")
print("  reset OK (count=0)")

cov:enable()

-- different syscall
os.time()

cov:disable()

local count2 = cov:count()
print(string.format("  New measurement: %d hits", count2))

-----------------------------------------------
-- Test 5: edges() - coverage-guided fuzzing
-----------------------------------------------
print("\n[5] edges() test...")

-- measure baseline
cov:reset()
cov:enable()
local f1 = io.open("/proc/self/status", "r")
if f1 then f1:read("*a"); f1:close() end
cov:disable()

local edges1 = cov:edges()
local edge_count = 0
for _ in pairs(edges1) do edge_count = edge_count + 1 end
print(string.format("  Baseline: %d unique edges", edge_count))

-----------------------------------------------
-- Test 6: diff() - new path detection
-----------------------------------------------
print("\n[6] diff() test...")

-- try a different path
cov:reset()
cov:enable()
local f2 = io.open("/proc/self/cmdline", "r")
if f2 then f2:read("*a"); f2:close() end
cov:disable()

local new_edges = cov:diff(edges1)
print(string.format("  New edges: %d", new_edges))

if new_edges > 0 then
    print(GREEN .. "  OK: Different syscall = different kernel path" .. RESET)
else
    print(YELLOW .. "  INFO: Same path may have been used" .. RESET)
end

-----------------------------------------------
-- Test 7: syscall mutation + kcov combined
-----------------------------------------------
print("\n[7] Syscall mutation + KCov combined test...")

-- This test uses kcov to compare coverage across different inputs
-- Miniature version of a real fuzzing loop

local results = {}

-- try 3 different mutated inputs
local test_fds = {"/proc/self/maps", "/proc/self/status", "/proc/self/stat"}

for i, path in ipairs(test_fds) do
    cov:reset()
    cov:enable()

    local fh = io.open(path, "r")
    if fh then fh:read("*a"); fh:close() end

    cov:disable()

    local c = cov:count()
    local e = cov:edges()
    local ne = 0
    for _ in pairs(e) do ne = ne + 1 end

    results[i] = {path=path, hits=c, edges=ne}
    print(string.format("  Input %d: %s -> %d hits, %d edges", i, path, c, ne))
end

-----------------------------------------------
-- Cleanup
-----------------------------------------------
print("\n[8] Cleanup...")
cov:close()
print(GREEN .. "  KCov closed" .. RESET)

-----------------------------------------------
-- Summary
-----------------------------------------------
print(CYAN .. "\n=== Test Complete ===" .. RESET)
print(string.format("  Test 1 (open):    %s", cov and "PASS" or "FAIL"))
print(string.format("  Test 2 (enable):  %s", count > 0 and "PASS" or "WARN"))
print(string.format("  Test 3 (collect): %s", #pcs > 0 and "PASS" or "WARN"))
print(string.format("  Test 5 (edges):   %s", edge_count > 0 and "PASS" or "WARN"))
