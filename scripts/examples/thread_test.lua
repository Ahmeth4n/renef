-- Thread backtrace test script

print("=== Thread API Test ===")

-- Get current thread ID
local tid = Thread.id()
print("Current Thread ID: " .. tid)

-- Get backtrace
print("\n=== Call Stack (Backtrace) ===")
local bt = Thread.backtrace()

for i, frame in ipairs(bt) do
    print(string.format("\n[Frame #%d]", frame.index))
    print(string.format("  PC:     0x%x", frame.pc))

    if frame.symbol then
        print(string.format("  Symbol: %s", frame.symbol))
    end

    if frame.module then
        print(string.format("  Module: %s", frame.module))
    end

    if frame.offset then
        print(string.format("  Offset: 0x%x", frame.offset))
    end

    if frame.path then
        print(string.format("  Path:   %s", frame.path))
    end
end

print("\n=== Test Complete ===")
