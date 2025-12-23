-- Multi-hook test script for libmoduletest.so
-- Tests hooking multiple functions in the same library

-- Hook testHookFunc (offset: 0x98ca0)
hook("libmoduletest.so", 0x99110, {
    onEnter = function(args)
        print("[testHookFunc] onEnter")
    end,
    onLeave = function(retval)
        print("[testHookFunc] onLeave: " .. tostring(retval))
        return retval
    end
})

-- Hook testHookFuncTwo (offset: 0x98c54)
hook("libmoduletest.so", 0x990c4, {
    onEnter = function(args)
        print("[testHookFuncTwo] onEnter")
    end,
    onLeave = function(retval)
        print("[testHookFuncTwo] onLeave: " .. tostring(retval))
        return retval
    end
})

local RED = "\27[31m"
local GREEN = "\27[32m"
local YELLOW = "\27[33m"
local BLUE = "\27[34m"
local CYAN = "\27[36m"
local RESET = "\27[0m"

local results = Memory.scan("\xFF\xFF")
for i, r in ipairs(results) do
    print(GREEN .. "Library: " .. RESET .. r.library)
    print(YELLOW .. "Offset:  " .. RESET .. string.format("0x%x", r.offset))
    print(CYAN .. "Hex:     " .. RESET .. r.hex)
    print(BLUE .. "ASCII:   " .. RESET .. r.ascii)
    print("---")
end

print("Multi-hook loaded")
