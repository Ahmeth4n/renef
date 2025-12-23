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