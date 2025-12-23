-- Hook liba0x9.so first export and return 1337

local lib_name = "liba0x9.so"

print("Looking for " .. lib_name .. "...")

-- Check if library is already loaded
if not Module.find(lib_name) then
    print("[WARN] Library not loaded yet")
    print("[INFO] Trigger the function in the app first, then reload this script")
    return
end

print("Library found! Getting exports...")

local exports = Module.exports(lib_name)
if not exports or #exports == 0 then
    print("[ERROR] No exports in " .. lib_name)
    return
end

-- Hook first export
local func = exports[1]
print("Hooking: " .. func.name .. " @ 0x" .. string.format("%x", func.offset))

hook(lib_name, func.offset, {
    onEnter = function(args)
        print("[CALLED] " .. func.name)
    end,
    onLeave = function(retval)
        print("Original retval: " .. retval)
        return 1337
    end
})

print("Hook installed! Return value will be 1337")
