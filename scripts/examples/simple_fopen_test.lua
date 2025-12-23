-- Very simple fopen hook test
__hook_type__ = "trampoline"

print("=== Simple fopen Hook Test ===")

local libc = Module.find("libc.so")
if not libc then
    print("[ERROR] libc.so not found")
    return
end

print("[OK] libc.so @ " .. string.format("0x%x", libc))

local exports = Module.exports("libc.so")
if not exports then
    print("[ERROR] No exports")
    return
end

print("[OK] Got " .. #exports .. " exports")

-- Find fopen
for i, exp in ipairs(exports) do
    if exp.name == "fopen" then
        print("[FOUND] fopen @ offset: " .. string.format("0x%x", exp.offset))

        -- Hook it
        print("[INSTALL] Installing hook...")
        hook("libc.so", exp.offset, {
            onEnter = function(args)
                print(">>> FOPEN CALLED! <<<")
            end
        })
        print("[OK] Hook installed!")
        break
    end
end

print("")
print("Test the app now - you should see '>>> FOPEN CALLED! <<<' messages")
