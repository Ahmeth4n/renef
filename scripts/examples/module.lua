local libs = Module.list()
print(libs)

local base = Module.find("libc.so")
if base then
    print(string.format("libc.so base: 0x%x", base))
else
    print("Module not found")
end

print("exports:")
local exports = Module.exports("libmoduletest.so")

if exports then
    for i, exp in ipairs(exports) do
        print(string.format("%s -> 0x%x", exp.name, exp.offset))
    end
    print(string.format("Total: %d exports", #exports))
else
    print("exports not found")
end
