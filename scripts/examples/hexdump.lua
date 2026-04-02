-- hexdump() test script
-- Usage: l scripts/examples/hexdump.lua

print(CYAN .. "=== hexdump() Test ===" .. RESET)

-----------------------------------------------
-- Test 1: String
-----------------------------------------------
print("\n[1] String hexdump:")
print(hexdump("Hello World! Renef hexdump test 1234567890"))

-----------------------------------------------
-- Test 2: Binary data (with Memory.read)
-----------------------------------------------
print("\n[2] Binary data (including null bytes):")
local bin = "\x00\x01\x02\x03\xff\xfe\xfd\xfc\x48\x65\x6c\x6c\x6f\x00\x00\x00"
          .. "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
print(hexdump(bin))

-----------------------------------------------
-- Test 3: Byte table
-----------------------------------------------
print("\n[3] Byte table {0x52, 0x45, 0x4e, 0x45, 0x46}:")
print(hexdump({0x52, 0x45, 0x4e, 0x45, 0x46}))

-----------------------------------------------
-- Test 4: Memory address + length (libc section)
-----------------------------------------------
print("\n[4] Memory address (libc .rodata):")
local libc_base = Module.find("libc.so")
if libc_base then
    print(string.format("  libc base: 0x%x", libc_base))
    print(hexdump(libc_base, 64))
else
    print(YELLOW .. "  SKIP: libc not found (normal in standalone mode)" .. RESET)
end

-----------------------------------------------
-- Test 5: Length limit
-----------------------------------------------
print("\n[5] String with length limit (first 16 bytes):")
local long_str = ("ABCDEFGHIJKLMNOP"):rep(4)
print(hexdump(long_str, 16))

-----------------------------------------------
-- Test 6: Memory.hexdump() alias
-----------------------------------------------
print("\n[6] Memory.hexdump() alias:")
print(Memory.hexdump("Renef Framework"))

-----------------------------------------------
-- Test 7: Hook arg hexdump (simulated)
-----------------------------------------------
print("\n[7] Hook onEnter usage example:")
print([[
  hook("libc.so", "open", {
      onEnter = function(args)
          -- args[1] = x1 = path string pointer
          print(hexdump(args[1], 64))
      end
  })
]])

print(CYAN .. "\n=== Test Complete ===" .. RESET)
