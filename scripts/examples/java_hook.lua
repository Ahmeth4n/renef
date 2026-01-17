hook("com/example/reneftestapp/MainActivity", "hookTest", "(Ljava/lang/String;)Ljava/lang/String;", {
      onEnter = function(args)
          print("[onEnter] hookTest called")
          print("  param1 ref = " .. string.format("0x%x", args[2]))
      end,
      onLeave = function(retval)
          print("[onLeave] Original return: " .. string.format("0x%x", retval))

          local newStr = Jni.newStringUTF("HOOKED!")
          print("[onLeave] Returning: 'HOOKED!' (raw ptr: " .. string.format("0x%x", newStr) .. ")")

          return newStr
      end
  })

  print("[+] Hook installed")
