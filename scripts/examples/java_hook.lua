print("=== Java Hook Test ===")

hook("io/byterialab/moduletest/MainActivity", "getSecretValue", "(Ljava/lang/String;)Ljava/lang/String;", {
    onEnter = function(args)
        print("MainActivity.getSecretValue() called!")
        print("  class: " .. tostring(args.class))
        print("  this: " .. string.format("0x%x", args[0]))
        print("  key: " .. string.format("0x%x", args[1]))
    end
})
