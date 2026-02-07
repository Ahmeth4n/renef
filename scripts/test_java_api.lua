-- Java API Test Script
-- Usage: spawn com.example.app && l scripts/test_java_api.lua

print("=== Java API Test ===")

-- Test 1: Load class with Java.use 
print("\n[1] Testing Java.use()...")
local Build = Java.use("android/os/Build")
if Build then
    print("  OK: android.os.Build loaded")
else
    print("  FAIL: Could not load Build class")
    return
end

-- Test 2: Static method (non-argument)
print("\n[2] Testing static method call...")
local System = Java.use("java/lang/System")
if System then
    local time = System:call("currentTimeMillis", "()J")
    print(string.format("  System.currentTimeMillis() = %d", time or 0))
else
    print("  FAIL: Could not load System class")
end

-- Test 3: Static method (with argument)
print("\n[3] Testing static method with args...")
local String = Java.use("java/lang/String")
if String then
    local str = String:call("valueOf", "(I)Ljava/lang/String;", 123)
    print(string.format("  String.valueOf(123) = %s", tostring(str)))

    local str2 = String:call("valueOf", "(Z)Ljava/lang/String;", true)
    print(string.format("  String.valueOf(true) = %s", tostring(str2)))
else
    print("  FAIL: Could not load String class")
end

-- Test 4: Instance creation + instance method
print("\n[4] Testing instance creation and methods...")
local StringBuilder = Java.use("java/lang/StringBuilder")
if StringBuilder then
    local sb = StringBuilder:new("()V")
    if sb then
        print("  OK: StringBuilder instance created")

        sb:call("append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", "Hello")
        sb:call("append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", " World")
        local result = sb:call("toString", "()Ljava/lang/String;")
        print(string.format("  StringBuilder result: %s", tostring(result)))
    else
        print("  FAIL: Could not create StringBuilder instance")
    end
else
    print("  FAIL: Could not load StringBuilder class")
end

-- Test 5: Android Context
print("\n[5] Testing Android APIs...")
local ActivityThread = Java.use("android/app/ActivityThread")
if ActivityThread then
    local app = ActivityThread:call("currentApplication", "()Landroid/app/Application;")
    if app then
        local pkgName = app:call("getPackageName", "()Ljava/lang/String;")
        print(string.format("  Package: %s", tostring(pkgName)))
    else
        print("  INFO: No Application context")
    end
else
    print("  FAIL: Could not load ActivityThread")
end

print("\n=== Test Complete ===")
