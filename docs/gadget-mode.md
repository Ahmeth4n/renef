---
title: Gadget Mode
layout: default
nav_order: 6
---

# Gadget Mode

Gadget mode allows you to use Renef on **non-rooted devices** by embedding `libagent.so` directly into the target APK.

{: .note }
> This feature was introduced in **v0.3.0**.

---

## How It Works

Instead of injecting the agent at runtime (which requires root), you:

1. Patch the target APK to include `libagent.so`
2. Make the app load the library on startup
3. Connect to the embedded agent via port forwarding

---

## Setup

### 1. Patch the APK

Add `libagent.so` to the APK's native libraries:

```bash
# Unpack APK
apktool d target.apk -o target_unpacked

# Copy agent library
mkdir -p target_unpacked/lib/arm64-v8a
cp build/android/libagent.so target_unpacked/lib/arm64-v8a/

# Add System.loadLibrary call to the app's main activity
# or use a native library loader
```

{: .warning }
> You'll need to add code to load the library. This can be done via smali patching or by using tools like LSPatch.

### 2. Rebuild and Sign

```bash
# Rebuild APK
apktool b target_unpacked -o target_patched.apk

# Sign APK
apksigner sign --ks your-key.jks target_patched.apk

# Install
adb install target_patched.apk
```

### 3. Setup Port Forwarding

```bash
# Use the Makefile helper
make gadget-forward

# Or manually
adb forward tcp:6666 tcp:6666
```

### 4. Connect with Client

```bash
# Connect to gadget using -g flag with target PID
./build/renef -g <pid>
```

---

## Usage

Once connected, all standard Renef commands work:

```bash
# Connect to gadget
./build/renef -g 12345

# Execute Lua code
renef> print("Hello from gadget mode!")

# Load scripts
renef> l scripts/ssl_bypass.lua

# Hook functions
renef> exec hook("libc.so", 0x1234, { onEnter = function(args) print(args[0]) end })
```

---

## Makefile Helpers

| Target | Description |
|--------|-------------|
| `make gadget-forward` | Setup ADB port forwarding for gadget mode |
| `make gadget-kill` | Kill port forwarding |

---

## Comparison: Root vs Gadget Mode

| Feature | Root Mode | Gadget Mode |
|---------|-----------|-------------|
| Requires root | Yes | No |
| APK modification | No | Yes |
| Attach to any app | Yes | Only patched apps |
| Spawn apps | Yes | No |
| Runtime injection | Yes | No (embedded) |
| All Lua APIs | Yes | Yes |
| Hooks | Yes | Yes |

---

## Limitations

- **APK patching required**: You need to modify and re-sign the target APK
- **No spawn**: Can only connect to already running patched apps
- **Single app**: Each patched APK has its own embedded agent
- **Signature change**: Re-signing changes the app signature, which may affect:
  - Google Play Services
  - SafetyNet/Play Integrity
  - App-specific signature checks

---

## Tips

### Finding the PID

```bash
# Get PID of running app
adb shell pidof com.example.app
```

### Auto-load Library

For the agent to work, the app must load `libagent.so`. Common approaches:

1. **Smali patch**: Add `System.loadLibrary("agent")` to the main activity's `onCreate`
2. **LSPatch**: Use LSPatch to inject the library loader
3. **Native init**: If the app already loads native libraries, hook the init function

### Debugging Connection Issues

```bash
# Check if agent is listening
adb shell netstat -tlnp | grep 6666

# Check logcat for agent messages
adb logcat | grep -i renef
```
