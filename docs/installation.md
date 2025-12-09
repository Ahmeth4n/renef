---
title: Installation & Build
layout: default
nav_order: 4
---

# Installation & Build

## Requirements

- **macOS** or **Linux** (x86_64 or ARM64)
- **Android NDK** r26 or later
- **CMake** 3.16+
- **ADB** (Android Debug Bridge)
- **Rooted Android device** (ARM64)

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/ahmeth4n/renef.git
cd renef

# 2. Setup dependencies (Lua + Capstone)
make setup

# 3. Build everything
make

# 4. Deploy to device
make deploy

# 5. Run server on device
adb shell /data/local/tmp/renef_server

# 6. Run client on PC
./build/renef
```

---

## Build Targets

| Target | Description |
|--------|-------------|
| `make` | Build client, server, and payload |
| `make client` | Build only the PC client |
| `make server` | Build only the Android server |
| `make payload` | Build only the agent payload |
| `make deploy` | Build and push to device |
| `make install` | Deploy + setup port forwarding |
| `make clean` | Remove build artifacts |
| `make setup` | Setup Lua and Capstone dependencies |

---

## Build Modes

```bash
# Release build (default, optimized + stripped)
make release

# Debug build (symbols, no optimization)
make debug

# Or set BUILD_MODE directly
BUILD_MODE=debug make
```

---

## Configuration

### Android NDK Path

Default: `$(HOME)/Library/Android/sdk/ndk/26.3.11579264`

Override with:
```bash
NDK=/path/to/ndk make
```

Or set environment variable:
```bash
export NDK=/path/to/ndk
```

### Capstone Source Path

Default: `$(HOME)/Downloads/capstone`

If you cloned Capstone elsewhere:
```bash
# Clone Capstone
git clone https://github.com/capstone-engine/capstone.git /your/path/capstone

# Edit Makefile line 108
CAPSTONE_SRC := /your/path/capstone
```

---

## Dependencies

### Automatic Setup

```bash
make setup
```

This runs:
1. `setup-lua` - Downloads and builds Lua 5.4 for Android
2. `build-capstone` - Builds Capstone disassembler for Android

### Manual Setup

#### Lua

```bash
# Automatic
make setup-lua

# Or manual
cd external/lua
curl -L -o lua-5.4.7.tar.gz https://www.lua.org/ftp/lua-5.4.7.tar.gz
tar -xzf lua-5.4.7.tar.gz
./build-android.sh
```

#### Capstone

```bash
# Clone Capstone (if not already)
git clone https://github.com/capstone-engine/capstone.git ~/Downloads/capstone

# Build for Android
make build-capstone
```

---

## Project Structure

```
renef/
├── build/                  # Build output
│   ├── renef              # PC client binary
│   └── android/
│       ├── renef_server   # Android server binary
│       └── libagent.so    # Payload library
├── src/
│   ├── client/            # PC client source
│   ├── server/            # Android server source
│   ├── agent/             # Payload source (injected into target)
│   ├── injector/          # Injection logic
│   └── core/              # Shared code
├── external/
│   ├── lua/               # Lua library
│   └── capstone/          # Capstone disassembler
└── scripts/               # Lua scripts (SSL bypass, etc.)
```

---

## Deployment

### What Gets Deployed

```bash
make deploy
```

Pushes to `/data/local/tmp/`:
- `renef_server` - Server binary
- `.r` - Agent payload (hidden file)

### SELinux Fix (Samsung)

The Makefile automatically sets SELinux context for Samsung devices:
```bash
chcon u:object_r:app_data_file:s0 /data/local/tmp/.r
```

### Manual Deployment

```bash
adb push build/android/renef_server /data/local/tmp/
adb push build/android/libagent.so /data/local/tmp/.r
adb shell chmod +x /data/local/tmp/renef_server
adb shell chmod +x /data/local/tmp/.r
```

---

## Multiple Devices

```bash
# List devices
adb devices

# Deploy to specific device
ANDROID_SERIAL=device_id make deploy

# Or use -s flag
adb -s device_id push ...
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NDK` | Android NDK path | `~/Library/Android/sdk/ndk/26.3.11579264` |
| `BUILD_MODE` | `release` or `debug` | `release` |
| `ANDROID_SERIAL` | Target device ID | (first device) |
| `RENEF_PAYLOAD_PATH` | Custom payload path | `/data/local/tmp/.r` |

---

## Troubleshooting

### NDK Not Found

```
Error: NDK not found at /path/to/ndk
```

**Solution:** Set NDK path:
```bash
NDK=/correct/path/to/ndk make
```

### Capstone Not Found

```
Error: Capstone source not found
```

**Solution:** Clone Capstone:
```bash
git clone https://github.com/capstone-engine/capstone.git ~/Downloads/capstone
make build-capstone
```

### Permission Denied on Deploy

```
adb: error: failed to copy: Permission denied
```

**Solution:** Remove existing file first:
```bash
adb shell rm -f /data/local/tmp/.r
make deploy
```

### Injection Fails

```
Failed to find libc base
```

**Possible causes:**
1. Device not rooted
2. SELinux enforcing - try: `adb shell su -c setenforce 0`
3. Wrong architecture (only ARM64 supported)

### Build Errors

```bash
# Clean and rebuild
make clean
make setup
make
```
