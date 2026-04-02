---
title: Local Mode
layout: default
nav_order: 8
---

# Local Mode (`--local`)

Run Renef entirely on the Android device without a PC. The client connects to the server via Unix Domain Sockets directly, bypassing ADB and TCP entirely.

{: .tip }
> Local mode works even when **SELinux is enforcing**. Since the client and server communicate through an abstract Unix socket on the same device, no network ports or special SELinux policies are needed.

---

## Why Local Mode?

The standard setup requires a PC running the Renef client, connected to the device over ADB:

```
[PC] renef CLI → TCP:1907 → adb forward → [Device] renef_server → agent
```

With `--local`, everything runs on the device itself:

```
[Device] renef CLI → UDS → renef_server → agent
```

| | Standard (PC) | Local (`--local`) |
|---|---|---|
| **Requires PC** | Yes | No |
| **Transport** | TCP via ADB forward | Unix Domain Socket |
| **SELinux enforcing** | May block ADB forward | Works |
| **Latency** | ADB + TCP overhead | Near-zero |
| **Use case** | Desktop workflow | Termux, SSH, field testing |

---

## Setup

### 1. Build the Android client

The standard Renef client is built for your host OS (macOS/Linux). For on-device use, you need the ARM64 Android client:

```bash
# Build everything for local deployment
make deploy-local
```

This builds and pushes three binaries to `/data/local/tmp/`:

| Binary | Description |
|--------|-------------|
| `renef_server` | Server (injection + command routing) |
| `renef` | ARM64 client for on-device use |
| `libagent.so` | Agent payload |

### 2. Manual build (if needed)

```bash
# Build only the Android client
make client-android

# Push manually
adb push build/android/renef_client /data/local/tmp/renef
adb push build/android/renef_server /data/local/tmp/renef_server
adb push build/android/libagent.so /data/local/tmp/libagent.so
adb shell chmod +x /data/local/tmp/renef
adb shell chmod +x /data/local/tmp/renef_server
```

---

## Usage

### From Termux or ADB shell

```bash
# Get root
su

# Start server in background
/data/local/tmp/renef_server &

# Run client in local mode
/data/local/tmp/renef --local
```

### Spawn and hook

```bash
# Spawn an app
/data/local/tmp/renef --local -s com.example.app

# Spawn with script
/data/local/tmp/renef --local -s com.example.app -l /data/local/tmp/hook.lua

# Spawn with script and auto-watch
/data/local/tmp/renef --local -s com.example.app -l /data/local/tmp/hook.lua -w

# Attach to running process
/data/local/tmp/renef --local -a $(pidof com.example.app)
```

### Push scripts to device

```bash
# From PC
adb push scripts/ssl_unpin.lua /data/local/tmp/

# Then on device
/data/local/tmp/renef --local -s com.example.app -l /data/local/tmp/ssl_unpin.lua
```

---

## Combine with Gadget Mode

Local mode can be combined with gadget mode (`-g`) for rootless on-device usage with patched APKs:

```bash
# On device (Termux)
/data/local/tmp/renef --local -g $(pidof com.example.app) -l hook.lua
```

This connects directly to the embedded agent via UDS. No server, no root, no PC needed.

---

## How It Works

### Standard mode (PC → Device)

```
PC                              Device
renef CLI                       renef_server
    │                               │
    ├── TCP connect ─────────────>  │ (adb forward tcp:1907
    │   localhost:1907              │  → localabstract:com.android.internal.os.RuntimeInit)
    │                               │
    │   send("spawn com.app\n") ──> │ ── inject ──> target process
    │                               │                    │
    │   <── response ────────────── │ <── UDS ──────────┘
```

### Local mode (on-device)

```
Device
renef --local                   renef_server
    │                               │
    ├── UDS connect ─────────────>  │ @com.android.internal.os.RuntimeInit
    │   (abstract socket, direct)   │
    │                               │
    │   send("spawn com.app\n") ──> │ ── inject ──> target process
    │                               │                    │
    │   <── response ────────────── │ <── UDS ──────────┘
```

The only difference is the transport layer: TCP (via ADB forward) vs direct UDS. The abstract socket `@com.android.internal.os.RuntimeInit` is accessible to any process running as root on the device. No filesystem permissions, no network ports, no SELinux socket rules.

---

## SELinux Compatibility

Local mode is designed to work with SELinux in enforcing mode:

- **Abstract Unix sockets** live in the kernel namespace, not the filesystem. No SELinux file context (`file_contexts`) rules needed
- **No TCP ports** are opened, so no `net` SELinux rules needed
- **No ADB forwarding**, no `adbd` intermediary
- The server runs as root (`su`), which has `unconfined` or `su` SELinux domain on most ROMs
- The injection itself uses `memfd_create` + `dlopen` which works under standard process permissions

{: .note }
> On some Samsung devices with Knox, you may still need to set the SELinux context on the payload: `chcon u:object_r:app_data_file:s0 /data/local/tmp/libagent.so`. The `make deploy-local` command handles this automatically.

---

## Troubleshooting

### "Cannot connect to server via UDS"

The server is not running or the socket path doesn't match.

```bash
# Check if server is running
ps -A | grep renef_server

# Restart server
kill $(pidof renef_server) 2>/dev/null
/data/local/tmp/renef_server &

# Verify socket exists
cat /proc/net/unix | grep RuntimeInit
```

### "Permission denied" on injection

```bash
# Make sure you're root
whoami  # should print "root"

# Re-run with su
su -c "/data/local/tmp/renef --local -s com.example.app"
```

### Scripts not found

Remember that paths are relative to the **device filesystem**, not your PC:

```bash
# Wrong (PC path)
/data/local/tmp/renef --local -l scripts/hook.lua

# Correct (device path)
/data/local/tmp/renef --local -l /data/local/tmp/hook.lua
```

---

## Quick Reference

```bash
# One-time setup (from PC)
make deploy-local

# On device
su
/data/local/tmp/renef_server &
/data/local/tmp/renef --local -s com.example.app -l /data/local/tmp/script.lua -w
```
