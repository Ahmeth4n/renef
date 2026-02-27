---
title: magisk-renef
layout: default
nav_order: 11.6
---

# magisk-renef

[magisk-renef](https://github.com/vichhka-git/magisk-renef) is a Magisk / KernelSU / APatch module that automatically packages and runs the Renef server on a rooted Android device. Instead of manually copying binaries and launching the server over ADB, magisk-renef installs Renef as a system module so the server starts automatically on every boot — no ADB required.

---

## Features

- **Auto-start on boot** — Renef server launches automatically via `service.sh` on every reboot
- **Root manager agnostic** — Works with Magisk, KernelSU, and APatch
- **Always up to date** — GitHub Actions checks for new Renef releases daily and publishes a fresh module ZIP automatically
- **Zero manual setup** — No need to push binaries with ADB or start the server by hand
- **UDS transport** — Server binds to `@com.android.internal.os.RuntimeInit` Unix domain socket

---

## Requirements

- Rooted Android device (Magisk, KernelSU, or APatch)
- **ARM64 only** (aarch64)
- Android 10 or newer
- ADB (only needed for script delivery and log inspection, not for server startup)

---

## Installation

1. Download the latest `MagiskRenef-{version}.zip` from the [Releases page](https://github.com/vichhka-git/magisk-renef/releases)
2. Open your root manager (Magisk / KernelSU / APatch)
3. Install the ZIP from the root manager's module installer
4. Reboot your device

After reboot, `renef_server` starts automatically in the background.

{: .note }
You can verify the module is active by checking the module list in your root manager — it will show a status message confirming the server is running.

---

## Usage

With `renef_server` running on the device, connect from your workstation using the standard Renef CLI. Forward the UDS socket or use ADB to deliver scripts.

### Spawn a new process

```bash
renef -s com.example.app -l script.lua
```

### Attach to a running process by PID

```bash
renef -a <PID> -l script.lua
```

### Quick workflow

```bash
# 1. Get the PID of the target app (optional — use -s to spawn instead)
adb shell pidof com.example.app

# 2. Push your Lua script to the device
adb push hook.lua /data/local/tmp/

# 3. Attach and run the script
renef -a <PID> -l /data/local/tmp/hook.lua
```

---

## Troubleshooting

### Check the server log

```bash
adb shell cat /data/local/tmp/renef_server.log
```

### SELinux denials

If the server fails to start, SELinux enforcement may be blocking it. Temporarily disable enforcement to diagnose:

```bash
adb shell setenforce 0
```

{: .warning }
Disabling SELinux enforcement reduces the security of your device. Re-enable it with `setenforce 1` after testing.

### Attach fails on hardened apps

Some apps detect and resist process attachment. In these cases, prefer spawning the app fresh with `-s` instead of attaching with `-a`.

---

## How It Works

magisk-renef is built entirely through CI automation:

1. A GitHub Actions workflow runs **daily** and checks the upstream Renef repository for new releases
2. When a new release is detected, it downloads the official ARM64 Renef tarball
3. The workflow packages the binary into a Magisk-compatible ZIP (with `META-INF/`, `system/`, and `service.sh`)
4. The ZIP is published as a new GitHub Release automatically

This means the module always ships the latest official Renef binary without any manual intervention.

### Building locally

If you want to build the module yourself:

```bash
# Install uv (Python package manager) if not already installed
curl -Ls https://astral.sh/uv/install.sh | sh

# Run the build script
uv run python3 main.py

# Force a release build even if no new Renef version is detected
FORCE_RELEASE=1 uv run python3 main.py
```

---

## Comparison: magisk-renef vs manual setup

| | magisk-renef | Manual |
|---|---|---|
| **Server startup** | Automatic on boot | Manual via ADB every time |
| **Binary updates** | Automatic (daily CI) | Manual download and push |
| **ADB required at runtime** | No | Yes |
| **Root manager integration** | Yes | No |
| **Supported root managers** | Magisk, KernelSU, APatch | N/A |

---

## Source & Credits

- **magisk-renef** — [github.com/vichhka-git/magisk-renef](https://github.com/vichhka-git/magisk-renef)
- **Renef** — [github.com/Ahmeth4n/renef](https://github.com/Ahmeth4n/renef) by Ahmeth4n
- Inspired by [magisk-frida](https://github.com/ViRb3/magisk-frida) by ViRb3
