---
title: Process Management
layout: default
parent: Command Reference
nav_order: 1
---

# Process Management

## `spawn <package> [options]`

Spawn a new process and inject payload.

```bash
# Spawn with default trampoline hooking
spawn com.example.app

# Spawn with PLT/GOT hooking
spawn com.example.app --hook=pltgot

# Spawn with pause (spawn gate) — freezes app before onCreate
renef -s com.example.app -l bypass.lua --pause
```

**Options:**

| Flag | Description |
|---|---|
| `--hook=pltgot` | Use PLT/GOT hooking instead of trampoline |
| `--pause` | Freeze process after injection (spawn gate) |

**Output:**
```
OK 12345
```

### Spawn Gate (`--pause`)

The `--pause` flag freezes the target process (via `SIGSTOP`) immediately after the agent is injected and connected. This ensures hooks are installed **before** any application code runs — critical for bypassing root detection, integrity checks, or other startup-time protections.

**How it works:**
1. App is launched and agent is injected normally
2. After agent connection is established, process is frozen with `SIGSTOP`
3. When a script is loaded (`-l` flag or `l` command), the data is written to the kernel socket buffer
4. Process is resumed with `SIGCONT` — agent reads the buffered script and installs hooks (microseconds) before the main thread reaches `onCreate` (milliseconds)

```bash
# With script — auto-resumes after script is loaded
renef -s com.example.app -l root_bypass.lua --pause

# Without script — stays paused until manual resume
renef -s com.example.app --pause
renef> l scripts/root_bypass.lua    # loads script and auto-resumes
# or
renef> resume                       # manual resume without script
```

{: .note }
> Spawn gate uses `SIGSTOP`/`SIGCONT` signals — no ptrace, no `/proc` trace, no SELinux audit. Undetectable by anti-tampering checks.

---

## `resume`

Resume a spawn-gated process. Only needed when `--pause` was used without a script.

```bash
renef> resume
Resumed pid 12345
```

---

## `attach <pid> [--hook=type]`

Attach to running process by PID.

```bash
# Attach to PID
attach 1234

# Attach with PLT/GOT hooking
attach 1234 --hook=pltgot
```

**Output:**
```
OK
```
