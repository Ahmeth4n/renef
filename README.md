<img src="https://renef.io/assets/img/renef-logo-black.svg" alt="Renef Logo" width="180"/>

# Renef

**Dynamic instrumentation toolkit for Android ARM64**

[![Release](https://img.shields.io/github/v/release/ahmeth4n/renef?style=flat-square&color=blue)](https://github.com/ahmeth4n/renef/releases)
[![License](https://img.shields.io/github/license/ahmeth4n/renef?style=flat-square)](https://github.com/ahmeth4n/renef/blob/main/LICENSE)
[![Stars](https://img.shields.io/github/stars/ahmeth4n/renef?style=flat-square)](https://github.com/ahmeth4n/renef/stargazers)
[![Issues](https://img.shields.io/github/issues/ahmeth4n/renef?style=flat-square)](https://github.com/ahmeth4n/renef/issues)
[![Docs](https://img.shields.io/badge/docs-renef.io-green?style=flat-square)](https://renef.io)
[![HookShare](https://img.shields.io/badge/hooks-hook.renef.io-orange?style=flat-square)](https://hook.renef.io)

---

Renef lets you hook native and Java functions, scan and patch memory, and inject into running processes on Android ARM64 — all through a Lua scripting interface. No ptrace required.

For comprehensive information, see [renef.io](https://renef.io).

## Install

### Prebuilt binaries

Download the latest release from [GitHub Releases](https://github.com/ahmeth4n/renef/releases).

### Build from source

Prerequisites: CMake 3.16+, C++17 compiler, Android NDK r25+

```bash
# Setup dependencies (first time)
make setup

# Build client, server, and agent
make all

# Build, deploy to device, and start server
make install
```

## Learn more

Visit [renef.io](https://renef.io) for docs, guides, and API reference.

## Hooks

Browse and share community hooks at **[hook.renef.io](https://hook.renef.io)** — SSL pinning bypass, root detection bypass, debugger detection bypass, and more.

## Community

[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0?style=flat-square&logo=telegram&logoColor=white)](https://t.me/+W5oJDYXg22FmMDA0)
[![X](https://img.shields.io/badge/X-000000?style=flat-square&logo=x&logoColor=white)](https://x.com/renef0x)
[![Discord](https://img.shields.io/badge/Discord-5865F2?style=flat-square&logo=discord&logoColor=white)](https://discord.gg/776bkf5U)

## License

MIT License - see [LICENSE](LICENSE) for details.
