---
title: Lua API Reference
layout: default
nav_order: 7
has_children: true
---

# Lua API Reference

This section covers all available Lua APIs in Renef.

## APIs

- [Module API]({% link docs/api/module.md %}) - Module.list, Module.find, Module.exports, Module.symbols
- [Memory API]({% link docs/api/memory.md %}) - Memory.search, Memory.dump, Memory.read, Memory.write, Memory.patch, hexdump
- [Hook API]({% link docs/api/hook.md %}) - Native and Java hooking
- [Thread API]({% link docs/api/thread.md %}) - Thread.backtrace, Thread.id
- [Console API]({% link docs/api/console.md %}) - console.log, print, colors
- [File API]({% link docs/api/file.md %}) - File.read, File.exists, File.readlink, File.fdpath
- [Java API]({% link docs/api/java.md %}) - Java.use, class wrapper, instance methods
- [Syscall API]({% link docs/api/syscall.md %}) - Syscall.trace, Syscall.stop, syscall tracing
- [KCov API]({% link docs/api/kcov.md %}) - KCov.open, kernel coverage collection, coverage-guided fuzzing
- [OS API]({% link docs/api/os.md %}) - OS.getpid, OS.kill, OS.tgkill, OS.listdir
