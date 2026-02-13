---
title: Hookshare
layout: default
nav_order: 10
---

# Hookshare

[Hookshare](https://hook.renef.io/) is a community platform for sharing ready-to-use Renef hook scripts. Browse, download, and use scripts written by other users — or publish your own.

---

## What is Hookshare?

Hookshare hosts pre-made Lua hook scripts for common tasks like SSL pinning bypass, root detection bypass, API monitoring, and more. Instead of writing hooks from scratch, you can find a script that already does what you need.

---

## Using Scripts

### Browse & Download

Visit [hook.renef.io](https://hook.renef.io/) to browse available scripts. Each script page includes a description, supported targets, and usage instructions.

### Load in Renef

Once you have a script, load it directly:

```bash
# Spawn app and load script
renef> spawn com.example.app
renef> l ssl_unpin.lua

# Or from command line
./build/renef -s com.example.app -l ssl_unpin.lua
```

---

## Featured Scripts

| Script | Description |
|--------|-------------|
| [Universal SSL Pinning Bypass](https://hook.renef.io/@ahmethan/universal-ssl-pinning-bypass-script) | Covers 30+ SSL verification targets including Conscrypt, OkHttp, NSC, and more |

---

## Publishing Scripts

You can share your own hook scripts with the community on Hookshare. Visit [hook.renef.io](https://hook.renef.io/) to get started.
