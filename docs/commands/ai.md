---
title: AI Implementation
layout: default
parent: Command Reference
nav_order: 9
---

# AI Implementation

The `ai` command uses LLM models to generate Renef Lua scripts from natural language prompts.

---

## Usage

```
ai <prompt>
ai <prompt> @<file_path>
```

## Providers

Renef supports three LLM providers:

| Provider | Model | Speed | Cost | Tool Calling |
|---|---|---|---|---|
| Ollama | llama3.1 | Slow (local CPU) | Free | Limited |
| OpenAI | gpt-4o | Fast | ~$0.01/req | Reliable |
| Anthropic | claude-sonnet-4-20250514 | Fast | ~$0.01/req | Reliable |

Provider is auto-detected based on environment variables:
1. `OPENAI_API_KEY` set → OpenAI
2. `ANTHROPIC_API_KEY` set → Anthropic
3. Neither → Ollama (local)

Override with `RENEF_AI_PROVIDER=ollama|openai|anthropic`.

---

## Examples

### Basic usage

```bash
renef> ai bypass ssl pinning
renef> ai bypass root detection for this app
renef> ai hook all fopen calls and log file paths
renef> ai trace crypto functions in libcrypto.so
```

### File references with `@path`

Inline file contents into the prompt using `@`:

```bash
renef> ai hook the encrypt method in @/tmp/CryptoManager.java
renef> ai bypass root check in @./RootDetector.smali
renef> ai explain @/tmp/decompiled.java and generate hooks
```

Multiple files:

```bash
renef> ai compare @old.java and @new.java and hook the differences
```

### With target connected

When a target process is attached/spawned, the AI can execute Renef commands to gather information:

```
renef> ai bypass root detection
[AI] Provider: OpenAI (gpt-4o)
[AI] Thinking...
[AI] exec: print(Module.list())
[AI] result: libc.so, libssl.so, libapp.so...
[AI] exec: for _,e in ipairs(Module.exports("libapp.so")) do print(e.name) end
[AI] result: Java_com_example_RootCheck_isRooted...

─── AI Response ───
Based on the analysis...

─── Extracted Script ───
hook("com/example/RootCheck", "isRooted", "()Z", {
    onLeave = function() return false end
})
```

---

## Configuration

All configuration is via environment variables:

```bash
# Provider selection
RENEF_AI_PROVIDER=openai          # ollama, openai, or anthropic

# API keys
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# Ollama settings
OLLAMA_HOST=127.0.0.1             # Ollama server address
OLLAMA_PORT=11434                 # Ollama server port

# Model override (any provider)
OLLAMA_MODEL=gpt-4o-mini          # Override default model

# Custom system prompt
RENEF_AI_PROMPT=/path/to/prompt.md
```

---

## System Prompt

The AI uses `RENEF_AI_PROMPT.md` (project root) as its system prompt. This file contains:

- Full Renef Lua API reference
- 7 working script examples (hooks, SSL bypass, root bypass, syscall tracing)
- Critical rules (no Frida syntax, use `print()`, JNI slash notation, etc.)

Edit this file to customize AI behavior — no rebuild required.

Search order:
1. `RENEF_AI_PROMPT` env variable (custom path)
2. `RENEF_AI_PROMPT.md` (current directory)
3. `/data/local/tmp/renef_prompt.md` (Android device)

---

## Ollama Setup

```bash
# Install
curl -fsSL https://ollama.com/install.sh | sh

# Download model (tool calling requires 3.1+)
ollama pull llama3.1

# Start server
ollama serve

# If renef runs on Android device, forward Ollama port
adb reverse tcp:11434 tcp:11434
```
