# =============================================================================
# RENEF - Production Build System
# =============================================================================

# Build mode: debug or release
BUILD_MODE ?= release

# Detect host OS and architecture
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
    HOST_OS := macos
    ifeq ($(UNAME_M),arm64)
        HOST_ARCH := arm64
        NDK_HOST := darwin-x86_64
    else
        HOST_ARCH := x86_64
        NDK_HOST := darwin-x86_64
    endif
else ifeq ($(UNAME_S),Linux)
    HOST_OS := linux
    ifeq ($(UNAME_M),aarch64)
        HOST_ARCH := arm64
        NDK_HOST := linux-x86_64
    else
        HOST_ARCH := x86_64
        NDK_HOST := linux-x86_64
    endif
else ifeq ($(OS),Windows_NT)
    HOST_OS := windows
    HOST_ARCH := x86_64
    NDK_HOST := windows-x86_64
else
    $(error Unsupported OS: $(UNAME_S))
endif

# Auto-detect NDK: find the latest version in common locations per OS
ifeq ($(HOST_OS),macos)
    NDK_BASE_DIR := $(HOME)/Library/Android/sdk/ndk
else ifeq ($(HOST_OS),linux)
    NDK_BASE_DIR := $(firstword $(wildcard $(HOME)/Android/Sdk/ndk $(ANDROID_HOME)/ndk $(ANDROID_SDK_ROOT)/ndk /opt/android-ndk))
else ifeq ($(HOST_OS),windows)
    NDK_BASE_DIR := $(firstword $(wildcard $(LOCALAPPDATA)/Android/Sdk/ndk $(ANDROID_HOME)/ndk $(ANDROID_SDK_ROOT)/ndk))
endif

# Find latest NDK version using pure Make (no shell commands)
NDK_VERSIONS := $(wildcard $(NDK_BASE_DIR)/*)
NDK_AUTO := $(lastword $(sort $(NDK_VERSIONS)))

# Use NDK environment variable if set, otherwise use auto-detected
NDK ?= $(NDK_AUTO)

# Verify NDK exists
ifeq ($(wildcard $(NDK)/toolchains),)
    $(error NDK not found at '$(NDK)'. Set NDK=/path/to/ndk or install Android NDK)
endif

TOOLCHAIN := $(NDK)/toolchains/llvm/prebuilt/$(NDK_HOST)
CLANG := $(TOOLCHAIN)/bin/aarch64-linux-android21-clang
CLANGXX := $(TOOLCHAIN)/bin/aarch64-linux-android21-clang++

BUILD_DIR := build
ANDROID_BUILD := $(BUILD_DIR)/android

RENEF_CLIENT := $(BUILD_DIR)/renef
RENEF_SERVER := $(ANDROID_BUILD)/renef_server
PAYLOAD_SO := $(ANDROID_BUILD)/libagent.so

ifeq ($(BUILD_MODE),release)
    CMAKE_BUILD_TYPE := Release
    SERVER_OPT_FLAGS := -O3 -DNDEBUG
    PAYLOAD_OPT_FLAGS := -O3 -DNDEBUG
    STRIP_CMD := strip
else
    CMAKE_BUILD_TYPE := Debug
    SERVER_OPT_FLAGS := -O0 -g
    PAYLOAD_OPT_FLAGS := -O0 -g
    STRIP_CMD := @true
endif

# Server sources (new paths)
SERVER_SRCS := src/server/main.cpp \
               src/librenef/transport/server.cpp \
               src/librenef/transport/uds.cpp \
               src/librenef/transport/tcp.cpp \
               src/librenef/cmd/cmd.cpp \
               src/librenef/cmd/cmd_ping.cpp \
               src/librenef/cmd/cmd_attach.cpp \
               src/librenef/cmd/cmd_spawn.cpp \
               src/librenef/cmd/cmd_list.cpp \
               src/librenef/cmd/cmd_inspect.cpp \
               src/librenef/cmd/cmd_eval.cpp \
               src/librenef/cmd/cmd_load.cpp \
               src/librenef/cmd/cmd_watch.cpp \
               src/librenef/cmd/cmd_memscan.cpp \
               src/librenef/cmd/cmd_hooks.cpp \
               src/librenef/cmd/cmd_sec.cpp \
               src/librenef/cmd/cmd_memdump.cpp \
               src/librenef/cmd/cmd_hookgen.cpp \
               src/librenef/util/string.cpp \
               src/librenef/util/crypto.cpp \
               src/librenef/util/socket.cpp \
               src/inject/injector.cpp

SERVER_CXXFLAGS := -std=c++17 \
                   $(SERVER_OPT_FLAGS) \
                   -Isrc/librenef/include \
                   -Isrc/librenef \
                   -Isrc/server \
                   -Isrc/inject \
                   -Iexternal \
                   -Iexternal/capstone/include \
                   -static-libstdc++ \
                   -Wall -Wextra

CAPSTONE_VERSION := 5.0.3
CAPSTONE_SRC := external/capstone/capstone-$(CAPSTONE_VERSION)
CAPSTONE_BUILD := $(CAPSTONE_SRC)/build-android
CAPSTONE_LIB := external/capstone/lib-android/arm64-v8a/libcapstone.a
CAPSTONE_HOST_LIB := external/capstone/lib/libcapstone.a

ASIO_VERSION := 1-30-2
ASIO_DIR := external/asio
ASIO_HEADER := $(ASIO_DIR)/include/asio.hpp

LUA_VERSION := 5.4.7
LUA_SRC := external/lua

SERVER_LDFLAGS := -Wl,--whole-archive $(CAPSTONE_LIB) -Wl,--no-whole-archive

LUA_LIB := external/lua/lib-android/lib/liblua.a
LUA_INCLUDE := external/lua/lib-android/include

PAYLOAD_CFLAGS := -shared -fPIC -std=c11 \
                  $(PAYLOAD_OPT_FLAGS) \
                  -Isrc/agent/include \
                  -Isrc/agent \
                  -Iexternal/capstone/include \
                  -I$(LUA_INCLUDE) \
                  -I$(NDK)/toolchains/llvm/prebuilt/$(NDK_HOST)/sysroot/usr/include
PAYLOAD_LDFLAGS := -llog $(CAPSTONE_LIB) $(LUA_LIB) -lm -ldl

# Agent sources (new paths)
AGENT_SRCS := src/agent/core/agent.c \
              src/agent/core/globals.c \
              src/agent/core/registry.c \
              src/agent/hook/native.c \
              src/agent/hook/java.c \
              src/agent/proc/proc.c \
              src/agent/handlers/eval.c \
              src/agent/handlers/inspect.c \
              src/agent/handlers/memscan.c \
              src/agent/handlers/memdump.c \
              src/agent/handlers/builtin.c \
              src/agent/lua/engine.c \
              src/agent/lua/api_hook.c \
              src/agent/lua/api_memory.c \
              src/agent/lua/api_thread.c \
              src/agent/lua/api_file.c \
              src/agent/lua/api_jni.c

.PHONY: all clean clean-capstone clean-all client server payload deploy install test build-capstone setup setup-lua setup-asio setup-capstone-host release debug plugins client-android deploy-local

all: client server payload

plugins:
	@if [ -d "examples/plugins" ] && [ -n "$$(ls examples/plugins/*.c 2>/dev/null)" ]; then \
		echo "Building plugins..."; \
		$(MAKE) -C examples/plugins install; \
	else \
		echo "No plugins found in examples/plugins/"; \
	fi

release:
	@$(MAKE) BUILD_MODE=release all

debug:
	@$(MAKE) BUILD_MODE=debug all

setup: setup-asio setup-lua setup-capstone-host build-capstone
	@echo "All dependencies set up"

setup-asio: $(ASIO_HEADER)

$(ASIO_HEADER):
	@echo "Downloading ASIO $(ASIO_VERSION)..."
	@mkdir -p external
	@cd external && \
		curl -sL -o asio.tar.gz "https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-$(ASIO_VERSION).tar.gz" && \
		tar -xzf asio.tar.gz && \
		rm -rf asio && \
		mv asio-asio-$(ASIO_VERSION)/asio asio && \
		rm -rf asio-asio-$(ASIO_VERSION) asio.tar.gz
	@echo "ASIO $(ASIO_VERSION) downloaded"

setup-lua: $(LUA_LIB)

$(LUA_LIB):
	@echo "Downloading and building Lua $(LUA_VERSION)..."
	@mkdir -p $(LUA_SRC)
	@if [ ! -f "$(LUA_SRC)/src/lua.h" ]; then \
		cd external && \
		curl -sL -o lua.tar.gz "https://www.lua.org/ftp/lua-$(LUA_VERSION).tar.gz" && \
		tar -xzf lua.tar.gz && \
		rm -rf lua && \
		mv lua-$(LUA_VERSION) lua && \
		rm lua.tar.gz; \
	fi
	@echo "Building Lua for Android ARM64..."
	@mkdir -p $(LUA_SRC)/lib-android/lib $(LUA_SRC)/lib-android/include
	@cd $(LUA_SRC)/src && \
		$(CLANG) -c -fPIC -O2 -Wall -DLUA_USE_POSIX -DLUA_USE_DLOPEN \
			lapi.c lcode.c lctype.c ldebug.c ldo.c ldump.c lfunc.c lgc.c llex.c \
			lmem.c lobject.c lopcodes.c lparser.c lstate.c lstring.c ltable.c \
			ltm.c lundump.c lvm.c lzio.c lauxlib.c lbaselib.c lcorolib.c ldblib.c \
			liolib.c lmathlib.c loadlib.c loslib.c lstrlib.c ltablib.c lutf8lib.c linit.c && \
		$(TOOLCHAIN)/bin/llvm-ar rcs ../lib-android/lib/liblua.a *.o && \
		rm -f *.o && \
		cp lua.h luaconf.h lualib.h lauxlib.h ../lib-android/include/
	@echo "Lua $(LUA_VERSION) built"

setup-capstone-host: $(CAPSTONE_HOST_LIB)

$(CAPSTONE_HOST_LIB):
	@echo "Downloading and building Capstone $(CAPSTONE_VERSION) for host..."
	@mkdir -p external/capstone
	@if [ ! -d "$(CAPSTONE_SRC)" ]; then \
		cd external/capstone && \
		curl -sL -o capstone.tar.gz "https://github.com/capstone-engine/capstone/archive/refs/tags/$(CAPSTONE_VERSION).tar.gz" && \
		tar -xzf capstone.tar.gz && \
		rm capstone.tar.gz; \
	fi
	@mkdir -p $(CAPSTONE_SRC)/build-host
	@cd $(CAPSTONE_SRC)/build-host && \
		cmake .. -DCMAKE_BUILD_TYPE=Release && \
		make -j$$(nproc 2>/dev/null || sysctl -n hw.ncpu)
	@mkdir -p external/capstone/lib external/capstone/include
	@cp $(CAPSTONE_SRC)/build-host/libcapstone.a external/capstone/lib/
	@cp -r $(CAPSTONE_SRC)/include/capstone external/capstone/include/
	@echo "Capstone $(CAPSTONE_VERSION) built for host"

client: $(ASIO_HEADER) $(CAPSTONE_HOST_LIB)
	@echo "Building renef client for $(HOST_OS)/$(HOST_ARCH) ($(BUILD_MODE))..."
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) .. && cmake --build .
	@if [ "$(BUILD_MODE)" = "release" ]; then \
		$(STRIP_CMD) $(RENEF_CLIENT) 2>/dev/null || true; \
	fi
	@echo "Built: $(RENEF_CLIENT)"

server: $(RENEF_SERVER)

$(RENEF_SERVER): $(SERVER_SRCS) $(CAPSTONE_LIB)
	@echo "Building renef_server for Android ARM64 ($(BUILD_MODE))..."
	@mkdir -p $(ANDROID_BUILD)
	$(CLANGXX) $(SERVER_CXXFLAGS) $(SERVER_SRCS) -o $@ $(SERVER_LDFLAGS)
	@if [ "$(BUILD_MODE)" = "release" ]; then \
		$(TOOLCHAIN)/bin/llvm-strip $@ 2>/dev/null || true; \
	fi
	@echo "Built: $@"

build-capstone: $(CAPSTONE_LIB)

$(CAPSTONE_LIB):
	@echo "Building Capstone $(CAPSTONE_VERSION) for Android ARM64..."
	@mkdir -p external/capstone
	@if [ ! -d "$(CAPSTONE_SRC)" ]; then \
		cd external/capstone && \
		curl -sL -o capstone.tar.gz "https://github.com/capstone-engine/capstone/archive/refs/tags/$(CAPSTONE_VERSION).tar.gz" && \
		tar -xzf capstone.tar.gz && \
		rm capstone.tar.gz; \
	fi
	@rm -rf $(CAPSTONE_BUILD)
	@mkdir -p $(CAPSTONE_BUILD)
	@cd $(CAPSTONE_BUILD) && cmake .. \
		-DCMAKE_TOOLCHAIN_FILE=$(NDK)/build/cmake/android.toolchain.cmake \
		-DANDROID_ABI=arm64-v8a \
		-DANDROID_PLATFORM=android-21 \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_POSITION_INDEPENDENT_CODE=ON
	@cd $(CAPSTONE_BUILD) && make -j$$(nproc 2>/dev/null || sysctl -n hw.ncpu)
	@mkdir -p external/capstone/lib-android/arm64-v8a external/capstone/include
	@cp $(CAPSTONE_BUILD)/libcapstone.a $(CAPSTONE_LIB)
	@cp -r $(CAPSTONE_SRC)/include/capstone external/capstone/include/
	@echo "Capstone $(CAPSTONE_VERSION) built for Android"

payload: $(PAYLOAD_SO)

$(PAYLOAD_SO): $(AGENT_SRCS) $(CAPSTONE_LIB) $(LUA_LIB)
	@echo "Building agent payload for Android ARM64 ($(BUILD_MODE))..."
	@mkdir -p $(ANDROID_BUILD)
	$(CLANG) $(PAYLOAD_CFLAGS) -o $@ $(AGENT_SRCS) $(PAYLOAD_LDFLAGS)
	@if [ "$(BUILD_MODE)" = "release" ]; then \
		$(TOOLCHAIN)/bin/llvm-strip $@ 2>/dev/null || true; \
	fi
	@echo "Built: $@"

deploy: server payload
	@echo "Deploying to Android..."
	adb push $(RENEF_SERVER) /data/local/tmp/renef_server
	adb shell chmod +x /data/local/tmp/renef_server
	@echo "Pushing payload to hidden location..."
	adb push $(PAYLOAD_SO) /data/local/tmp/libagent.so
	adb shell chmod 777 /data/local/tmp/libagent.so
	@echo "Setting SELinux context (Samsung fix)..."
	-adb shell su -c "chcon u:object_r:app_data_file:s0 /data/local/tmp/libagent.so" 2>/dev/null || true
	@echo "Deployed"

install: deploy
	@if ! adb forward --list | grep -q "tcp:1907"; then \
		echo "Setting up adb forward..."; \
		adb forward tcp:1907 localabstract:com.android.internal.os.RuntimeInit; \
		echo "Port forwarded"; \
	else \
		echo "Port already forwarded"; \
	fi
	@echo ""
	@echo "Run on device: adb shell /data/local/tmp/renef_server"
	@echo "Run on PC: ./$(RENEF_CLIENT)"

gadget-forward:
ifndef PID
	$(error PID is required. Usage: make gadget-forward PID=<pid>)
endif
	@adb forward --remove tcp:1907 2>/dev/null || true
	adb forward tcp:1907 localabstract:renef_pl_$(PID)
	@echo ""
	@echo "Gadget mode forward ready!"
	@echo "Run: ./$(RENEF_CLIENT) -g $(PID)"

# List current ADB forwards
forward-list:
	@adb forward --list

# Remove all ADB forwards
forward-clean:
	@adb forward --remove-all
	@echo "All forwards removed"

test: install
	@echo "=== Starting test ==="
	@adb shell "nohup /data/local/tmp/renef_server > /dev/null 2>&1 &"
	@sleep 2
	@echo "renef://ping" | $(RENEF_CLIENT)

clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaned"

clean-capstone:
	@rm -rf $(CAPSTONE_BUILD)
	@rm -f $(CAPSTONE_LIB)
	@echo "Capstone cleaned"

clean-all: clean clean-capstone
	@echo "Full clean completed"

# =============================================================================
# Android Client (for Termux / on-device usage)
# =============================================================================

RENEF_CLIENT_ANDROID := $(ANDROID_BUILD)/renef

# Client sources for Android (same as server uses librenef)
CLIENT_ANDROID_SRCS := src/binr/renef/main.cpp \
                       src/binr/renef/tui/memscan_tui.cpp \
                       src/librenef/cmd/cmd.cpp \
                       src/librenef/cmd/cmd_ping.cpp \
                       src/librenef/cmd/cmd_attach.cpp \
                       src/librenef/cmd/cmd_spawn.cpp \
                       src/librenef/cmd/cmd_list.cpp \
                       src/librenef/cmd/cmd_inspect.cpp \
                       src/librenef/cmd/cmd_eval.cpp \
                       src/librenef/cmd/cmd_load.cpp \
                       src/librenef/cmd/cmd_watch.cpp \
                       src/librenef/cmd/cmd_memscan.cpp \
                       src/librenef/cmd/cmd_hooks.cpp \
                       src/librenef/cmd/cmd_sec.cpp \
                       src/librenef/cmd/cmd_memdump.cpp \
                       src/librenef/cmd/cmd_hookgen.cpp \
                       src/librenef/cmd/cmd_plugin.cpp \
                       src/librenef/transport/server.cpp \
                       src/librenef/transport/uds.cpp \
                       src/librenef/transport/tcp.cpp \
                       src/librenef/util/string.cpp \
                       src/librenef/util/crypto.cpp \
                       src/librenef/util/socket.cpp \
                       src/librenef/util/server_connection.cpp \
                       src/librenef/plugin/plugin.cpp \
                       src/librenef/binding/renef.cpp \
                       src/inject/injector.cpp

CLIENT_ANDROID_CXXFLAGS := -std=c++17 \
                           $(SERVER_OPT_FLAGS) \
                           -DRENEF_CLI_BUILD \
                           -DRENEF_NO_READLINE \
                           -Isrc/librenef/include \
                           -Isrc/librenef \
                           -Isrc/binr/renef/tui \
                           -Isrc/inject \
                           -Iexternal \
                           -Iexternal/asio/include \
                           -Iexternal/capstone/include \
                           -DASIO_STANDALONE \
                           -static-libstdc++ \
                           -Wall -Wextra

CLIENT_ANDROID_LDFLAGS := -Wl,--whole-archive $(CAPSTONE_LIB) -Wl,--no-whole-archive -ldl

client-android: $(RENEF_CLIENT_ANDROID)

$(RENEF_CLIENT_ANDROID): $(CLIENT_ANDROID_SRCS) $(CAPSTONE_LIB) $(ASIO_HEADER)
	@echo "Building renef client for Android ARM64 ($(BUILD_MODE))..."
	@echo "Note: Building without readline (use basic input in Termux)"
	@mkdir -p $(ANDROID_BUILD)
	$(CLANGXX) $(CLIENT_ANDROID_CXXFLAGS) $(CLIENT_ANDROID_SRCS) -o $@ $(CLIENT_ANDROID_LDFLAGS)
	@if [ "$(BUILD_MODE)" = "release" ]; then \
		$(TOOLCHAIN)/bin/llvm-strip $@ 2>/dev/null || true; \
	fi
	@echo "Built: $@"

# Deploy all binaries for local/Termux usage
deploy-local: server payload client-android
	@echo "Deploying all binaries for local usage..."
	adb push $(RENEF_SERVER) /data/local/tmp/renef_server
	adb push $(RENEF_CLIENT_ANDROID) /data/local/tmp/renef
	adb shell chmod +x /data/local/tmp/renef_server
	adb shell chmod +x /data/local/tmp/renef
	adb push $(PAYLOAD_SO) /data/local/tmp/libagent.so
	adb shell chmod 777 /data/local/tmp/libagent.so
	-adb shell su -c "chcon u:object_r:app_data_file:s0 /data/local/tmp/libagent.so" 2>/dev/null || true
	@echo ""
	@echo "Deployed to /data/local/tmp/"
	@echo "Usage in Termux/ADB shell:"
	@echo "  1. su"
	@echo "  2. /data/local/tmp/renef_server &"
	@echo "  3. /data/local/tmp/renef --local"

info:
	@echo "Build Configuration:"
	@echo "  Host: $(HOST_OS)/$(HOST_ARCH)"
	@echo "  NDK: $(NDK)"
	@echo "  NDK Host: $(NDK_HOST)"
	@echo "  Mode: $(BUILD_MODE)"
	@echo "  Client: Native build for host"
	@echo "  Client Android: Cross-compile to ARM64 (no readline)"
	@echo "  Server: Cross-compile to ARM64 Android"
	@echo "  Payload: Cross-compile to ARM64 Android"
