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

SRC_DIR := src
BUILD_DIR := build
PAYLOAD_DIR := src/agent
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

SERVER_SRCS := $(SRC_DIR)/server/renef_server.cpp \
               $(SRC_DIR)/core/transport/transport_server.cpp \
               $(SRC_DIR)/core/transport/uds_transport.cpp \
               $(SRC_DIR)/core/transport/tcp_transport.cpp \
               $(SRC_DIR)/core/cmd.cpp \
               $(SRC_DIR)/core/cmds/ping/ping.cpp \
               $(SRC_DIR)/core/cmds/attach/attach.cpp \
               $(SRC_DIR)/core/cmds/spawn/spawn.cpp \
               $(SRC_DIR)/core/cmds/list/la.cpp \
               $(SRC_DIR)/core/cmds/inspect/ib.cpp \
               $(SRC_DIR)/core/cmds/eval/eval.cpp \
               $(SRC_DIR)/core/cmds/load/load.cpp \
               $(SRC_DIR)/core/cmds/watch/watch.cpp \
               $(SRC_DIR)/core/cmds/memscan/memscan.cpp \
               $(SRC_DIR)/core/cmds/hooks/hooks.cpp \
               $(SRC_DIR)/core/cmds/sec/sec.cpp \
               $(SRC_DIR)/core/cmds/memdump/memdump.cpp \
               $(SRC_DIR)/core/cmds/hookgen/hookgen.cpp \
               $(SRC_DIR)/core/util/string/string_utils.cpp \
               $(SRC_DIR)/core/util/crypto/crypto.cpp \
               $(SRC_DIR)/core/util/socket/socket_helper.cpp \
               $(SRC_DIR)/injector/injector.cpp

SERVER_CXXFLAGS := -std=c++17 \
                   $(SERVER_OPT_FLAGS) \
                   -I$(SRC_DIR)/core \
                   -I$(SRC_DIR)/core/transport \
                   -I$(SRC_DIR)/server \
                   -I$(SRC_DIR)/core/util \
                   -I$(SRC_DIR)/core/crypto \
                   -I$(SRC_DIR)/core/util/string \
                   -I$(SRC_DIR)/core/util/socket \
                   -I$(SRC_DIR)/core/cmds/ping \
                   -I$(SRC_DIR)/core/cmds/attach \
                   -I$(SRC_DIR)/core/cmds/spawn \
                   -I$(SRC_DIR)/core/cmds/list \
                   -I$(SRC_DIR)/core/cmds/inspect \
                   -I$(SRC_DIR)/core/cmds/watch \
                   -I$(SRC_DIR)/core/cmds/memscan \
                   -I$(SRC_DIR)/core/cmds/hooks \
                   -I$(SRC_DIR)/core/cmds/sec \
                   -I$(SRC_DIR)/core/cmds/hookgen \
                   -I$(SRC_DIR)/injector \
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
                  -I$(PAYLOAD_DIR) \
                  -Iexternal/capstone/include \
                  -I$(LUA_INCLUDE) \
                  -I$(NDK)/toolchains/llvm/prebuilt/$(NDK_HOST)/sysroot/usr/include
PAYLOAD_LDFLAGS := -llog $(CAPSTONE_LIB) $(LUA_LIB) -lm -ldl

AGENT_SRCS := $(PAYLOAD_DIR)/agent.c \
              $(PAYLOAD_DIR)/core/globals.c \
              $(PAYLOAD_DIR)/core/cmd_registry.c \
              $(PAYLOAD_DIR)/hook/hook.c \
              $(PAYLOAD_DIR)/hook/hook_java.c \
              $(PAYLOAD_DIR)/proc/proc.c \
              $(PAYLOAD_DIR)/handlers/cmd_eval.c \
              $(PAYLOAD_DIR)/handlers/cmd_inspect.c \
              $(PAYLOAD_DIR)/handlers/cmd_memscan.c \
              $(PAYLOAD_DIR)/handlers/cmd_memdump.c \
              $(PAYLOAD_DIR)/handlers/cmd_builtin.c \
              $(PAYLOAD_DIR)/lua/engine/lua_engine.c \
              $(PAYLOAD_DIR)/lua/hook/lua_hook.c \
              $(PAYLOAD_DIR)/lua/memory/lua_memory.c \
              $(PAYLOAD_DIR)/lua/thread/lua_thread.c

.PHONY: all clean clean-capstone clean-all client server payload deploy install test build-capstone setup setup-lua setup-asio setup-capstone-host release debug

all: client server payload

release:
	@$(MAKE) BUILD_MODE=release all

debug:
	@$(MAKE) BUILD_MODE=debug all

setup: setup-asio setup-lua setup-capstone-host build-capstone
	@echo "✅ All dependencies set up"

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
	@echo "✅ ASIO $(ASIO_VERSION) downloaded"

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
	@echo "✅ Lua $(LUA_VERSION) built"

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
	@echo "✅ Capstone $(CAPSTONE_VERSION) built for host"

client: $(ASIO_HEADER) $(CAPSTONE_HOST_LIB)
	@echo "Building renef client for $(HOST_OS)/$(HOST_ARCH) ($(BUILD_MODE))..."
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) .. && cmake --build .
	@if [ "$(BUILD_MODE)" = "release" ]; then \
		$(STRIP_CMD) $(RENEF_CLIENT) 2>/dev/null || true; \
	fi
	@echo "✅ Built: $(RENEF_CLIENT)"

server: $(RENEF_SERVER)

$(RENEF_SERVER): $(SERVER_SRCS) $(CAPSTONE_LIB)
	@echo "Building renef_server for Android ARM64 ($(BUILD_MODE))..."
	@mkdir -p $(ANDROID_BUILD)
	$(CLANGXX) $(SERVER_CXXFLAGS) $(SERVER_SRCS) -o $@ $(SERVER_LDFLAGS)
	@if [ "$(BUILD_MODE)" = "release" ]; then \
		$(TOOLCHAIN)/bin/llvm-strip $@ 2>/dev/null || true; \
	fi
	@echo "✅ Built: $@"

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
	@echo "✅ Capstone $(CAPSTONE_VERSION) built for Android"

payload: $(PAYLOAD_SO)

$(PAYLOAD_SO): $(AGENT_SRCS) $(CAPSTONE_LIB) $(LUA_LIB)
	@echo "Building agent payload for Android ARM64 ($(BUILD_MODE))..."
	@mkdir -p $(ANDROID_BUILD)
	$(CLANG) $(PAYLOAD_CFLAGS) -o $@ $(AGENT_SRCS) $(PAYLOAD_LDFLAGS)
	@if [ "$(BUILD_MODE)" = "release" ]; then \
		$(TOOLCHAIN)/bin/llvm-strip $@ 2>/dev/null || true; \
	fi
	@echo "✅ Built: $@"

deploy: server payload
	@echo "Deploying to Android..."
	adb push $(RENEF_SERVER) /data/local/tmp/renef_server
	-adb shell rm -f /data/local/tmp/.r 2>/dev/null || true
	adb push $(PAYLOAD_SO) /data/local/tmp/.r
	adb shell chmod +x /data/local/tmp/renef_server
	adb shell chmod +x /data/local/tmp/.r
	@echo "Setting SELinux context (Samsung fix)..."
	-adb shell su -c "chcon u:object_r:app_data_file:s0 /data/local/tmp/.r" 2>/dev/null || true
	@echo "✅ Deployed"

install: deploy
	@if ! adb forward --list | grep -q "tcp:1907"; then \
		echo "Setting up adb forward..."; \
		adb forward tcp:1907 localabstract:com.android.internal.os.RuntimeInit; \
		echo "✅ Port forwarded"; \
	else \
		echo "✅ Port already forwarded"; \
	fi
	@echo ""
	@echo "Run on device: adb shell /data/local/tmp/renef_server"
	@echo "Run on PC: ./$(RENEF_CLIENT)"

test: install
	@echo "=== Starting test ==="
	@adb shell "nohup /data/local/tmp/renef_server > /dev/null 2>&1 &"
	@sleep 2
	@echo "renef://ping" | $(RENEF_CLIENT)

clean:
	rm -rf $(BUILD_DIR)
	@echo "✅ Cleaned"

clean-capstone:
	@rm -rf $(CAPSTONE_BUILD)
	@rm -f $(CAPSTONE_LIB)
	@echo "✅ Capstone cleaned"

clean-all: clean clean-capstone
	@echo "✅ Full clean completed"

info:
	@echo "Build Configuration:"
	@echo "  Host: $(HOST_OS)/$(HOST_ARCH)"
	@echo "  NDK: $(NDK)"
	@echo "  NDK Host: $(NDK_HOST)"
	@echo "  Mode: $(BUILD_MODE)"
	@echo "  Client: Native build for host"
	@echo "  Server: Cross-compile to ARM64 Android"
	@echo "  Payload: Cross-compile to ARM64 Android"
