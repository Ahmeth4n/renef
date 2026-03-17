cmake_minimum_required(VERSION 3.16)
project(renef VERSION 0.3.5)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# ---------------------------------------------------------------------------
# Asio header-only library
# Uses local copy if available (from `make setup-asio`), otherwise downloads.
# ---------------------------------------------------------------------------
set(ASIO_LOCAL_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/external/asio/include/asio.hpp)

add_library(asio INTERFACE)
if(EXISTS ${ASIO_LOCAL_HEADER})
    target_include_directories(asio INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/external/asio/include
    )
else()
    message(STATUS "Local asio not found, downloading via FetchContent...")
    FetchContent_Declare(asio
        GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
        GIT_TAG        asio-1-30-2
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(asio)
    target_include_directories(asio INTERFACE ${asio_SOURCE_DIR}/asio/include)
endif()
target_compile_definitions(asio INTERFACE ASIO_STANDALONE)

# ---------------------------------------------------------------------------
# Capstone disassembler library
# Uses pre-built .a if available (from `make setup-capstone-host`),
# otherwise builds from source via FetchContent.
# ---------------------------------------------------------------------------
set(CAPSTONE_PREBUILT ${CMAKE_CURRENT_SOURCE_DIR}/external/capstone/lib/libcapstone.a)
set(CAPSTONE_LOCAL_SRC ${CMAKE_CURRENT_SOURCE_DIR}/external/capstone/capstone-5.0.3)

set(CAPSTONE_PREBUILT_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/external/capstone/include/capstone/capstone.h)

if(EXISTS ${CAPSTONE_PREBUILT} AND EXISTS ${CAPSTONE_PREBUILT_INCLUDE})
    # Use pre-built static library (from make setup-capstone-host)
    add_library(capstone STATIC IMPORTED)
    set_target_properties(capstone PROPERTIES
        IMPORTED_LOCATION ${CAPSTONE_PREBUILT}
    )
    target_include_directories(capstone INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/external/capstone/include
    )
else()
    message(STATUS "Pre-built capstone not found, building from source...")
    set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

    # Use local source if available, otherwise download
    if(EXISTS ${CAPSTONE_LOCAL_SRC}/CMakeLists.txt)
        set(FETCHCONTENT_SOURCE_DIR_CAPSTONE ${CAPSTONE_LOCAL_SRC})
    endif()

    FetchContent_Declare(capstone
        GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
        GIT_TAG        5.0.3
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(capstone)
endif()

# FTXUI TUI library (host-only)
option(RENEF_BUILD_TUI "Build with FTXUI-based TUI support" ON)

if(RENEF_BUILD_TUI)
    FetchContent_Declare(
        ftxui
        GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
        GIT_TAG v5.0.0
    )
    FetchContent_MakeAvailable(ftxui)
endif()

# Compiler warnings
add_compile_options(-Wall -Wextra)

# librenef - core library (build both static and shared)
add_library(renef_core STATIC
    # Command registry
    src/librenef/cmd/cmd.cpp

    # Commands (flattened)
    src/librenef/cmd/cmd_ping.cpp
    src/librenef/cmd/cmd_attach.cpp
    src/librenef/cmd/cmd_spawn.cpp
    src/librenef/cmd/cmd_eval.cpp
    src/librenef/cmd/cmd_load.cpp
    src/librenef/cmd/cmd_watch.cpp
    src/librenef/cmd/cmd_memscan.cpp
    src/librenef/cmd/cmd_hooks.cpp
    src/librenef/cmd/cmd_sec.cpp
    src/librenef/cmd/cmd_memdump.cpp
    src/librenef/cmd/cmd_hookgen.cpp
    src/librenef/cmd/cmd_inspect.cpp
    src/librenef/cmd/cmd_list.cpp
    src/librenef/cmd/cmd_plugin.cpp
    src/librenef/cmd/cmd_strace.cpp

    # Transport
    src/librenef/transport/uds.cpp
    src/librenef/transport/tcp.cpp
    src/librenef/transport/server.cpp

    # Utilities
    src/librenef/util/socket.cpp
    src/librenef/util/server_connection.cpp
    src/librenef/util/string.cpp
    src/librenef/util/crypto.cpp

    # Injector
    src/inject/injector.cpp

    # Plugin system
    src/librenef/plugin/plugin.cpp

    # C API Binding
    src/librenef/binding/renef.cpp
)

target_include_directories(renef_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/librenef/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/librenef
    ${CMAKE_CURRENT_SOURCE_DIR}/src/librenef/binding
    ${CMAKE_CURRENT_SOURCE_DIR}/src/inject
    ${CMAKE_CURRENT_SOURCE_DIR}/external
)

target_link_libraries(renef_core PUBLIC
    capstone
)

# Capstone AArch64 compat: ensures CS_ARCH_ARM64 is available in newer capstone versions
target_compile_definitions(renef_core PUBLIC CAPSTONE_AARCH64_COMPAT_HEADER)

# Shared library for Python/FFI bindings
add_library(renef_shared SHARED
    src/librenef/binding/renef.cpp
    src/librenef/util/socket.cpp
    src/librenef/util/crypto.cpp
    src/librenef/transport/uds.cpp
    src/librenef/transport/tcp.cpp
    src/inject/injector.cpp
)

target_include_directories(renef_shared PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/librenef/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/librenef
    ${CMAKE_CURRENT_SOURCE_DIR}/src/librenef/binding
    ${CMAKE_CURRENT_SOURCE_DIR}/src/inject
    ${CMAKE_CURRENT_SOURCE_DIR}/external
)

target_link_libraries(renef_shared PUBLIC capstone)
target_compile_definitions(renef_shared PUBLIC CAPSTONE_AARCH64_COMPAT_HEADER)
set_target_properties(renef_shared PROPERTIES
    OUTPUT_NAME "renef"
    VERSION 0.3.5
    SOVERSION 0
)

# Find readline library
find_path(Readline_INCLUDE_DIR readline/readline.h
    HINTS
        /opt/homebrew/opt/readline/include
        /usr/local/opt/readline/include
        /usr/include
)

find_library(Readline_LIBRARY readline
    HINTS
        /opt/homebrew/opt/readline/lib
        /usr/local/opt/readline/lib
        /usr/lib
        /usr/lib/x86_64-linux-gnu
)

if(NOT Readline_INCLUDE_DIR OR NOT Readline_LIBRARY)
    message(FATAL_ERROR "readline library not found. Please install it:
    - macOS: brew install readline
    - Ubuntu/Debian: sudo apt-get install libreadline-dev
    - Arch: sudo pacman -S readline")
endif()

message(STATUS "Found readline: ${Readline_LIBRARY}")
message(STATUS "readline include: ${Readline_INCLUDE_DIR}")

# renef CLI client executable
add_executable(renef
    src/binr/renef/main.cpp
    src/binr/renef/tui/memscan_tui.cpp
)

target_include_directories(renef PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/librenef/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/librenef
    ${CMAKE_CURRENT_SOURCE_DIR}/src/binr/renef/tui
    ${CMAKE_CURRENT_SOURCE_DIR}/external
    ${Readline_INCLUDE_DIR}
)

# Enable CLI-only commands
target_compile_definitions(renef PRIVATE RENEF_CLI_BUILD)

target_link_libraries(renef
    PRIVATE
        asio
        capstone
        renef_core
        ${Readline_LIBRARY}
        ${CMAKE_DL_LIBS}
)

# TUI support (FTXUI)
if(RENEF_BUILD_TUI)
    target_sources(renef PRIVATE
        src/binr/renef/tui/tui_app.cpp
        src/binr/renef/tui/tui_state.cpp
        src/binr/renef/tui/tui_status_bar.cpp
        src/binr/renef/tui/command_adapter.cpp
        src/binr/renef/tui/tabs/console_tab.cpp
        src/binr/renef/tui/tabs/hooks_tab.cpp
        src/binr/renef/tui/tabs/memory_tab.cpp
        src/binr/renef/tui/tabs/modules_tab.cpp
        src/binr/renef/tui/tabs/logs_tab.cpp
    )
    target_compile_definitions(renef PRIVATE RENEF_HAS_TUI)
    target_link_libraries(renef PRIVATE
        ftxui::screen
        ftxui::dom
        ftxui::component
    )
endif()

# Export symbols for plugins to use (ren_exec, ren_print, etc.)
set_target_properties(renef PROPERTIES ENABLE_EXPORTS ON)
if(UNIX AND NOT APPLE)
    target_link_options(renef PRIVATE -rdynamic)
endif()

# renef-strace standalone executable
add_executable(renef-strace
    src/binr/renef-strace/main.cpp
)

target_include_directories(renef-strace PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/librenef/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/librenef
    ${CMAKE_CURRENT_SOURCE_DIR}/external
)

target_link_libraries(renef-strace
    PRIVATE
        asio
        capstone
        renef_core
        ${CMAKE_DL_LIBS}
)
# Note: Android components (renef_server and libagent.so) are built
# separately via Makefile using Android NDK cross-compilation.
# This CMakeLists.txt only builds the native client (renef) for the host platform.
