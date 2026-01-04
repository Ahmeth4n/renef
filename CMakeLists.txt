cmake_minimum_required(VERSION 3.16)
project(renef VERSION 0.1.1)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Asio header-only library
add_library(asio INTERFACE)
target_include_directories(asio INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/external/asio/include
)
target_compile_definitions(asio INTERFACE ASIO_STANDALONE)

# Capstone disassembler library
add_library(capstone STATIC IMPORTED)
set_target_properties(capstone PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/external/capstone/lib/libcapstone.a
)
target_include_directories(capstone INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/external/capstone/include
)

# Compiler warnings
add_compile_options(-Wall -Wextra)

# librenef - core library
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
)

target_include_directories(renef_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/librenef/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/librenef
    ${CMAKE_CURRENT_SOURCE_DIR}/src/inject
    ${CMAKE_CURRENT_SOURCE_DIR}/external
)

target_link_libraries(renef_core PUBLIC
    capstone
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

# Export symbols for plugins to use (ren_exec, ren_print, etc.)
set_target_properties(renef PROPERTIES ENABLE_EXPORTS ON)
if(UNIX AND NOT APPLE)
    target_link_options(renef PRIVATE -rdynamic)
endif()

# Note: Android components (renef_server and libagent.so) are built
# separately via Makefile using Android NDK cross-compilation.
# This CMakeLists.txt only builds the native client (renef) for the host platform.
