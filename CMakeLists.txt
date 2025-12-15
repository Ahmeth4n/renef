cmake_minimum_required(VERSION 3.11)
project(renef VERSION 0.1.1)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Asio header-only kütüphanesi
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

# Lua 5.4 library
add_library(lua STATIC IMPORTED)
set_target_properties(lua PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/external/lua/lib-android/lib/liblua.a
)
target_include_directories(lua INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/external/lua/lib-android/include
)

# Compiler uyarıları
add_compile_options(-Wall -Wextra)

# Core library (commands, utilities)
add_library(renef_core STATIC
    src/core/cmd.cpp
    src/core/cmds/ping/ping.cpp
    src/core/cmds/attach/attach.cpp
    src/core/cmds/spawn/spawn.cpp
    src/core/cmds/list/la.cpp
    src/core/cmds/inspect/ib.cpp
    src/core/cmds/eval/eval.cpp
    src/core/cmds/load/load.cpp
    src/core/cmds/watch/watch.cpp
    src/core/cmds/memscan/memscan.cpp
    src/core/cmds/hooks/hooks.cpp
    src/core/cmds/sec/sec.cpp
    src/core/cmds/memdump/memdump.cpp
    src/core/cmds/hookgen/hookgen.cpp
    src/core/util/string/string_utils.cpp
    src/core/util/crypto/crypto.cpp
    src/core/util/socket/socket_helper.cpp
    src/core/transport/uds_transport.cpp
    src/core/transport/tcp_transport.cpp
    src/core/transport/transport_server.cpp
    src/injector/injector.cpp
)

target_include_directories(renef_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/util
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/util/string
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/util/socket
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/util/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/transport
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/cmds/watch
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/cmds/load
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/cmds/memscan
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/cmds/hooks
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/cmds/sec
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/cmds/hookgen
    ${CMAKE_CURRENT_SOURCE_DIR}/src/injector
    ${CMAKE_CURRENT_SOURCE_DIR}/external
)

target_link_libraries(renef_core PUBLIC
    capstone
)

# readline kütüphanesini bul
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
    src/cli/renef.cpp
    src/cli/tui/memscan_tui.cpp
)

target_include_directories(renef PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/util
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/util/string
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/util/socket
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/util/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/transport
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/cmds/hooks
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cli/tui
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
)

# Note: Android components (renef_server and libagent.so) are built
# separately via Makefile using Android NDK cross-compilation.
# This CMakeLists.txt only builds the native client (renef) for the host platform.
