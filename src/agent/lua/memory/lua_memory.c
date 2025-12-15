#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <android/log.h>
#include <lauxlib.h>
#include "lua_memory.h"

#define TAG "LUA_MEMORY"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

extern int g_output_client_fd;

static void send_to_cli(const char* msg) {
    LOGI("[CLI_SEND] g_output_client_fd=%d, msg=%s", g_output_client_fd, msg ? msg : "NULL");
    if (g_output_client_fd >= 0 && msg) {
        size_t len = strlen(msg);
        ssize_t written = write(g_output_client_fd, msg, len);
        write(g_output_client_fd, "\n", 1);
        LOGI("[CLI_SEND] wrote %zd bytes to fd %d", written, g_output_client_fd);
    } else {
        LOGI("[CLI_SEND] SKIPPED - fd=%d", g_output_client_fd);
    }
}

static bool pattern_matches(const unsigned char* data, const int* pattern, size_t patternLen) {
    for (size_t i = 0; i < patternLen; i++) {
        if (pattern[i] != WILDCARD_BYTE && pattern[i] != data[i]) {
            return false;
        }
    }
    return true;
}

static void* my_memmem(const void* haystack, size_t haystack_len,
                       const void* needle, size_t needle_len) {
    if (needle_len == 0) return (void*)haystack;
    if (haystack_len < needle_len) return NULL;

    const unsigned char* h = (const unsigned char*)haystack;
    const unsigned char* n = (const unsigned char*)needle;
    const unsigned char* end = h + haystack_len - needle_len + 1;

    while (h < end) {
        if (memcmp(h, n, needle_len) == 0) {
            return (void*)h;
        }
        h++;
    }
    return NULL;
}

MemorySearchResult memory_search(const unsigned char* pattern, size_t patternLen) {
    MemorySearchResult result;
    memset(&result, 0, sizeof(result));

    result.capacity = 256;
    result.items = (MemoryResult*)malloc(result.capacity * sizeof(MemoryResult));
    if (!result.items) {
        return result;
    }

    FILE* maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) {
        free(result.items);
        result.items = NULL;
        return result;
    }

    char buffer[512];

    while (fgets(buffer, sizeof(buffer), maps) && result.count < DEFAULT_MAX_RESULTS) {
        if (strstr(buffer, "00000000") == NULL || strstr(buffer, ".so") == NULL) {
            continue;
        }

        char addr[64], perms[8], offset[16], dev[16], inode[16], path[256];
        path[0] = '\0';

        int parsed = sscanf(buffer, "%63s %7s %15s %15s %15s %255[^\n]",
                           addr, perms, offset, dev, inode, path);
        if (parsed < 5) {
            continue;
        }

        if (perms[0] != 'r') {
            continue;
        }

        char* dash = strchr(addr, '-');
        if (dash == NULL) {
            continue;
        }

        *dash = '\0';
        char* start_str = addr;
        char* end_str = dash + 1;

        uintptr_t startAddr = strtoull(start_str, NULL, 16);
        uintptr_t endAddr = strtoull(end_str, NULL, 16);
        if (endAddr <= startAddr) {
            continue;
        }

        size_t regionSize = endAddr - startAddr;
        if (regionSize < patternLen) {
            continue;
        }

        const unsigned char* regionBegin = (const unsigned char*)startAddr;
        const unsigned char* regionEnd = regionBegin + regionSize;
        const unsigned char* searchStart = regionBegin;

        while (searchStart < regionEnd && result.count < DEFAULT_MAX_RESULTS) {
            size_t remaining = regionEnd - searchStart;
            const unsigned char* found = (const unsigned char*)my_memmem(
                searchStart, remaining, pattern, patternLen
            );

            if (found == NULL) {
                break;
            }

            LOGI("Pattern found at %p in %s", (const void*)found, path);

            const size_t contextSize = 16;
            const unsigned char* contextStart = (found - regionBegin >= contextSize)
                ? found - contextSize : regionBegin;
            const unsigned char* contextEnd = (regionEnd - (found + patternLen) >= contextSize)
                ? found + patternLen + contextSize : regionEnd;

            size_t totalContextSize = contextEnd - contextStart;
            size_t patternOffset = found - contextStart;

            char hexDump[512];
            char* hexPtr = hexDump;
            hexDump[0] = '\0';
            for (size_t i = 0; i < totalContextSize && (hexPtr - hexDump) < 480; i++) {
                if (i == patternOffset) hexPtr += sprintf(hexPtr, "[");
                hexPtr += sprintf(hexPtr, "%02X ", contextStart[i]);
                if (i == patternOffset + patternLen - 1) hexPtr += sprintf(hexPtr, "] ");
            }

            char asciiDump[128];
            char* asciiPtr = asciiDump;
            asciiDump[0] = '\0';
            for (size_t i = 0; i < totalContextSize && i < 100; i++) {
                unsigned char c = contextStart[i];
                if (i == patternOffset) *asciiPtr++ = '[';
                *asciiPtr++ = (c >= 32 && c <= 126) ? (char)c : '.';
                if (i == patternOffset + patternLen - 1) *asciiPtr++ = ']';
            }
            *asciiPtr = '\0';

            LOGI("Offset: 0x%lx", (unsigned long)(found - regionBegin));
            LOGI("HEX: %s", hexDump);
            LOGI("ASCII: %s", asciiDump);

            if (result.count >= result.capacity) {
                int new_capacity = result.capacity * 2;
                MemoryResult* new_items = (MemoryResult*)realloc(result.items, new_capacity * sizeof(MemoryResult));
                if (!new_items) {
                    break;
                }
                result.items = new_items;
                result.capacity = new_capacity;
            }

            result.items[result.count].library_name = strdup(path);
            result.items[result.count].hex_result = strdup(hexDump);
            result.items[result.count].ascii_result = strdup(asciiDump);
            result.items[result.count].found_offset_addr = (uintptr_t)(found - regionBegin);
            result.items[result.count].absolute_addr = (uintptr_t)found;
            result.count++;

            searchStart = found + 1;
        }
    }

    fclose(maps);
    return result;
}

void free_search_result(MemorySearchResult* result) {
    if (result->items) {
        for (int i = 0; i < result->count; i++) {
            free(result->items[i].library_name);
            free(result->items[i].hex_result);
            free(result->items[i].ascii_result);
        }
        free(result->items);
        result->items = NULL;
    }
    result->count = 0;
    result->capacity = 0;
}

static bool add_result(MemorySearchResult* result, const char* path,
                       const unsigned char* found, const unsigned char* regionBegin,
                       const unsigned char* regionEnd, size_t patternLen) {
    if (result->count >= result->capacity) {
        int new_capacity = result->capacity * 2;
        MemoryResult* new_items = (MemoryResult*)realloc(result->items, new_capacity * sizeof(MemoryResult));
        if (!new_items) return false;
        result->items = new_items;
        result->capacity = new_capacity;
    }

    const size_t contextSize = 16;
    const unsigned char* contextStart = (found - regionBegin >= contextSize) ? found - contextSize : regionBegin;
    const unsigned char* contextEnd = (regionEnd - (found + patternLen) >= contextSize) ? found + patternLen + contextSize : regionEnd;
    size_t totalContextSize = contextEnd - contextStart;
    size_t patternOffset = found - contextStart;

    char hexDump[512];
    char* hexPtr = hexDump;
    hexDump[0] = '\0';
    for (size_t i = 0; i < totalContextSize && (hexPtr - hexDump) < 480; i++) {
        if (i == patternOffset) hexPtr += sprintf(hexPtr, "[");
        hexPtr += sprintf(hexPtr, "%02X ", contextStart[i]);
        if (i == patternOffset + patternLen - 1) hexPtr += sprintf(hexPtr, "] ");
    }

    char asciiDump[128];
    char* asciiPtr = asciiDump;
    for (size_t i = 0; i < totalContextSize && i < 100; i++) {
        unsigned char c = contextStart[i];
        if (i == patternOffset) *asciiPtr++ = '[';
        *asciiPtr++ = (c >= 32 && c <= 126) ? (char)c : '.';
        if (i == patternOffset + patternLen - 1) *asciiPtr++ = ']';
    }
    *asciiPtr = '\0';

    result->items[result->count].library_name = strdup(path);
    result->items[result->count].hex_result = strdup(hexDump);
    result->items[result->count].ascii_result = strdup(asciiDump);
    result->items[result->count].found_offset_addr = (uintptr_t)(found - regionBegin);
    result->items[result->count].absolute_addr = (uintptr_t)found;
    result->count++;
    return true;
}

MemorySearchResult memory_search_pattern(const int* pattern, size_t patternLen) {
    MemorySearchResult result;
    memset(&result, 0, sizeof(result));
    result.capacity = 256;
    result.items = (MemoryResult*)malloc(result.capacity * sizeof(MemoryResult));
    if (!result.items) return result;

    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        free(result.items);
        result.items = NULL;
        return result;
    }

    int firstByte = -1;
    size_t firstByteIdx = 0;
    for (size_t i = 0; i < patternLen; i++) {
        if (pattern[i] != WILDCARD_BYTE) {
            firstByte = pattern[i];
            firstByteIdx = i;
            if (pattern[i] != 0x00 && pattern[i] != 0xFF && pattern[i] != 0x48) {
                break;
            }
        }
    }

    LOGI("Pattern search: len=%zu, firstByte=0x%02X at idx=%zu", patternLen, firstByte, firstByteIdx);

    char buffer[512];
    size_t totalBytesSearched = 0;
    const size_t MAX_SEARCH_BYTES = 50 * 1024 * 1024;  // 50MB limit to prevent timeout

    while (fgets(buffer, sizeof(buffer), maps) && result.count < DEFAULT_MAX_RESULTS) {
        if (totalBytesSearched > MAX_SEARCH_BYTES) {
            LOGI("Pattern search: reached 50MB limit, stopping");
            break;
        }

        if (!strstr(buffer, ".so")) continue;

        char addr[64], perms[8], offset[16], dev[16], inode[16], path[256];
        path[0] = '\0';

        if (sscanf(buffer, "%63s %7s %15s %15s %15s %255[^\n]", addr, perms, offset, dev, inode, path) < 5)
            continue;
        if (perms[0] != 'r') continue;

        char* dash = strchr(addr, '-');
        if (!dash) continue;
        *dash = '\0';

        uintptr_t startAddr = strtoull(addr, NULL, 16);
        uintptr_t endAddr = strtoull(dash + 1, NULL, 16);
        if (endAddr <= startAddr) continue;

        size_t regionSize = endAddr - startAddr;
        if (regionSize < patternLen) continue;

        totalBytesSearched += regionSize;

        const unsigned char* regionBegin = (const unsigned char*)startAddr;
        const unsigned char* maxSearchPos = regionBegin + regionSize - patternLen;
        const unsigned char* regionEnd = regionBegin + regionSize;

        if (firstByte >= 0) {
            const unsigned char* p = regionBegin + firstByteIdx;  // Start at offset where anchor byte would be
            while (p < regionEnd && result.count < DEFAULT_MAX_RESULTS) {
                size_t searchLen = regionEnd - p;
                const unsigned char* candidate = (const unsigned char*)memchr(p, firstByte, searchLen);
                if (!candidate) break;

                const unsigned char* checkPos = candidate - firstByteIdx;
                if (checkPos >= regionBegin && checkPos <= maxSearchPos) {
                    if (pattern_matches(checkPos, pattern, patternLen)) {
                        add_result(&result, path, checkPos, regionBegin, regionEnd, patternLen);
                    }
                }
                p = candidate + 1;
            }
        } else {
            for (const unsigned char* p = regionBegin; p <= maxSearchPos && result.count < DEFAULT_MAX_RESULTS; p++) {
                if (pattern_matches(p, pattern, patternLen)) {
                    add_result(&result, path, p, regionBegin, regionEnd, patternLen);
                }
            }
        }
    }

    LOGI("Pattern search done: %d results, searched %zu bytes", result.count, totalBytesSearched);
    fclose(maps);
    return result;
}

MemorySearchResult memory_search_string(const char* str) {
    return memory_search((const unsigned char*)str, strlen(str));
}

MemorySearchResult memory_search_in_lib(const char* libName, const unsigned char* pattern, size_t patternLen) {
    MemorySearchResult result;
    memset(&result, 0, sizeof(result));
    result.capacity = 256;
    result.items = (MemoryResult*)malloc(result.capacity * sizeof(MemoryResult));
    if (!result.items) return result;

    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        free(result.items);
        result.items = NULL;
        return result;
    }

    char buffer[512];
    while (fgets(buffer, sizeof(buffer), maps) && result.count < DEFAULT_MAX_RESULTS) {
        if (!strstr(buffer, libName)) continue;

        char addr[64], perms[8], offset[16], dev[16], inode[16], path[256];
        path[0] = '\0';

        if (sscanf(buffer, "%63s %7s %15s %15s %15s %255[^\n]", addr, perms, offset, dev, inode, path) < 5)
            continue;
        if (perms[0] != 'r') continue;

        char* dash = strchr(addr, '-');
        if (!dash) continue;
        *dash = '\0';

        uintptr_t startAddr = strtoull(addr, NULL, 16);
        uintptr_t endAddr = strtoull(dash + 1, NULL, 16);
        if (endAddr <= startAddr) continue;

        size_t regionSize = endAddr - startAddr;
        if (regionSize < patternLen) continue;

        const unsigned char* regionBegin = (const unsigned char*)startAddr;
        const unsigned char* regionEnd = regionBegin + regionSize;
        const unsigned char* searchStart = regionBegin;

        while (searchStart < regionEnd && result.count < DEFAULT_MAX_RESULTS) {
            size_t remaining = regionEnd - searchStart;
            const unsigned char* found = (const unsigned char*)my_memmem(searchStart, remaining, pattern, patternLen);
            if (!found) break;
            add_result(&result, path, found, regionBegin, regionEnd, patternLen);
            searchStart = found + 1;
        }
    }

    fclose(maps);
    return result;
}

MemorySearchResult memory_search_pattern_in_lib(const char* libName, const int* pattern, size_t patternLen) {
    MemorySearchResult result;
    memset(&result, 0, sizeof(result));
    result.capacity = 256;
    result.items = (MemoryResult*)malloc(result.capacity * sizeof(MemoryResult));
    if (!result.items) return result;

    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        free(result.items);
        result.items = NULL;
        return result;
    }

    char buffer[512];
    while (fgets(buffer, sizeof(buffer), maps) && result.count < DEFAULT_MAX_RESULTS) {
        if (!strstr(buffer, libName)) continue;

        char addr[64], perms[8], offset[16], dev[16], inode[16], path[256];
        path[0] = '\0';

        if (sscanf(buffer, "%63s %7s %15s %15s %15s %255[^\n]", addr, perms, offset, dev, inode, path) < 5)
            continue;
        if (perms[0] != 'r') continue;

        char* dash = strchr(addr, '-');
        if (!dash) continue;
        *dash = '\0';

        uintptr_t startAddr = strtoull(addr, NULL, 16);
        uintptr_t endAddr = strtoull(dash + 1, NULL, 16);
        if (endAddr <= startAddr) continue;

        size_t regionSize = endAddr - startAddr;
        if (regionSize < patternLen) continue;

        const unsigned char* regionBegin = (const unsigned char*)startAddr;
        const unsigned char* regionEnd = regionBegin + regionSize;

        for (const unsigned char* p = regionBegin; p <= regionEnd - patternLen && result.count < DEFAULT_MAX_RESULTS; p++) {
            if (pattern_matches(p, pattern, patternLen)) {
                add_result(&result, path, p, regionBegin, regionEnd, patternLen);
            }
        }
    }

    fclose(maps);
    return result;
}

static int parse_pattern(const char* patternStr, int* outPattern, size_t maxLen) {
    int count = 0;
    const char* p = patternStr;

    while (*p && count < (int)maxLen) {
        while (*p == ' ') p++;
        if (!*p) break;

        if (p[0] == '?' && p[1] == '?') {
            outPattern[count++] = WILDCARD_BYTE;
            p += 2;
        } else if ((p[0] >= '0' && p[0] <= '9') || (p[0] >= 'A' && p[0] <= 'F') || (p[0] >= 'a' && p[0] <= 'f')) {
            char hex[3] = {p[0], p[1], 0};
            outPattern[count++] = (int)strtol(hex, NULL, 16);
            p += 2;
        } else {
            p++;
        }
    }
    return count;
}

static int lua_mem_search(lua_State* L) {
    const char* input = luaL_checkstring(L, 1);
    const char* libFilter = lua_isstring(L, 2) ? lua_tostring(L, 2) : NULL;

    MemorySearchResult result;

    if (strstr(input, " ") || strstr(input, "??")) {
        int pattern[256];
        int patternLen = parse_pattern(input, pattern, 256);

        if (libFilter) {
            result = memory_search_pattern_in_lib(libFilter, pattern, patternLen);
        } else {
            result = memory_search_pattern(pattern, patternLen);
        }
    } else {
        if (libFilter) {
            result = memory_search_in_lib(libFilter, (const unsigned char*)input, strlen(input));
        } else {
            result = memory_search_string(input);
        }
    }

    lua_newtable(L);
    for (int i = 0; i < result.count; i++) {
        lua_newtable(L);

        lua_pushstring(L, result.items[i].library_name);
        lua_setfield(L, -2, "library");

        lua_pushinteger(L, result.items[i].absolute_addr);
        lua_setfield(L, -2, "addr");

        lua_pushinteger(L, result.items[i].found_offset_addr);
        lua_setfield(L, -2, "offset");

        lua_pushstring(L, result.items[i].hex_result);
        lua_setfield(L, -2, "hex");

        lua_pushstring(L, result.items[i].ascii_result);
        lua_setfield(L, -2, "ascii");

        lua_rawseti(L, -2, i + 1);
    }

    free_search_result(&result);
    return 1;
}

static int lua_mem_dump(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);

    int n = luaL_len(L, 1);
    char buf[1024];

    for (int i = 1; i <= n; i++) {
        lua_rawgeti(L, 1, i);

        lua_getfield(L, -1, "library");
        const char* lib = lua_tostring(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, -1, "addr");
        uintptr_t addr = (uintptr_t)lua_tointeger(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, -1, "offset");
        uintptr_t offset = (uintptr_t)lua_tointeger(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, -1, "hex");
        const char* hex = lua_tostring(L, -1);
        lua_pop(L, 1);

        const char* filename = lib ? strrchr(lib, '/') : NULL;
        filename = filename ? filename + 1 : (lib ? lib : "???");

        snprintf(buf, sizeof(buf), "[%d] %s + 0x%lx (0x%lx)\n    %s",
                 i, filename, (unsigned long)offset, (unsigned long)addr, hex ? hex : "");

        lua_getglobal(L, "print");
        lua_pushstring(L, buf);
        lua_call(L, 1, 0);

        lua_pop(L, 1);  // pop the table entry
    }

    return 0;
}

static int lua_mem_read(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    size_t size = (size_t)luaL_checkinteger(L, 2);

    if (size > 0x100000) size = 0x100000;  // Max 1MB

    lua_pushlstring(L, (const char*)addr, size);
    return 1;
}

static int lua_mem_write(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    size_t len;
    const char* data = luaL_checklstring(L, 2, &len);

    memcpy((void*)addr, data, len);
    lua_pushboolean(L, 1);
    return 1;
}

static int lua_mem_read_u8(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushinteger(L, *(uint8_t*)addr);
    return 1;
}

static int lua_mem_read_u16(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushinteger(L, *(uint16_t*)addr);
    return 1;
}

static int lua_mem_read_u32(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushinteger(L, *(uint32_t*)addr);
    return 1;
}

static int lua_mem_read_u64(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushinteger(L, *(uint64_t*)addr);
    return 1;
}

static int lua_mem_write_u8(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    *(uint8_t*)addr = (uint8_t)luaL_checkinteger(L, 2);
    return 0;
}

static int lua_mem_write_u16(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    *(uint16_t*)addr = (uint16_t)luaL_checkinteger(L, 2);
    return 0;
}

static int lua_mem_write_u32(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    *(uint32_t*)addr = (uint32_t)luaL_checkinteger(L, 2);
    return 0;
}

static int lua_mem_write_u64(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    *(uint64_t*)addr = (uint64_t)luaL_checkinteger(L, 2);
    return 0;
}

static int lua_mem_read_str(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    size_t maxLen = luaL_optinteger(L, 2, 256);

    const char* str = (const char*)addr;
    size_t len = strnlen(str, maxLen);
    lua_pushlstring(L, str, len);
    return 1;
}

static int lua_mem_patch(lua_State* L) {
    uintptr_t address = (uintptr_t)luaL_checkinteger(L, 1);
    size_t patch_len;
    const char* patch_bytes = luaL_checklstring(L, 2, &patch_len);

    LOGI("Memory.patch: address=0x%lx, len=%zu", (unsigned long)address, patch_len);

    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = address & ~(page_size - 1);
    size_t region_size = ((address + patch_len - page_start) + page_size - 1) & ~(page_size - 1);

    if (mprotect((void*)page_start, region_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "ERROR: mprotect failed at 0x%lx", (unsigned long)address);
        send_to_cli(err_msg);
        lua_pushboolean(L, 0);
        lua_pushstring(L, "mprotect failed");
        return 2;
    }

    memcpy((void*)address, patch_bytes, patch_len);


    char success_msg[256];
    snprintf(success_msg, sizeof(success_msg), "✓ Patched %zu bytes at 0x%lx", patch_len, (unsigned long)address);
    send_to_cli(success_msg);

    lua_pushboolean(L, 1);
    return 1;
}

void register_memory_search_api(lua_State* L) {
    lua_newtable(L);

    lua_pushcfunction(L, lua_mem_search);
    lua_setfield(L, -2, "search");

    lua_pushcfunction(L, lua_mem_search);
    lua_setfield(L, -2, "scan");

    lua_pushcfunction(L, lua_mem_dump);
    lua_setfield(L, -2, "dump");

    lua_pushcfunction(L, lua_mem_read);
    lua_setfield(L, -2, "read");

    lua_pushcfunction(L, lua_mem_write);
    lua_setfield(L, -2, "write");

    lua_pushcfunction(L, lua_mem_patch);
    lua_setfield(L, -2, "patch");

    lua_pushcfunction(L, lua_mem_read_u8);
    lua_setfield(L, -2, "readU8");

    lua_pushcfunction(L, lua_mem_read_u16);
    lua_setfield(L, -2, "readU16");

    lua_pushcfunction(L, lua_mem_read_u32);
    lua_setfield(L, -2, "readU32");

    lua_pushcfunction(L, lua_mem_read_u64);
    lua_setfield(L, -2, "readU64");

    lua_pushcfunction(L, lua_mem_write_u8);
    lua_setfield(L, -2, "writeU8");

    lua_pushcfunction(L, lua_mem_write_u16);
    lua_setfield(L, -2, "writeU16");

    lua_pushcfunction(L, lua_mem_write_u32);
    lua_setfield(L, -2, "writeU32");

    lua_pushcfunction(L, lua_mem_write_u64);
    lua_setfield(L, -2, "writeU64");

    lua_pushcfunction(L, lua_mem_read_str);
    lua_setfield(L, -2, "readStr");

    lua_pushcfunction(L, lua_mem_read_str);
    lua_setfield(L, -2, "readString");

    lua_setglobal(L, "Memory");
}
