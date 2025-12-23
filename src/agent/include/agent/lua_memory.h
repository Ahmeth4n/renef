#ifndef LUA_MEMORY_H
#define LUA_MEMORY_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <lua.h>

#define DEFAULT_MAX_RESULTS 1000
#define WILDCARD_BYTE 0x100

typedef struct {
    char* library_name;
    uintptr_t found_offset_addr;
    uintptr_t absolute_addr;
    char* hex_result;
    char* ascii_result;
} MemoryResult;

typedef struct {
    MemoryResult* items;
    int count;
    int capacity;
} MemorySearchResult;

MemorySearchResult memory_search(const unsigned char* pattern, size_t patternLen);
MemorySearchResult memory_search_pattern(const int* pattern, size_t patternLen);
MemorySearchResult memory_search_string(const char* str);
MemorySearchResult memory_search_in_lib(const char* libName, const unsigned char* pattern, size_t patternLen);
MemorySearchResult memory_search_pattern_in_lib(const char* libName, const int* pattern, size_t patternLen);
void free_search_result(MemorySearchResult* result);
void register_memory_search_api(lua_State* L);

#endif
