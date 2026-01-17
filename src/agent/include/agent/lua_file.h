#ifndef LUA_FILE_H
#define LUA_FILE_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <lua.h>

#define FILE_PATH_MAX 4096

typedef struct {
    char* content;
    size_t size;
    bool success;
} FileReadResult;

typedef struct {
    char* target;
    bool success;
} FileReadlinkResult;

FileReadResult file_read(const char* path);
FileReadlinkResult file_readlink(const char* path);
bool file_exists(const char* path);
void register_file_api(lua_State* L);

#endif