/**
 * File API for Lua
 *
 * Provides file system operations:
 * - File.readlink(path) - read symlink target
 * - File.read(path) - read file contents
 * - File.exists(path) - check if file exists
 * - File.fdpath(fd) - get path for file descriptor
 */

#include <agent/lua_file.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <lauxlib.h>
#include <lualib.h>

// Core functions

FileReadResult file_read(const char* path) {
    FileReadResult result;
    memset(&result, 0, sizeof(result));

    FILE* file = fopen(path, "r");
    if (file == NULL) {
        result.success = false;
        return result;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (size <= 0) {
        size_t capacity = 4096;
        size_t total = 0;
        result.content = malloc(capacity);
        if (!result.content) {
            fclose(file);
            result.success = false;
            return result;
        }

        char buf[1024];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), file)) > 0) {
            if (total + n >= capacity) {
                capacity *= 2;
                char* newbuf = realloc(result.content, capacity);
                if (!newbuf) {
                    free(result.content);
                    fclose(file);
                    result.success = false;
                    return result;
                }
                result.content = newbuf;
            }
            memcpy(result.content + total, buf, n);
            total += n;
        }
        fclose(file);
        result.content[total] = '\0';
        result.size = total;
        result.success = true;
        return result;
    }

    if (size > FILE_PATH_MAX * 10) {
        fclose(file);
        result.success = false;
        return result;
    }

    result.content = malloc(size + 1);
    if (!result.content) {
        fclose(file);
        result.success = false;
        return result;
    }

    size_t read_size = fread(result.content, 1, size, file);
    fclose(file);

    result.content[read_size] = '\0';
    result.size = read_size;
    result.success = true;
    return result;
}

FileReadlinkResult file_readlink(const char* path) {
    FileReadlinkResult result;
    memset(&result, 0, sizeof(result));

    char buf[PATH_MAX];
    ssize_t len = readlink(path, buf, sizeof(buf) - 1);

    if (len == -1) {
        result.success = false;
        return result;
    }

    buf[len] = '\0';
    result.target = strdup(buf);
    result.success = (result.target != NULL);
    return result;
}

bool file_exists(const char* path) {
    struct stat st;
    return stat(path, &st) == 0;
}

// Lua bindings

// File.readlink(path) -> string or nil
static int l_file_readlink(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);

    FileReadlinkResult result = file_readlink(path);
    if (!result.success) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushstring(L, result.target);
    free(result.target);
    return 1;
}

// File.read(path) -> string or nil
static int l_file_read(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);

    FileReadResult result = file_read(path);
    if (!result.success) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushlstring(L, result.content, result.size);
    free(result.content);
    return 1;
}

// File.exists(path) -> boolean
static int l_file_exists(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    lua_pushboolean(L, file_exists(path));
    return 1;
}

// File.fdpath(fd) -> string or nil
// Convenience: reads /proc/self/fd/{fd} symlink
static int l_file_fdpath(lua_State *L) {
    int fd = luaL_checkinteger(L, 1);

    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    FileReadlinkResult result = file_readlink(path);
    if (!result.success) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushstring(L, result.target);
    free(result.target);
    return 1;
}

static const luaL_Reg file_funcs[] = {
    {"readlink", l_file_readlink},
    {"read", l_file_read},
    {"exists", l_file_exists},
    {"fdpath", l_file_fdpath},
    {NULL, NULL}
};

void register_file_api(lua_State* L) {
    luaL_newlib(L, file_funcs);
    lua_setglobal(L, "File");
}