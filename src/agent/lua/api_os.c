#include <lua.h>
#include <lauxlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// OS.getpid()
static int l_os_getpid(lua_State* L) {
    lua_pushinteger(L, getpid());
    return 1;
}

// OS.kill(pid, sig)
static int l_os_kill(lua_State* L) {
    int pid = luaL_checkinteger(L, 1);
    int sig = luaL_checkinteger(L, 2);
    int ret = kill(pid, sig);
    lua_pushinteger(L, ret);
    return 1;
}

// OS.tgkill(tgid, tid, sig)
static int l_os_tgkill(lua_State* L) {
    int tgid = luaL_checkinteger(L, 1);
    int tid = luaL_checkinteger(L, 2);
    int sig = luaL_checkinteger(L, 3);
    int ret = syscall(SYS_tgkill, tgid, tid, sig);
    lua_pushinteger(L, ret);
    return 1;
}

// OS.listdir(path) -> table of names
static int l_os_listdir(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    DIR* dir = opendir(path);
    if (!dir) {
        lua_pushnil(L);
        return 1;
    }
    lua_newtable(L);
    int i = 1;
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        lua_pushstring(L, entry->d_name);
        lua_rawseti(L, -2, i++);
    }
    closedir(dir);
    return 1;
}

static const luaL_Reg os_funcs[] = {
    {"getpid", l_os_getpid},
    {"kill", l_os_kill},
    {"tgkill", l_os_tgkill},
    {"listdir", l_os_listdir},
    {NULL, NULL}
};

void register_os_api(lua_State* L) {
    luaL_newlib(L, os_funcs);
    lua_setglobal(L, "OS");
}
