#include "lua_engine.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <android/log.h>
#include "../hook/lua_hook.h"
#include "../memory/lua_memory.h"
#include "../thread/lua_thread.h"
#include "../../proc/proc.h"

#define TAG "RENEF_LUA"
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

static int lua_console_log(lua_State* L) {
    const char* msg = luaL_checkstring(L, 1);

    LOGI("[SCRIPT] %s", msg);

    send_to_cli(msg);

    return 0;
}


static int lua_list_modules(lua_State* L){
    char* l_libs = get_loaded_libraries();
    lua_pushstring(L, l_libs);
    free(l_libs); 
    return 1;
}

static int lua_find_module(lua_State* L){
    const char* lib_name = luaL_checkstring(L, 1);
    void* base = find_library_base(lib_name); 
    
    if (base) {
        lua_pushinteger(L, (uintptr_t)base);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

static int lua_module_exports(lua_State* L) {
    const char* lib_name = luaL_checkstring(L, 1);
    elf_exports_t* exports = get_exports(lib_name);

    if (!exports) {
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);
    for (size_t i = 0; i < exports->count; i++) {
        lua_newtable(L);
        lua_pushstring(L, exports->exports[i].name);
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, exports->exports[i].offset);
        lua_setfield(L, -2, "offset");
        lua_rawseti(L, -2, i + 1);
    }

    free_elf_exports(exports);
    return 1;
}

static int lua_module_symbols(lua_State* L) {
    const char* lib_name = luaL_checkstring(L, 1);
    elf_exports_t* symbols = get_symbols(lib_name);

    if (!symbols) {
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);
    for (size_t i = 0; i < symbols->count; i++) {
        lua_newtable(L);
        lua_pushstring(L, symbols->exports[i].name);
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, symbols->exports[i].offset);
        lua_setfield(L, -2, "offset");
        lua_rawseti(L, -2, i + 1);
    }

    free_elf_exports(symbols);
    return 1;
}


static int lua_jni_string(lua_State* L) {
    const char* value = luaL_checkstring(L, 1);
    lua_newtable(L);
    lua_pushstring(L, "string");
    lua_setfield(L, -2, "__jni_type");
    lua_pushstring(L, value);
    lua_setfield(L, -2, "value");
    return 1;
}

static int lua_jni_int(lua_State* L) {
    lua_Integer value = luaL_checkinteger(L, 1);
    lua_newtable(L);
    lua_pushstring(L, "int");
    lua_setfield(L, -2, "__jni_type");
    lua_pushinteger(L, value);
    lua_setfield(L, -2, "value");
    return 1;
}

static int lua_jni_long(lua_State* L) {
    lua_Integer value = luaL_checkinteger(L, 1);
    lua_newtable(L);
    lua_pushstring(L, "long");
    lua_setfield(L, -2, "__jni_type");
    lua_pushinteger(L, value);
    lua_setfield(L, -2, "value");
    return 1;
}

static int lua_jni_boolean(lua_State* L) {
    int value = lua_toboolean(L, 1);
    lua_newtable(L);
    lua_pushstring(L, "boolean");
    lua_setfield(L, -2, "__jni_type");
    lua_pushboolean(L, value);
    lua_setfield(L, -2, "value");
    return 1;
}


static int lua_print(lua_State* L) {
    int n = lua_gettop(L);
    lua_getglobal(L, "tostring");

    for (int i = 1; i <= n; i++) {
        lua_pushvalue(L, -1);
        lua_pushvalue(L, i);
        lua_call(L, 1, 1);

        const char* s = lua_tostring(L, -1);
        if (s) {
            LOGI("[SCRIPT] %s", s);
            send_to_cli(s);
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
    return 0;
}

void register_renef_api(lua_State* L) {
    lua_pushcfunction(L, lua_print);
    lua_setglobal(L, "print");

    lua_pushstring(L, "\033[0m");
    lua_setglobal(L, "RESET");
    lua_pushstring(L, "\033[31m");
    lua_setglobal(L, "RED");
    lua_pushstring(L, "\033[32m");
    lua_setglobal(L, "GREEN");
    lua_pushstring(L, "\033[33m");
    lua_setglobal(L, "YELLOW");
    lua_pushstring(L, "\033[34m");
    lua_setglobal(L, "BLUE");
    lua_pushstring(L, "\033[35m");
    lua_setglobal(L, "MAGENTA");
    lua_pushstring(L, "\033[36m");
    lua_setglobal(L, "CYAN");
    lua_pushstring(L, "\033[37m");
    lua_setglobal(L, "WHITE");

    lua_newtable(L);
    lua_pushcfunction(L, lua_console_log);
    lua_setfield(L, -2, "log");
    lua_setglobal(L, "console");

    lua_newtable(L);
    lua_pushcfunction(L, lua_list_modules);
    lua_setfield(L, -2, "list");
    lua_pushcfunction(L, lua_find_module);
    lua_setfield(L, -2, "find");
    lua_pushcfunction(L, lua_module_exports);
    lua_setfield(L, -2, "exports");
    lua_pushcfunction(L, lua_module_symbols);
    lua_setfield(L, -2, "symbols");

    lua_setglobal(L, "Module");


    lua_newtable(L);
    lua_pushcfunction(L, lua_jni_string);
    lua_setfield(L, -2, "string");
    lua_pushcfunction(L, lua_jni_int);
    lua_setfield(L, -2, "int");
    lua_pushcfunction(L, lua_jni_long);
    lua_setfield(L, -2, "long");
    lua_pushcfunction(L, lua_jni_boolean);
    lua_setfield(L, -2, "boolean");
    lua_setglobal(L, "JNI");

    LOGI("Registering memory API...");
    register_memory_api(L);
    LOGI("Registering thread API...");
    lua_register_thread(L);
    LOGI("All APIs registered");
}

LuaEngine* lua_engine_create(void) {
    LuaEngine* engine = malloc(sizeof(LuaEngine));
    if (!engine) {
        LOGI("Failed to allocate LuaEngine");
        return NULL;
    }

    engine->L = luaL_newstate();
    if (!engine->L) {
        LOGI("Failed to create Lua state");
        free(engine);
        return NULL;
    }

    luaL_openlibs(engine->L);

    register_renef_api(engine->L);
    register_memory_search_api(engine->L);

    engine->initialized = true;
    LOGI("Lua engine initialized");

    return engine;
}

void lua_engine_destroy(LuaEngine* engine) {
    if (engine) {
        if (engine->L) {
            lua_close(engine->L);
        }
        free(engine);
        LOGI("Lua engine destroyed");
    }
}

bool lua_engine_load_script(LuaEngine* engine, const char* script) {
    if (!engine || !engine->initialized || !script) {
        return false;
    }

    int load_result = luaL_loadstring(engine->L, script);
    if (load_result != LUA_OK) {
        const char* error = lua_tostring(engine->L, -1);
        LOGI("Lua compile error: %s", error);
        lua_pop(engine->L, 1);
        return false;
    }

    int exec_result = lua_pcall(engine->L, 0, 0, 0);
    if (exec_result != LUA_OK) {
        const char* error = lua_tostring(engine->L, -1);
        LOGI("Lua runtime error: %s", error);
        lua_pop(engine->L, 1);
        return false;
    }

    return true;
}

bool lua_engine_load_file(LuaEngine* engine, const char* filepath) {
    if (!engine || !engine->initialized || !filepath) {
        return false;
    }

    int load_result = luaL_loadfile(engine->L, filepath);
    if (load_result != LUA_OK) {
        const char* error = lua_tostring(engine->L, -1);
        LOGI("Lua file load error: %s", error);
        lua_pop(engine->L, 1);
        return false;
    }

    int exec_result = lua_pcall(engine->L, 0, 0, 0);
    if (exec_result != LUA_OK) {
        const char* error = lua_tostring(engine->L, -1);
        LOGI("Lua file exec error: %s", error);
        lua_pop(engine->L, 1);
        return false;
    }

    return true;
}

lua_State* lua_engine_get_state(LuaEngine* engine) {
    if (!engine || !engine->initialized) {
        return NULL;
    }
    return engine->L;
}
