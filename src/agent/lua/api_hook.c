#include <agent/lua_hook.h>
#include <agent/hook.h>
#include <agent/globals.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <lua.h>
#include <lauxlib.h>
#include <string.h>
#include <android/log.h>

#define TAG "LUA_HOOK"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)


static struct HookTarget create_native_target(lua_State* L) {
    struct HookTarget target;
    target.type = NATIVE_METHOD;

    const char* lib_name = luaL_checkstring(L, 1);
    strncpy(target.info.native.lib_name, lib_name, 127);
    target.info.native.lib_name[127] = '\0';

    target.info.native.offset = (uintptr_t)luaL_checkinteger(L, 2);

    if (lua_isnumber(L, 3)) {
        target.info.native.size = (size_t)lua_tointeger(L, 3);
    } else {
        target.info.native.size = 0;
    }

    return target;
}

static struct HookTarget create_java_target(lua_State* L) {
    struct HookTarget target;
    target.type = JAVA_METHOD;

    const char* class_name = luaL_checkstring(L, 1);
    strncpy(target.info.java.class_name, class_name, 127);
    target.info.java.class_name[127] = '\0';

    const char* method_name = luaL_checkstring(L, 2);
    strncpy(target.info.java.method_name, method_name, 127);
    target.info.java.method_name[127] = '\0';

    if (lua_isstring(L, 3)) {
        const char* sig = lua_tostring(L, 3);
        strncpy(target.info.java.method_sig, sig, 127);
        target.info.java.method_sig[127] = '\0';
    } else {
        target.info.java.method_sig[0] = '\0';
    }

    return target;
}

static int lua_hook(lua_State* L) {
    struct HookTarget target;

    lua_getglobal(L, "__hook_type__");
    if (lua_isstring(L, -1)) {
        const char* hook_type_str = lua_tostring(L, -1);
        LOGI("Global hook type detected: %s", hook_type_str);

        if (strcmp(hook_type_str, "pltgot") == 0) {
            g_default_hook_type = HOOK_PLT_GOT;
            LOGI("Hook type set to PLT/GOT");
        } else if (strcmp(hook_type_str, "trampoline") == 0) {
            g_default_hook_type = HOOK_TRAMPOLINE;
            LOGI("Hook type set to trampoline");
        } else {
            LOGI("Unknown hook type '%s', using default", hook_type_str);
        }
    }
    lua_pop(L, 1);

    if (lua_isnumber(L, 2)) {
        target = create_native_target(L);
    } else if (lua_isstring(L, 2)) {
        target = create_java_target(L);
    } else {
        return luaL_error(L, "Invalid hook arguments");
    }

    int callback_index = 0;

    if (target.type == NATIVE_METHOD)
        callback_index = 3;
    else
        if (lua_isstring(L, 3))
            callback_index = 4;
        else
            callback_index = 3;


    if (!lua_istable(L, callback_index)) {
        return luaL_error(L, "Callbacks must be a table");
    }

    int onEnter_ref = LUA_NOREF;
    lua_getfield(L, callback_index, "onEnter");
    if (lua_isfunction(L, -1)) {
        onEnter_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        lua_pop(L, 1);
    }


    int onLeave_ref = LUA_NOREF;
    lua_getfield(L, callback_index, "onLeave");
    if (lua_isfunction(L, -1)) {
        onLeave_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        lua_pop(L, 1);
    }

    if (onEnter_ref != LUA_NOREF) {
        LOGI("onEnter callback registered (ref: %d)", onEnter_ref);
    }
    if (onLeave_ref != LUA_NOREF) {
        LOGI("onLeave callback registered (ref: %d)", onLeave_ref);
    }

    LOGI("Hook target: type=%d, callbacks registered", target.type);

    if (target.type == NATIVE_METHOD) {
        bool result = install_lua_hook(target.info.native.lib_name,
                                       target.info.native.offset,
                                       onEnter_ref, onLeave_ref);
        if (!result) {
            return luaL_error(L, "Failed to install native hook");
        }
    } else if (target.type == JAVA_METHOD) {
        bool result = install_lua_java_hook(target.info.java.class_name,
                                            target.info.java.method_name,
                                            target.info.java.method_sig,
                                            onEnter_ref, onLeave_ref);
        if (!result) {
            return luaL_error(L, "Failed to install Java hook");
        }
    }

    return 0;
}

void register_memory_api(lua_State* L) {
    lua_pushcfunction(L, lua_hook);
    lua_setglobal(L, "hook");
}
