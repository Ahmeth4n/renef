#ifndef LUA_ENGINE_H
#define LUA_ENGINE_H

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    lua_State* L;
    bool initialized;
} LuaEngine;

LuaEngine* lua_engine_create(void);
void lua_engine_destroy(LuaEngine* engine);

bool lua_engine_load_script(LuaEngine* engine, const char* script);
bool lua_engine_load_file(LuaEngine* engine, const char* filepath);

void register_renef_api(lua_State* L);

lua_State* lua_engine_get_state(LuaEngine* engine);

#ifdef __cplusplus
}
#endif

#endif
