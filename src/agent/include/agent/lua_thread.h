#ifndef LUA_THREAD_H
#define LUA_THREAD_H

#include <lua.h>
#include <stdint.h>

extern __thread uintptr_t g_hook_caller_fp;
extern __thread uintptr_t g_hook_caller_lr;

void lua_register_thread(lua_State* L);

#endif
