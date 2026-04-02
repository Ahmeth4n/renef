#ifndef LUA_KCOV_H
#define LUA_KCOV_H

#include <lua.h>

#ifdef __cplusplus
extern "C" {
#endif

void register_kcov_api(lua_State* L);

#ifdef __cplusplus
}
#endif

#endif
