#ifndef LUA_HOOK_H
#define LUA_HOOK_H

#include <lua.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

enum MemHookType{
	NATIVE_METHOD,
	JAVA_METHOD
};

typedef struct HookTarget{
    enum MemHookType type;
    union{
        struct{
            char lib_name[128];
            uintptr_t offset;
            size_t size;
        } native;
        struct{
            char class_name[128];
            char method_name[128];
            char method_sig[128];
        } java;
    } info;
} HookTarget;

void register_memory_api(lua_State* L);

bool install_lua_hook(const char* lib_name, uintptr_t offset,
                      int onEnter_ref, int onLeave_ref);

#ifdef __cplusplus
}
#endif

#endif
