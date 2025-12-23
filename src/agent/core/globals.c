#include <agent/globals.h>
#include <agent/hook.h>

LuaEngine* g_lua_engine = NULL;

int g_output_client_fd = -1;

JNIEnv* g_current_jni_env = NULL;

int g_default_hook_type = HOOK_TRAMPOLINE;
