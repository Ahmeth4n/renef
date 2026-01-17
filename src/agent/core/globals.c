#include <agent/globals.h>
#include <agent/hook.h>

LuaEngine* g_lua_engine = NULL;

int g_output_client_fd = -1;

JNIEnv* g_current_jni_env = NULL;

JavaVM* g_java_vm = NULL;

int g_default_hook_type = HOOK_TRAMPOLINE;

JNIEnv* get_current_jni_env(void) {
    JNIEnv* env = NULL;
    if (g_java_vm) {
        int status = (*g_java_vm)->GetEnv(g_java_vm, (void**)&env, JNI_VERSION_1_6);
        if (status == JNI_EDETACHED) {
            (*g_java_vm)->AttachCurrentThread(g_java_vm, &env, NULL);
        }
    }
    return env;
}
