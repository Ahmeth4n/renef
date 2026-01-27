#ifndef AGENT_GLOBALS_H
#define AGENT_GLOBALS_H

#include <android/log.h>
#include <stdint.h>
#include <stdbool.h>
#include <jni.h>
#include <agent/lua_engine.h>

#define LOG_TAG "RENEF_AGENT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define PAGE_SIZE 4096
#define PAGE_START(addr) ((void*)((uintptr_t)(addr) & ~(PAGE_SIZE - 1)))
#define ALIGN_UP(addr, size) (((addr) + (size) - 1) & ~((size) - 1))

#define MAX_HOOKS 32

extern LuaEngine* g_lua_engine;

extern int g_output_client_fd;

extern JNIEnv* g_current_jni_env;

extern JavaVM* g_java_vm;

extern int g_default_hook_type;

JNIEnv* get_current_jni_env(void);
JNIEnv* get_jni_env(void);

#endif
