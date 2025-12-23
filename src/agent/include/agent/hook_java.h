#ifndef HOOK_JAVA_H
#define HOOK_JAVA_H

#include <jni.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_JAVA_HOOKS 32

typedef struct {
    int api_level;
    size_t access_flags_offset;
    size_t entry_point_offset;
    size_t art_method_size;
} ArtMethodOffsets;

typedef struct {
    char class_name[256];
    char method_name[128];
    char method_sig[256];
    bool is_static;

    void* art_method;
    void* original_entry_point;
    void* hook_trampoline;

    int lua_onEnter_ref;
    int lua_onLeave_ref;

    bool is_hooked;
    int hook_index;
} JavaHookInfo;

extern JavaHookInfo g_java_hooks[MAX_JAVA_HOOKS];
extern int g_java_hook_count;

int java_hook_init(JNIEnv* env);

int get_android_api_level(void);

const ArtMethodOffsets* get_art_method_offsets(void);

void* jmethodid_to_art_method(JNIEnv* env, jmethodID method_id, jclass clazz);

int install_java_hook(JNIEnv* env,
                      const char* class_name,
                      const char* method_name,
                      const char* signature,
                      int onEnter_ref,
                      int onLeave_ref);

int uninstall_java_hook(int hook_index);

int uninstall_all_java_hooks(void);

void* get_java_hook_original_entry(int hook_index);

void java_hook_handler(int hook_index, uint64_t* saved_regs);

void* create_java_hook_trampoline(int hook_index);

#ifdef __cplusplus
}
#endif

#endif
