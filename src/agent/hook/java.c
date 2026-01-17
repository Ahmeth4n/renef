#include <agent/hook_java.h>
#include <agent/globals.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>

JavaHookInfo g_java_hooks[MAX_JAVA_HOOKS];
int g_java_hook_count = 0;

static int g_api_level = 0;
static ArtMethodOffsets g_offsets = {0};
static bool g_java_hook_initialized = false;
static pthread_mutex_t g_java_hook_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t g_java_lua_mutex = PTHREAD_MUTEX_INITIALIZER;

static __thread int g_current_java_hook_index = -1;


int get_android_api_level(void) {
    if (g_api_level > 0) {
        return g_api_level;
    }

    char sdk_ver[PROP_VALUE_MAX];
    if (__system_property_get("ro.build.version.sdk", sdk_ver) > 0) {
        g_api_level = atoi(sdk_ver);
    } else {
        g_api_level = 29;
        LOGW("Failed to detect API level, defaulting to %d", g_api_level);
    }

    LOGI("Detected Android API level: %d", g_api_level);
    return g_api_level;
}


#define ROUND_UP_PTR(x) (((x) + 7) & ~7)

const ArtMethodOffsets* get_art_method_offsets(void) {
    if (g_offsets.api_level > 0) {
        return &g_offsets;
    }

    int api = get_android_api_level();
    g_offsets.api_level = api;


    g_offsets.access_flags_offset = 4;


    if (api >= 35) {
        g_offsets.entry_point_offset = ROUND_UP_PTR(4 + 4 + 4 + 2 + 2) + 8;
        g_offsets.art_method_size = g_offsets.entry_point_offset + 8;
    } else if (api >= 33) {
        g_offsets.entry_point_offset = ROUND_UP_PTR(4 + 4 + 4 + 2 + 2) + 8;
        g_offsets.art_method_size = g_offsets.entry_point_offset + 8;
    } else if (api >= 31) {
        g_offsets.entry_point_offset = ROUND_UP_PTR(4 + 4 + 4 + 2 + 2) + 8;
        g_offsets.art_method_size = g_offsets.entry_point_offset + 8;
    } else if (api >= 30) {
        g_offsets.entry_point_offset = ROUND_UP_PTR(4 + 4 + 4 + 2 + 2) + 8;
        g_offsets.art_method_size = g_offsets.entry_point_offset + 8;
    } else if (api >= 29) {
        g_offsets.entry_point_offset = ROUND_UP_PTR(4 + 4 + 4 + 2 + 2) + 8;
        g_offsets.art_method_size = g_offsets.entry_point_offset + 8;
    } else if (api >= 28) {
        g_offsets.entry_point_offset = ROUND_UP_PTR(4 + 4 + 4 + 2 + 2) + 8;
        g_offsets.art_method_size = g_offsets.entry_point_offset + 8;
    } else if (api >= 26) {
        g_offsets.entry_point_offset = ROUND_UP_PTR(4 + 4 + 4 + 2 + 2) + 8;
        g_offsets.art_method_size = g_offsets.entry_point_offset + 8;
    } else {
        g_offsets.entry_point_offset = 32;
        g_offsets.art_method_size = 40;
    }

    LOGI("ArtMethod offsets for API %d: access_flags=%zu, entry_point=%zu, size=%zu",
         api, g_offsets.access_flags_offset, g_offsets.entry_point_offset,
         g_offsets.art_method_size);

    return &g_offsets;
}


void* jmethodid_to_art_method(JNIEnv* env, jmethodID method_id, jclass clazz) {
    if (!method_id) {
        LOGE("jmethodid_to_art_method: method_id is NULL");
        return NULL;
    }

    int api = get_android_api_level();

    if (api >= 30 && ((uintptr_t)method_id & 1)) {
        LOGI("Android 11+ detected index-based jmethodID: %p", method_id);


        jobject method_obj = (*env)->ToReflectedMethod(env, clazz, method_id, JNI_FALSE);
        if (!method_obj) {
            (*env)->ExceptionClear(env);
            method_obj = (*env)->ToReflectedMethod(env, clazz, method_id, JNI_TRUE);
            if (!method_obj) {
                LOGE("Failed to get reflected method");
                (*env)->ExceptionClear(env);
                return NULL;
            }
        }

        jclass executable_class = (*env)->FindClass(env, "java/lang/reflect/Executable");
        if (!executable_class) {
            LOGE("Failed to find Executable class");
            (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, method_obj);
            return NULL;
        }

        jfieldID art_method_field = (*env)->GetFieldID(env, executable_class, "artMethod", "J");
        if (!art_method_field) {
            LOGE("Failed to get artMethod field");
            (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, method_obj);
            (*env)->DeleteLocalRef(env, executable_class);
            return NULL;
        }

        jlong art_method_ptr = (*env)->GetLongField(env, method_obj, art_method_field);

        (*env)->DeleteLocalRef(env, method_obj);
        (*env)->DeleteLocalRef(env, executable_class);

        LOGI("Got ArtMethod pointer via reflection: %p", (void*)art_method_ptr);
        return (void*)art_method_ptr;
    }

    LOGI("Using direct jmethodID as ArtMethod pointer: %p", method_id);
    return (void*)method_id;
}


void* create_java_hook_trampoline(int hook_index) {
    void* trampoline = mmap(NULL, PAGE_SIZE,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trampoline == MAP_FAILED) {
        LOGE("Failed to allocate trampoline: %s", strerror(errno));
        return NULL;
    }

    uint32_t* code = (uint32_t*)trampoline;
    int idx = 0;

    // Prologue
    code[idx++] = 0xA9BF7BFD;  // stp x29, x30, [sp, #-16]!
    code[idx++] = 0x910003FD;  // mov x29, sp
    code[idx++] = 0xD10483FF;  // sub sp, sp, #288

    // Save x0-x28
    code[idx++] = 0xA90007E0;  // stp x0, x1, [sp, #0]
    code[idx++] = 0xA9010FE2;  // stp x2, x3, [sp, #16]
    code[idx++] = 0xA90217E4;  // stp x4, x5, [sp, #32]
    code[idx++] = 0xA9031FE6;  // stp x6, x7, [sp, #48]
    code[idx++] = 0xA90427E8;  // stp x8, x9, [sp, #64]
    code[idx++] = 0xA9052FEA;  // stp x10, x11, [sp, #80]
    code[idx++] = 0xA90637EC;  // stp x12, x13, [sp, #96]
    code[idx++] = 0xA9073FEE;  // stp x14, x15, [sp, #112]
    code[idx++] = 0xA90847F0;  // stp x16, x17, [sp, #128]
    code[idx++] = 0xA9094FF2;  // stp x18, x19, [sp, #144]
    code[idx++] = 0xA90A57F4;  // stp x20, x21, [sp, #160]
    code[idx++] = 0xA90B5FF6;  // stp x22, x23, [sp, #176]
    code[idx++] = 0xA90C67F8;  // stp x24, x25, [sp, #192]
    code[idx++] = 0xA90D6FFA;  // stp x26, x27, [sp, #208]
    code[idx++] = 0xF90073FC;  // str x28, [sp, #224]

    // Call onEnter(hook_index, saved_regs)
    code[idx++] = 0xD2800000 | ((hook_index & 0xFFFF) << 5);  // movz x0, #hook_index
    code[idx++] = 0x910003E1;  // mov x1, sp
    int onenter_ldr_idx = idx;
    code[idx++] = 0x58000010;  // ldr x16, [pc, #offset]
    code[idx++] = 0xD63F0200;  // blr x16

    // Restore argument registers
    code[idx++] = 0xA94007E0;  // ldp x0, x1, [sp, #0]
    code[idx++] = 0xA9410FE2;  // ldp x2, x3, [sp, #16]
    code[idx++] = 0xA94217E4;  // ldp x4, x5, [sp, #32]
    code[idx++] = 0xA9431FE6;  // ldp x6, x7, [sp, #48]
    code[idx++] = 0xA94427E8;  // ldp x8, x9, [sp, #64]

    // Call original entry point
    int original_ldr_idx = idx;
    code[idx++] = 0x58000010;  // ldr x16, [pc, #offset]
    code[idx++] = 0xD63F0200;  // blr x16

    // Save return value
    code[idx++] = 0xF90083E0;  // str x0, [sp, #256]

    // Call onLeave(hook_index, retval)
    code[idx++] = 0xD2800000 | ((hook_index & 0xFFFF) << 5);  // movz x0, #hook_index
    code[idx++] = 0xF94083E1;  // ldr x1, [sp, #256]
    int onleave_ldr_idx = idx;
    code[idx++] = 0x58000010;  // ldr x16, [pc, #offset]
    code[idx++] = 0xD63F0200;  // blr x16

    // Epilogue
    code[idx++] = 0x910483FF;  // add sp, sp, #288
    code[idx++] = 0xA8C17BFD;  // ldp x29, x30, [sp], #16
    code[idx++] = 0xD65F03C0;  // ret

    if (idx % 2 != 0) {
        code[idx++] = 0xD503201F;  // nop (align)
    }

    // Data section
    int onenter_addr_idx = idx;
    *(uint64_t*)(&code[idx]) = (uint64_t)java_hook_on_enter;
    idx += 2;

    int onleave_addr_idx = idx;
    *(uint64_t*)(&code[idx]) = (uint64_t)java_hook_on_leave;
    idx += 2;

    int original_addr_idx = idx;
    *(uint64_t*)(&code[idx]) = 0;
    idx += 2;

    *(uint64_t*)(&code[idx]) = (uint64_t)hook_index;
    idx += 2;

    // Patch LDR offsets
    int onenter_offset = (onenter_addr_idx - onenter_ldr_idx) * 4;
    code[onenter_ldr_idx] = 0x58000010 | ((onenter_offset / 4) << 5);

    int original_offset = (original_addr_idx - original_ldr_idx) * 4;
    code[original_ldr_idx] = 0x58000010 | ((original_offset / 4) << 5);

    int onleave_offset = (onleave_addr_idx - onleave_ldr_idx) * 4;
    code[onleave_ldr_idx] = 0x58000010 | ((onleave_offset / 4) << 5);

    __builtin___clear_cache((char*)trampoline, (char*)trampoline + idx * 4 + 32);

    LOGI("Created Java hook trampoline at %p (size=%d bytes)", trampoline, idx * 4);

    return trampoline;
}


/*
 * onEnter handler - called before original method executes.
 * Invokes Lua onEnter callback with method info and arguments.
 */
void java_hook_on_enter(int hook_index, uint64_t* saved_regs) {
    if (hook_index < 0 || hook_index >= g_java_hook_count) {
        LOGE("Invalid Java hook index: %d", hook_index);
        return;
    }

    JavaHookInfo* hook = &g_java_hooks[hook_index];
    g_current_java_hook_index = hook_index;

    LOGI("=== Java Hook #%d onEnter: %s.%s%s ===",
         hook_index, hook->class_name, hook->method_name, hook->method_sig);

    uint64_t x0 = saved_regs[0];
    uint64_t x1 = saved_regs[1];
    uint64_t x2 = saved_regs[2];
    uint64_t x3 = saved_regs[3];

    LOGI("  Args: X0=0x%llx X1=0x%llx X2=0x%llx X3=0x%llx",
         (unsigned long long)x0, (unsigned long long)x1,
         (unsigned long long)x2, (unsigned long long)x3);

    // Capture JNIEnv if available (x0 might contain it for JNI calls)
    if (x0 != 0) {
        // Note: For ART quick calls, x0 is ArtMethod*, not JNIEnv*
        // JNIEnv capture happens elsewhere in native hooks
    }

    if (hook->lua_onEnter_ref != LUA_NOREF && g_lua_engine) {
        pthread_mutex_lock(&g_java_lua_mutex);
        lua_State* L = lua_engine_get_state(g_lua_engine);
        if (L) {
            lua_rawgeti(L, LUA_REGISTRYINDEX, hook->lua_onEnter_ref);

            lua_newtable(L);

            // Add method metadata
            lua_pushstring(L, hook->class_name);
            lua_setfield(L, -2, "class");
            lua_pushstring(L, hook->method_name);
            lua_setfield(L, -2, "method");
            lua_pushstring(L, hook->method_sig);
            lua_setfield(L, -2, "signature");
            lua_pushboolean(L, hook->is_static);
            lua_setfield(L, -2, "isStatic");

            // Add register values as array indices 0-7
            for (int i = 0; i < 8; i++) {
                lua_pushinteger(L, saved_regs[i]);
                lua_rawseti(L, -2, i);
            }

            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                LOGE("Java hook onEnter callback failed: %s", lua_tostring(L, -1));
                lua_pop(L, 1);
            }
        }
        pthread_mutex_unlock(&g_java_lua_mutex);
    }
}


/*
 * onLeave handler - called after original method returns.
 * Invokes Lua onLeave callback with return value.
 * Returns the (possibly modified) return value.
 */
uint64_t java_hook_on_leave(int hook_index, uint64_t ret_val) {
    if (hook_index < 0 || hook_index >= g_java_hook_count) {
        LOGE("Invalid Java hook index in onLeave: %d", hook_index);
        return ret_val;
    }

    JavaHookInfo* hook = &g_java_hooks[hook_index];

    LOGI("=== Java Hook #%d onLeave: %s.%s%s ===",
         hook_index, hook->class_name, hook->method_name, hook->method_sig);
    LOGI("  Return value: 0x%llx (%lld)", (unsigned long long)ret_val, (long long)ret_val);

    if (hook->lua_onLeave_ref != LUA_NOREF && g_lua_engine) {
        pthread_mutex_lock(&g_java_lua_mutex);
        lua_State* L = lua_engine_get_state(g_lua_engine);
        if (L) {
            lua_rawgeti(L, LUA_REGISTRYINDEX, hook->lua_onLeave_ref);
            lua_pushinteger(L, ret_val);

            if (lua_pcall(L, 1, 1, 0) == LUA_OK) {
                // Handle return value modification
                if (lua_isnil(L, -1)) {
                    // No modification, keep original return value
                } else if (lua_istable(L, -1)) {
                    // Check for JNI type wrapper: {__jni_type = "...", value = ...}
                    lua_getfield(L, -1, "__jni_type");
                    if (lua_isstring(L, -1)) {
                        const char* jni_type = lua_tostring(L, -1);
                        lua_pop(L, 1);
                        lua_getfield(L, -1, "value");

                        if (strcmp(jni_type, "string") == 0 && lua_isstring(L, -1)) {
                            const char* str_value = lua_tostring(L, -1);
                            if (g_current_jni_env && str_value) {
                                jstring new_str = (*g_current_jni_env)->NewStringUTF(g_current_jni_env, str_value);
                                ret_val = (uint64_t)new_str;
                                LOGI("  Modified to jstring: \"%s\"", str_value);
                            }
                        } else if (strcmp(jni_type, "int") == 0 || strcmp(jni_type, "long") == 0) {
                            ret_val = (uint64_t)lua_tointeger(L, -1);
                            LOGI("  Modified to %s: %lld", jni_type, (long long)ret_val);
                        } else if (strcmp(jni_type, "boolean") == 0) {
                            ret_val = lua_toboolean(L, -1) ? 1 : 0;
                            LOGI("  Modified to boolean: %s", ret_val ? "true" : "false");
                        }
                        lua_pop(L, 1);  // pop value
                    } else {
                        lua_pop(L, 1);  // pop nil __jni_type
                    }
                } else if (lua_isinteger(L, -1) || lua_isnumber(L, -1)) {
                    ret_val = (uint64_t)lua_tointeger(L, -1);
                    LOGI("  Modified to: 0x%llx", (unsigned long long)ret_val);
                }
                lua_pop(L, 1);  // pop return value
            } else {
                LOGE("Java hook onLeave callback failed: %s", lua_tostring(L, -1));
                lua_pop(L, 1);
            }
        }
        pthread_mutex_unlock(&g_java_lua_mutex);
    }

    return ret_val;
}


int java_hook_init(JNIEnv* env) {
    if (g_java_hook_initialized) {
        return 0;
    }

    pthread_mutex_lock(&g_java_hook_mutex);

    if (g_java_hook_initialized) {
        pthread_mutex_unlock(&g_java_hook_mutex);
        return 0;
    }

    get_art_method_offsets();

    memset(g_java_hooks, 0, sizeof(g_java_hooks));
    g_java_hook_count = 0;

    g_java_hook_initialized = true;

    pthread_mutex_unlock(&g_java_hook_mutex);

    LOGI("Java hook subsystem initialized");
    return 0;
}

int install_java_hook(JNIEnv* env,
                      const char* class_name,
                      const char* method_name,
                      const char* signature,
                      int onEnter_ref,
                      int onLeave_ref) {

    if (!env) {
        LOGE("JNIEnv is NULL");
        return -1;
    }

    java_hook_init(env);

    pthread_mutex_lock(&g_java_hook_mutex);

    if (g_java_hook_count >= MAX_JAVA_HOOKS) {
        LOGE("Maximum Java hooks reached (%d)", MAX_JAVA_HOOKS);
        pthread_mutex_unlock(&g_java_hook_mutex);
        return -1;
    }

    LOGI("Installing Java hook: %s.%s%s", class_name, method_name, signature);

    char java_class_name[256];
    strncpy(java_class_name, class_name, sizeof(java_class_name) - 1);
    java_class_name[sizeof(java_class_name) - 1] = '\0';
    for (char* p = java_class_name; *p; p++) {
        if (*p == '/') *p = '.';
    }

    jclass clazz = (*env)->FindClass(env, class_name);

    if (!clazz || (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        LOGI("FindClass failed, trying application ClassLoader for: %s", java_class_name);

        jclass activity_thread_class = (*env)->FindClass(env, "android/app/ActivityThread");
        if (!activity_thread_class) {
            LOGE("Failed to find ActivityThread class");
            (*env)->ExceptionClear(env);
            pthread_mutex_unlock(&g_java_hook_mutex);
            return -1;
        }

        jmethodID current_application_method = (*env)->GetStaticMethodID(env, activity_thread_class,
            "currentApplication", "()Landroid/app/Application;");
        if (!current_application_method) {
            LOGE("Failed to find currentApplication method");
            (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, activity_thread_class);
            pthread_mutex_unlock(&g_java_hook_mutex);
            return -1;
        }

        jobject application = (*env)->CallStaticObjectMethod(env, activity_thread_class, current_application_method);
        (*env)->DeleteLocalRef(env, activity_thread_class);

        if (!application) {
            LOGE("currentApplication() returned null");
            (*env)->ExceptionClear(env);
            pthread_mutex_unlock(&g_java_hook_mutex);
            return -1;
        }

        jclass context_class = (*env)->FindClass(env, "android/content/Context");
        jmethodID get_classloader_method = (*env)->GetMethodID(env, context_class,
            "getClassLoader", "()Ljava/lang/ClassLoader;");
        (*env)->DeleteLocalRef(env, context_class);

        jobject classloader = (*env)->CallObjectMethod(env, application, get_classloader_method);
        (*env)->DeleteLocalRef(env, application);

        if (!classloader) {
            LOGE("getClassLoader() returned null");
            (*env)->ExceptionClear(env);
            pthread_mutex_unlock(&g_java_hook_mutex);
            return -1;
        }

        jclass classloader_class = (*env)->FindClass(env, "java/lang/ClassLoader");
        jmethodID load_class_method = (*env)->GetMethodID(env, classloader_class,
            "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        (*env)->DeleteLocalRef(env, classloader_class);

        jstring class_name_str = (*env)->NewStringUTF(env, java_class_name);
        clazz = (jclass)(*env)->CallObjectMethod(env, classloader, load_class_method, class_name_str);
        (*env)->DeleteLocalRef(env, class_name_str);
        (*env)->DeleteLocalRef(env, classloader);

        if (!clazz || (*env)->ExceptionCheck(env)) {
            LOGE("Class not found via application ClassLoader: %s", java_class_name);
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            pthread_mutex_unlock(&g_java_hook_mutex);
            return -1;
        }

        LOGI("Class loaded via application ClassLoader: %s", java_class_name);
    }

    jmethodID method_id = (*env)->GetMethodID(env, clazz, method_name, signature);
    bool is_static = false;

    if (!method_id) {
        (*env)->ExceptionClear(env);
        method_id = (*env)->GetStaticMethodID(env, clazz, method_name, signature);
        if (method_id) {
            is_static = true;
        }
    }

    if (!method_id) {
        LOGE("Method not found: %s.%s%s", class_name, method_name, signature);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, clazz);
        pthread_mutex_unlock(&g_java_hook_mutex);
        return -1;
    }

    LOGI("Found method: %s (jmethodID=%p, static=%d)", method_name, method_id, is_static);

    void* art_method = jmethodid_to_art_method(env, method_id, clazz);
    if (!art_method) {
        LOGE("Failed to get ArtMethod pointer");
        (*env)->DeleteLocalRef(env, clazz);
        pthread_mutex_unlock(&g_java_hook_mutex);
        return -1;
    }

    LOGI("ArtMethod pointer: %p", art_method);

    const ArtMethodOffsets* offsets = get_art_method_offsets();

    void** entry_point_ptr = (void**)((uintptr_t)art_method + offsets->entry_point_offset);

    void* page = (void*)((uintptr_t)entry_point_ptr & ~(PAGE_SIZE - 1));
    if (mprotect(page, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        LOGE("Failed to change page protection: %s", strerror(errno));
        (*env)->DeleteLocalRef(env, clazz);
        pthread_mutex_unlock(&g_java_hook_mutex);
        return -1;
    }

    void* original_entry = *entry_point_ptr;
    LOGI("Original entry point: %p", original_entry);

    int hook_index = g_java_hook_count;
    JavaHookInfo* hook = &g_java_hooks[hook_index];

    strncpy(hook->class_name, class_name, sizeof(hook->class_name) - 1);
    strncpy(hook->method_name, method_name, sizeof(hook->method_name) - 1);
    strncpy(hook->method_sig, signature, sizeof(hook->method_sig) - 1);
    hook->is_static = is_static;
    hook->art_method = art_method;
    hook->original_entry_point = original_entry;
    hook->lua_onEnter_ref = onEnter_ref;
    hook->lua_onLeave_ref = onLeave_ref;
    hook->hook_index = hook_index;

    void* trampoline = create_java_hook_trampoline(hook_index);
    if (!trampoline) {
        LOGE("Failed to create trampoline");
        (*env)->DeleteLocalRef(env, clazz);
        pthread_mutex_unlock(&g_java_hook_mutex);
        return -1;
    }

    hook->hook_trampoline = trampoline;

    // Find and fill the original entry point address in the trampoline's data section
    // The data section layout: onenter_addr, onleave_addr, original_addr, hook_index
    // We need to find the original_addr slot (third 64-bit value after code)
    uint64_t* tramp_data = (uint64_t*)trampoline;
    for (int i = 0; i < PAGE_SIZE / 8; i++) {
        // Find the pattern: java_hook_on_enter, java_hook_on_leave, 0 (placeholder)
        if (tramp_data[i] == (uint64_t)java_hook_on_enter &&
            tramp_data[i + 1] == (uint64_t)java_hook_on_leave &&
            tramp_data[i + 2] == 0) {
            tramp_data[i + 2] = (uint64_t)original_entry;
            __builtin___clear_cache((char*)&tramp_data[i + 2], (char*)&tramp_data[i + 3]);
            LOGI("Filled original entry point at trampoline offset %d", (int)(i + 2) * 8);
            break;
        }
    }

    *entry_point_ptr = trampoline;

    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    hook->is_hooked = true;
    g_java_hook_count++;

    (*env)->DeleteLocalRef(env, clazz);
    pthread_mutex_unlock(&g_java_hook_mutex);

    LOGI("Java hook #%d installed: %s.%s%s (onEnter=%d, onLeave=%d)",
         hook_index, class_name, method_name, signature, onEnter_ref, onLeave_ref);
    return hook_index;
}

int uninstall_java_hook(int hook_index) {
    if (hook_index < 0 || hook_index >= g_java_hook_count) {
        LOGE("Invalid hook index: %d", hook_index);
        return -1;
    }

    pthread_mutex_lock(&g_java_hook_mutex);

    JavaHookInfo* hook = &g_java_hooks[hook_index];

    if (!hook->is_hooked) {
        LOGI("Hook %d already uninstalled", hook_index);
        pthread_mutex_unlock(&g_java_hook_mutex);
        return 0;
    }

    const ArtMethodOffsets* offsets = get_art_method_offsets();
    void** entry_point_ptr = (void**)((uintptr_t)hook->art_method + offsets->entry_point_offset);

    void* page = (void*)((uintptr_t)entry_point_ptr & ~(PAGE_SIZE - 1));
    if (mprotect(page, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        LOGE("Failed to change page protection for unhook: %s", strerror(errno));
        pthread_mutex_unlock(&g_java_hook_mutex);
        return -1;
    }

    *entry_point_ptr = hook->original_entry_point;
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    if (hook->hook_trampoline) {
        munmap(hook->hook_trampoline, PAGE_SIZE);
        hook->hook_trampoline = NULL;
    }

    if (g_lua_engine) {
        lua_State* L = lua_engine_get_state(g_lua_engine);
        if (L) {
            if (hook->lua_onEnter_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, hook->lua_onEnter_ref);
            }
            if (hook->lua_onLeave_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, hook->lua_onLeave_ref);
            }
        }
    }

    hook->lua_onEnter_ref = LUA_NOREF;
    hook->lua_onLeave_ref = LUA_NOREF;
    hook->is_hooked = false;

    pthread_mutex_unlock(&g_java_hook_mutex);

    LOGI("Java hook #%d uninstalled", hook_index);
    return 0;
}

int uninstall_all_java_hooks(void) {
    int count = 0;
    for (int i = 0; i < g_java_hook_count; i++) {
        if (g_java_hooks[i].is_hooked) {
            if (uninstall_java_hook(i) == 0) {
                count++;
            }
        }
    }
    LOGI("Uninstalled %d Java hooks", count);
    return count;
}

void* get_java_hook_original_entry(int hook_index) {
    if (hook_index < 0 || hook_index >= g_java_hook_count) {
        return NULL;
    }
    return g_java_hooks[hook_index].original_entry_point;
}
