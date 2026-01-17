#include <agent/lua_jni.h>
#include <agent/lua_engine.h>
#include <agent/globals.h>

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <jni.h>
#include <android/log.h>
#include <elf.h>

#define TAG "JNI_API"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

typedef void* (*DecodeJObject_t)(void* thread, jobject obj);
static DecodeJObject_t g_decode_jobject = NULL;
static DecodeJObject_t g_decode_global_jobject = NULL;
static int g_decode_init_tried = 0;

// JNIEnvExt structure - matches AOSP art/runtime/jni/jni_env_ext.h
// Layout: JNIEnv base (functions pointer) + self_ + vm_
typedef struct {
    void* functions;      // JNINativeInterface* - offset 0
    void* self;           // Thread* - offset 8 - this is what we need
    void* vm;             // JavaVMExt* - offset 16
} JNIEnvExt;

static uintptr_t find_lib_base(const char* lib_name) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name) && strstr(line, "r-xp")) {
            sscanf(line, "%lx-", &base);
            break;
        }
    }

    fclose(fp);
    return base;
}

static uintptr_t find_symbol_offset(const char* lib_path, const char* symbol_name) {
    FILE* fp = fopen(lib_path, "rb");
    if (!fp) return 0;

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, fp) != 1) {
        fclose(fp);
        return 0;
    }

    fseek(fp, ehdr.e_shoff, SEEK_SET);

    Elf64_Shdr* shdrs = malloc(ehdr.e_shnum * sizeof(Elf64_Shdr));
    if (!shdrs || fread(shdrs, sizeof(Elf64_Shdr), ehdr.e_shnum, fp) != ehdr.e_shnum) {
        free(shdrs);
        fclose(fp);
        return 0;
    }

    Elf64_Shdr* dynsym = NULL;
    Elf64_Shdr* dynstr = NULL;

    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_DYNSYM) {
            dynsym = &shdrs[i];
            dynstr = &shdrs[dynsym->sh_link];
            break;
        }
    }

    uintptr_t offset = 0;

    if (dynsym && dynstr) {
        char* strtab = malloc(dynstr->sh_size);
        if (strtab) {
            fseek(fp, dynstr->sh_offset, SEEK_SET);
            fread(strtab, 1, dynstr->sh_size, fp);

            int num_syms = dynsym->sh_size / sizeof(Elf64_Sym);
            Elf64_Sym* syms = malloc(dynsym->sh_size);
            if (syms) {
                fseek(fp, dynsym->sh_offset, SEEK_SET);
                fread(syms, sizeof(Elf64_Sym), num_syms, fp);

                for (int i = 0; i < num_syms; i++) {
                    if (syms[i].st_name && strcmp(&strtab[syms[i].st_name], symbol_name) == 0) {
                        offset = syms[i].st_value;
                        break;
                    }
                }
                free(syms);
            }
            free(strtab);
        }
    }

    free(shdrs);
    fclose(fp);
    return offset;
}

static void init_decode_jobject(void) {
    if (g_decode_init_tried) return;
    g_decode_init_tried = 1;

    const char* lib_paths[] = {
        "/apex/com.android.art/lib64/libart.so",
        "/apex/com.android.runtime/lib64/libart.so",
        NULL
    };

    const char* decode_symbols[] = {
        "_ZNK3art6Thread13DecodeJObjectEP8_jobject",        // Android 8+ const
        "_ZN3art6Thread13DecodeJObjectEP8_jobject",         // Android 8+ non-const
        NULL
    };

    const char* global_symbols[] = {
        "_ZNK3art6Thread19DecodeGlobalJObjectEP8_jobject",  // Android 10+ const
        "_ZN3art6Thread19DecodeGlobalJObjectEP8_jobject",   // Android 10+ non-const
        NULL
    };

    uintptr_t base = find_lib_base("libart.so");
    if (!base) {
        LOGI("Could not find libart.so base address");
        return;
    }
    LOGI("libart.so base: 0x%lx", base);

    for (int p = 0; lib_paths[p] && !g_decode_jobject; p++) {
        for (int s = 0; decode_symbols[s] && !g_decode_jobject; s++) {
            uintptr_t offset = find_symbol_offset(lib_paths[p], decode_symbols[s]);
            if (offset) {
                g_decode_jobject = (DecodeJObject_t)(base + offset);
                LOGI("Found DecodeJObject: %s at offset 0x%lx, addr=0x%lx",
                     decode_symbols[s], offset, (uintptr_t)g_decode_jobject);
            }
        }
    }

    for (int p = 0; lib_paths[p] && !g_decode_global_jobject; p++) {
        for (int s = 0; global_symbols[s] && !g_decode_global_jobject; s++) {
            uintptr_t offset = find_symbol_offset(lib_paths[p], global_symbols[s]);
            if (offset) {
                g_decode_global_jobject = (DecodeJObject_t)(base + offset);
                LOGI("Found DecodeGlobalJObject: %s at offset 0x%lx, addr=0x%lx",
                     global_symbols[s], offset, (uintptr_t)g_decode_global_jobject);
            }
        }
    }

    if (!g_decode_jobject && !g_decode_global_jobject) {
        LOGI("No DecodeJObject functions found");
    }
}

#define INDIRECT_REF_KIND_MASK 0x3
#define INDIRECT_REF_KIND_LOCAL 0x1
#define INDIRECT_REF_KIND_GLOBAL 0x2
#define INDIRECT_REF_KIND_WEAK_GLOBAL 0x3

typedef struct {
    void* functions;      // JNINativeInterface* - offset 0
    void* self;           // Thread* - offset 8
    void* vm;             // JavaVMExt* - offset 16
} JNIEnvExtFull;

static void* decode_local_ref_manual(JNIEnv* env, jobject ref) {
    uintptr_t ref_val = (uintptr_t)ref;

    if ((ref_val & INDIRECT_REF_KIND_MASK) != INDIRECT_REF_KIND_LOCAL) {
        LOGI("Not a local ref: 0x%lx (kind=%lu)", ref_val, ref_val & INDIRECT_REF_KIND_MASK);
        return NULL;
    }

    uintptr_t* env_ptr = (uintptr_t*)env;

    for (int offset = 3; offset < 10; offset++) {
        void* potential_table = (void*)env_ptr[offset];
        if (!potential_table) continue;

        uintptr_t* table_struct = (uintptr_t*)potential_table;

        for (int table_offset = 1; table_offset < 4; table_offset++) {
            void** table = (void**)table_struct[table_offset];
            if (!table) continue;

            uint32_t index = (ref_val >> 2) & 0xFFFF;  // Rough extraction

            LOGI("Trying table at env+%d, table_offset=%d, index=%u", offset*8, table_offset*8, index);
        }
    }

    return NULL;
}

static void* try_decode_stacked_ref(jobject ref) {
    uintptr_t ref_val = (uintptr_t)ref;

    if ((ref_val & INDIRECT_REF_KIND_MASK) != INDIRECT_REF_KIND_LOCAL) {
        LOGI("Not a local ref: 0x%lx", ref_val);
        return NULL;
    }

    uintptr_t slot_addr = ref_val & ~((uintptr_t)0x3);

    LOGI("Trying stacked ref decode: ref=0x%lx, slot_addr=0x%lx", ref_val, slot_addr);

    uint64_t* slot64 = (uint64_t*)slot_addr;
    uint64_t slot_val = *slot64;

    LOGI("Read 64-bit from slot: 0x%lx", slot_val);

    uint32_t lower32 = (uint32_t)(slot_val & 0xFFFFFFFF);
    uint32_t upper32 = (uint32_t)(slot_val >> 32);

    LOGI("Lower 32 bits: 0x%x, Upper 32 bits: 0x%x", lower32, upper32);

    if (lower32 >= 0x01000000 && lower32 < 0x40000000) {
        LOGI("Valid heap pointer found in lower 32 bits: 0x%x", lower32);
        return (void*)(uintptr_t)lower32;
    }

    if (upper32 >= 0x01000000 && upper32 < 0x40000000) {
        LOGI("Valid heap pointer found in upper 32 bits: 0x%x", upper32);
        return (void*)(uintptr_t)upper32;
    }

    if (slot_val >= 0x10000000 && slot_val < 0x40000000) {
        LOGI("Valid 64-bit heap pointer found: 0x%lx", slot_val);
        return (void*)slot_val;
    }

    LOGI("No valid heap pointer found in slot");
    return NULL;
}

static void* decode_jni_ref(JNIEnv* env, jobject ref) {
    if (!ref) return NULL;

    uintptr_t ref_val = (uintptr_t)ref;
    int ref_kind = ref_val & INDIRECT_REF_KIND_MASK;

    LOGI("decode_jni_ref: ref=0x%lx, kind=%d", ref_val, ref_kind);

    // Strategy 1: Try stacked ref decode (Android 10+ local refs)
    if (ref_kind == INDIRECT_REF_KIND_LOCAL) {
        void* stacked_result = try_decode_stacked_ref(ref);
        if (stacked_result) {
            LOGI("Stacked ref decode succeeded: 0x%lx", (uintptr_t)stacked_result);
            return stacked_result;
        }
    }

    // Strategy 2: Try DecodeJObject if available
    init_decode_jobject();

    JNIEnvExt* env_ext = (JNIEnvExt*)env;
    void* thread = env_ext->self;

    if (g_decode_jobject && thread) {
        LOGI("Trying DecodeJObject(%p, %p)...", thread, ref);
        void* raw_ptr = g_decode_jobject(thread, ref);
        if (raw_ptr) {
            LOGI("DecodeJObject succeeded: 0x%lx", (uintptr_t)raw_ptr);
            return raw_ptr;
        }
    }

    LOGI("Returning local ref as fallback: 0x%lx", ref_val);
    return (void*)ref;
}

static int lua_jni_new_string_utf(lua_State* L) {
    const char* str = luaL_checkstring(L, 1);

    JNIEnv* env = get_current_jni_env();
    if (!env) {
        return luaL_error(L, "JNIEnv not available");
    }

    jstring jstr = (*env)->NewStringUTF(env, str);
    if (!jstr) {
        return luaL_error(L, "Failed to create Java String");
    }

    void* raw_ptr = decode_jni_ref(env, jstr);
    LOGI("newStringUTF('%s'): jni_ref=%p, raw_ptr=%p", str, jstr, raw_ptr);

    lua_pushinteger(L, (lua_Integer)(uintptr_t)raw_ptr);
    return 1;
}

// Jni.getStringUTF(ref) -> returns string content
static int lua_jni_get_string_utf(lua_State* L) {
    uintptr_t ref = (uintptr_t)luaL_checkinteger(L, 1);

    JNIEnv* env = get_current_jni_env();
    if (!env) {
        return luaL_error(L, "JNIEnv not available");
    }

    if (ref == 0) {
        lua_pushnil(L);
        return 1;
    }

    jstring jstr = (jstring)ref;
    const char* chars = (*env)->GetStringUTFChars(env, jstr, NULL);
    if (!chars) {
        return luaL_error(L, "Failed to get String content");
    }

    lua_pushstring(L, chars);
    (*env)->ReleaseStringUTFChars(env, jstr, chars);

    return 1;
}

// Jni.deleteGlobalRef(ref) -> deletes a global reference
static int lua_jni_delete_global_ref(lua_State* L) {
    uintptr_t ref = (uintptr_t)luaL_checkinteger(L, 1);

    JNIEnv* env = get_current_jni_env();
    if (!env) {
        return luaL_error(L, "JNIEnv not available");
    }

    if (ref != 0) {
        (*env)->DeleteGlobalRef(env, (jobject)ref);
    }

    return 0;
}

// Jni.getStringLength(ref) -> returns string length
static int lua_jni_get_string_length(lua_State* L) {
    uintptr_t ref = (uintptr_t)luaL_checkinteger(L, 1);

    JNIEnv* env = get_current_jni_env();
    if (!env) {
        return luaL_error(L, "JNIEnv not available");
    }

    if (ref == 0) {
        lua_pushinteger(L, 0);
        return 1;
    }

    jstring jstr = (jstring)ref;
    jsize len = (*env)->GetStringLength(env, jstr);

    lua_pushinteger(L, (lua_Integer)len);
    return 1;
}

void lua_register_jni(lua_State* L) {
    lua_newtable(L);

    lua_pushcfunction(L, lua_jni_new_string_utf);
    lua_setfield(L, -2, "newStringUTF");

    lua_pushcfunction(L, lua_jni_get_string_utf);
    lua_setfield(L, -2, "getStringUTF");

    lua_pushcfunction(L, lua_jni_delete_global_ref);
    lua_setfield(L, -2, "deleteGlobalRef");

    lua_pushcfunction(L, lua_jni_get_string_length);
    lua_setfield(L, -2, "getStringLength");

    lua_setglobal(L, "Jni");

    LOGI("Jni API registered");
}
