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
#include <sys/system_properties.h>

#define TAG "JNI_API"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

typedef void* (*DecodeJObject_t)(void* thread, jobject obj);
static DecodeJObject_t g_decode_jobject = NULL;
static DecodeJObject_t g_decode_global_jobject = NULL;
static int g_decode_init_tried = 0;

typedef struct {
    void* functions;
    void* self;
    void* vm;
} JNIEnvExt;

static uintptr_t find_lib_info(const char* lib_name, char* path_out, size_t path_size) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name)) {
            unsigned long start;
            char path[256] = {0};
            if (sscanf(line, "%lx-%*lx %*4s %*x %*s %*d %255s", &start, path) >= 1) {
                if (base == 0 || start < base) {
                    base = (uintptr_t)start;
                    if (path_out && path[0]) {
                        strncpy(path_out, path, path_size - 1);
                        path_out[path_size - 1] = '\0';
                    }
                }
            }
        }
    }

    fclose(fp);
    return base;
}

static uintptr_t get_first_load_vaddr(const char* lib_path) {
    FILE* fp = fopen(lib_path, "rb");
    if (!fp) return 0;

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, fp) != 1) {
        fclose(fp);
        return 0;
    }

    uintptr_t first_load_vaddr = 0;

    fseek(fp, ehdr.e_phoff, SEEK_SET);
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (fread(&phdr, sizeof(phdr), 1, fp) != 1) break;

        if (phdr.p_type == PT_LOAD) {
            first_load_vaddr = phdr.p_vaddr;
            break;
        }
    }

    fclose(fp);
    return first_load_vaddr;
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

    Elf64_Shdr* shstrtab = &shdrs[ehdr.e_shstrndx];
    char* shstrtab_data = malloc(shstrtab->sh_size);
    if (shstrtab_data) {
        fseek(fp, shstrtab->sh_offset, SEEK_SET);
        fread(shstrtab_data, 1, shstrtab->sh_size, fp);
    }

    uintptr_t offset = 0;

    for (int pass = 0; pass < 2 && offset == 0; pass++) {
        Elf64_Shdr* symtab_shdr = NULL;
        Elf64_Shdr* strtab_shdr = NULL;

        for (int i = 0; i < ehdr.e_shnum; i++) {
            if (pass == 0 && shdrs[i].sh_type == SHT_DYNSYM) {
                symtab_shdr = &shdrs[i];
                strtab_shdr = &shdrs[symtab_shdr->sh_link];
                break;
            }
            if (pass == 1 && shdrs[i].sh_type == SHT_SYMTAB) {
                symtab_shdr = &shdrs[i];
                strtab_shdr = &shdrs[symtab_shdr->sh_link];
                break;
            }
        }

        if (symtab_shdr && strtab_shdr) {
            char* strtab = malloc(strtab_shdr->sh_size);
            if (strtab) {
                fseek(fp, strtab_shdr->sh_offset, SEEK_SET);
                fread(strtab, 1, strtab_shdr->sh_size, fp);

                int num_syms = symtab_shdr->sh_size / sizeof(Elf64_Sym);
                Elf64_Sym* syms = malloc(symtab_shdr->sh_size);
                if (syms) {
                    fseek(fp, symtab_shdr->sh_offset, SEEK_SET);
                    fread(syms, sizeof(Elf64_Sym), num_syms, fp);

                    for (int i = 0; i < num_syms; i++) {
                        if (syms[i].st_name && syms[i].st_value != 0 &&
                            strcmp(&strtab[syms[i].st_name], symbol_name) == 0) {
                            offset = syms[i].st_value;
                            LOGI("Found %s in %s at offset 0x%lx",
                                 symbol_name, pass == 0 ? ".dynsym" : ".symtab", offset);
                            break;
                        }
                    }
                    free(syms);
                }
                free(strtab);
            }
        }
    }

    free(shstrtab_data);
    free(shdrs);
    fclose(fp);
    return offset;
}

static void init_decode_jobject(void) {
    if (g_decode_init_tried) return;
    g_decode_init_tried = 1;

    const char* decode_symbols[] = {
        "_ZNK3art6Thread13DecodeJObjectEP8_jobject",
        "_ZN3art6Thread13DecodeJObjectEP8_jobject",
        NULL
    };

    const char* global_symbols[] = {
        "_ZNK3art6Thread19DecodeGlobalJObjectEP8_jobject",
        "_ZN3art6Thread19DecodeGlobalJObjectEP8_jobject",
        NULL
    };

    char lib_path[256] = {0};
    uintptr_t load_addr = find_lib_info("libart.so", lib_path, sizeof(lib_path));
    if (!load_addr) {
        LOGI("Could not find libart.so in /proc/self/maps");
        return;
    }
    LOGI("libart.so load_addr: 0x%lx, path: %s", load_addr, lib_path);

    uintptr_t first_load_vaddr = get_first_load_vaddr(lib_path);
    uintptr_t load_bias = load_addr - first_load_vaddr;
    LOGI("libart.so first_load_vaddr: 0x%lx, load_bias: 0x%lx", first_load_vaddr, load_bias);

    for (int s = 0; decode_symbols[s] && !g_decode_jobject; s++) {
        uintptr_t offset = find_symbol_offset(lib_path, decode_symbols[s]);
        if (offset) {
            g_decode_jobject = (DecodeJObject_t)(load_bias + offset);
            LOGI("Found DecodeJObject: %s at 0x%lx (bias=0x%lx + offset=0x%lx)",
                 decode_symbols[s], (uintptr_t)g_decode_jobject, load_bias, offset);
        }
    }

    for (int s = 0; global_symbols[s] && !g_decode_global_jobject; s++) {
        uintptr_t offset = find_symbol_offset(lib_path, global_symbols[s]);
        if (offset) {
            g_decode_global_jobject = (DecodeJObject_t)(load_bias + offset);
            LOGI("Found DecodeGlobalJObject: %s at 0x%lx (bias=0x%lx + offset=0x%lx)",
                 global_symbols[s], (uintptr_t)g_decode_global_jobject, load_bias, offset);
        }
    }

    if (!g_decode_jobject && !g_decode_global_jobject) {
        LOGI("No DecodeJObject functions found in %s", lib_path);
    }
}

#define INDIRECT_REF_KIND_MASK 0x3
#define INDIRECT_REF_KIND_LOCAL 0x1
#define INDIRECT_REF_KIND_GLOBAL 0x2
#define INDIRECT_REF_KIND_WEAK_GLOBAL 0x3

static void* try_decode_stacked_ref(jobject ref) {
    uintptr_t ref_val = (uintptr_t)ref;

    if ((ref_val & INDIRECT_REF_KIND_MASK) != INDIRECT_REF_KIND_LOCAL) {
        LOGI("Not a local ref: 0x%lx", ref_val);
        return NULL;
    }

    uintptr_t slot_addr = ref_val & ~((uintptr_t)0x3);

    if (slot_addr < 0x10000) {
        LOGI("Slot address too small (index-based ref?): 0x%lx, returning ref as-is", slot_addr);
        return NULL;
    }

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

    if (ref_kind == INDIRECT_REF_KIND_LOCAL) {
        void* stacked_result = try_decode_stacked_ref(ref);
        if (stacked_result) {
            LOGI("Stacked ref decode succeeded: 0x%lx", (uintptr_t)stacked_result);
            return stacked_result;
        }
    }

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

static int get_api_level_cached(void) {
    static int cached = 0;
    if (cached == 0) {
        char value[92];
        if (__system_property_get("ro.build.version.sdk", value) > 0) {
            cached = atoi(value);
        } else {
            cached = 30;
        }
    }
    return cached;
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

    void* result = decode_jni_ref(env, jstr);

    LOGI("newStringUTF('%s'): jni_ref=%p, raw_ptr=%p", str, jstr, result);

    lua_pushinteger(L, (lua_Integer)(uintptr_t)result);
    return 1;
}

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
