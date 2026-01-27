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
#include <elf.h>
#include <fcntl.h>

JavaHookInfo g_java_hooks[MAX_JAVA_HOOKS];
int g_java_hook_count = 0;

static int g_api_level = 0;
static ArtMethodOffsets g_offsets = {0};
static bool g_java_hook_initialized = false;
static pthread_mutex_t g_java_hook_mutex = PTHREAD_MUTEX_INITIALIZER;

// Use recursive mutex to allow nested hook callbacks (parent calling child)
static pthread_mutex_t g_java_lua_mutex;
static pthread_once_t g_lua_mutex_init_once = PTHREAD_ONCE_INIT;

static void init_recursive_lua_mutex(void) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_java_lua_mutex, &attr);
    pthread_mutexattr_destroy(&attr);
    LOGI("Initialized recursive Lua mutex for nested hooks");
}

// Thread-local hook call stack for tracking nested calls
#define MAX_HOOK_CALL_DEPTH 16
typedef struct {
    int hook_indices[MAX_HOOK_CALL_DEPTH];
    int depth;
} HookCallStack;

static __thread HookCallStack g_hook_call_stack = {{0}, 0};

static __thread int g_current_java_hook_index = -1;

static void* g_interpreter_bridge = NULL;

static uint64_t nativized_method_stub(void) {
    int hook_index = g_current_java_hook_index;
    if (hook_index >= 0 && hook_index < g_java_hook_count) {
        JavaHookInfo* hook = &g_java_hooks[hook_index];
        if (hook->has_stored_return) {
            LOGI("nativized_method_stub returning stored value: 0x%llx",
                 (unsigned long long)hook->stored_return_value);
            return hook->stored_return_value;
        }
    }
    LOGW("nativized_method_stub: no stored return value, returning 0");
    return 0;
}


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

static void* elf_find_symbol(const char* lib_path, uintptr_t load_addr, const char* symbol_name) {
    int fd = open(lib_path, O_RDONLY);
    if (fd < 0) return NULL;

    off_t file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    void* map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (map == MAP_FAILED) return NULL;

    void* result = NULL;
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)map;

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        goto cleanup;
    }

    Elf64_Phdr* phdr = (Elf64_Phdr*)((uint8_t*)map + ehdr->e_phoff);
    uintptr_t first_load_vaddr = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            first_load_vaddr = phdr[i].p_vaddr;
            break;
        }
    }

    uintptr_t load_bias = load_addr - first_load_vaddr;

    Elf64_Shdr* shdr = (Elf64_Shdr*)((uint8_t*)map + ehdr->e_shoff);
    Elf64_Shdr* shstrtab = &shdr[ehdr->e_shstrndx];
    const char* shstrtab_data = (const char*)map + shstrtab->sh_offset;

    Elf64_Shdr* dynsym_shdr = NULL;
    Elf64_Shdr* dynstr_shdr = NULL;
    Elf64_Shdr* symtab_shdr = NULL;
    Elf64_Shdr* strtab_shdr = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char* name = shstrtab_data + shdr[i].sh_name;
        if (strcmp(name, ".dynsym") == 0) dynsym_shdr = &shdr[i];
        else if (strcmp(name, ".dynstr") == 0) dynstr_shdr = &shdr[i];
        else if (strcmp(name, ".symtab") == 0) symtab_shdr = &shdr[i];
        else if (strcmp(name, ".strtab") == 0) strtab_shdr = &shdr[i];
    }

    if (dynsym_shdr && dynstr_shdr) {
        Elf64_Sym* symtab = (Elf64_Sym*)((uint8_t*)map + dynsym_shdr->sh_offset);
        const char* strtab = (const char*)map + dynstr_shdr->sh_offset;
        size_t sym_count = dynsym_shdr->sh_size / sizeof(Elf64_Sym);

        for (size_t i = 0; i < sym_count; i++) {
            const char* name = strtab + symtab[i].st_name;
            if (strcmp(name, symbol_name) == 0 && symtab[i].st_value != 0) {
                result = (void*)(load_bias + symtab[i].st_value);
                LOGI("ELF: Found %s in .dynsym at %p", symbol_name, result);
                goto cleanup;
            }
        }
    }

    if (!result && symtab_shdr && strtab_shdr) {
        Elf64_Sym* symtab = (Elf64_Sym*)((uint8_t*)map + symtab_shdr->sh_offset);
        const char* strtab = (const char*)map + strtab_shdr->sh_offset;
        size_t sym_count = symtab_shdr->sh_size / sizeof(Elf64_Sym);

        for (size_t i = 0; i < sym_count; i++) {
            const char* name = strtab + symtab[i].st_name;
            if (strcmp(name, symbol_name) == 0 && symtab[i].st_value != 0) {
                result = (void*)(load_bias + symtab[i].st_value);
                LOGI("ELF: Found %s in .symtab at %p", symbol_name, result);
                goto cleanup;
            }
        }
    }

cleanup:
    munmap(map, file_size);
    return result;
}

static void* elf_find_symbol_containing(const char* lib_path, uintptr_t load_addr,
                                         const char* pattern, char* found_name, size_t found_name_size) {
    int fd = open(lib_path, O_RDONLY);
    if (fd < 0) return NULL;

    off_t file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    void* map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (map == MAP_FAILED) return NULL;

    void* result = NULL;
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)map;

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        goto cleanup;
    }

    Elf64_Phdr* phdr = (Elf64_Phdr*)((uint8_t*)map + ehdr->e_phoff);
    uintptr_t first_load_vaddr = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            first_load_vaddr = phdr[i].p_vaddr;
            break;
        }
    }

    uintptr_t load_bias = load_addr - first_load_vaddr;

    Elf64_Shdr* shdr = (Elf64_Shdr*)((uint8_t*)map + ehdr->e_shoff);
    Elf64_Shdr* shstrtab = &shdr[ehdr->e_shstrndx];
    const char* shstrtab_data = (const char*)map + shstrtab->sh_offset;

    Elf64_Shdr* dynsym_shdr = NULL;
    Elf64_Shdr* dynstr_shdr = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char* name = shstrtab_data + shdr[i].sh_name;
        if (strcmp(name, ".dynsym") == 0) dynsym_shdr = &shdr[i];
        else if (strcmp(name, ".dynstr") == 0) dynstr_shdr = &shdr[i];
    }

    if (dynsym_shdr && dynstr_shdr) {
        Elf64_Sym* symtab = (Elf64_Sym*)((uint8_t*)map + dynsym_shdr->sh_offset);
        const char* strtab = (const char*)map + dynstr_shdr->sh_offset;
        size_t sym_count = dynsym_shdr->sh_size / sizeof(Elf64_Sym);

        for (size_t i = 0; i < sym_count; i++) {
            const char* name = strtab + symtab[i].st_name;
            if (strstr(name, pattern) && symtab[i].st_value != 0) {
                if (strstr(name, "_ZN3art6Thread") || strstr(name, "_ZN3art9JNIEnvExt")) {
                    if (strstr(name, "Offset") || strstr(name, "Cookie") ||
                        strstr(name, "Size") || strstr(name, "Capacity") ||
                        strstr(name, "Count") || strstr(name, "Get") ||
                        strstr(name, "Set") || strstr(name, "Check") ||
                        strstr(name, "Trim") || strstr(name, "Remove") ||
                        strstr(name, "Pop") || strstr(name, "Segment")) {
                        LOGI("ELF: Skipping wrong function: %s", name);
                        continue;
                    }

                    bool is_create_func = (strstr(name, "Create") || strstr(name, "New") ||
                                           strstr(name, "Add") || strstr(name, "Push"));
                    bool is_ref_func = (strstr(name, "LocalRef") || strstr(name, "Reference") ||
                                        strstr(name, "JObject"));

                    if (is_create_func && is_ref_func) {
                        result = (void*)(load_bias + symtab[i].st_value);
                        if (found_name && found_name_size > 0) {
                            strncpy(found_name, name, found_name_size - 1);
                            found_name[found_name_size - 1] = '\0';
                        }
                        LOGI("ELF: Found matching symbol '%s': %s at %p", pattern, name, result);
                        goto cleanup;
                    }
                }
            }
        }
    }

cleanup:
    munmap(map, file_size);
    return result;
}

static void* find_interpreter_bridge(JNIEnv* env) {
    (void)env;

    if (g_interpreter_bridge) {
        return g_interpreter_bridge;
    }

    void* handle = dlopen("libart.so", RTLD_NOW | RTLD_NOLOAD);
    if (handle) {
        void* bridge = dlsym(handle, "art_quick_to_interpreter_bridge");
        if (bridge) {
            g_interpreter_bridge = bridge;
            LOGI("Found art_quick_to_interpreter_bridge via dlsym: %p", bridge);
            return bridge;
        }
    }

    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return NULL;

    char line[512];
    uintptr_t libart_base = 0;
    char libart_path[256] = {0};

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libart.so")) {
            unsigned long start;
            char path[256] = {0};
            if (sscanf(line, "%lx-%*lx %*4s %*x %*s %*d %255s", &start, path) >= 1) {
                if (libart_base == 0 || start < libart_base) {
                    libart_base = start;
                    if (path[0]) strncpy(libart_path, path, sizeof(libart_path) - 1);
                }
            }
        }
    }
    fclose(fp);

    if (!libart_base || !libart_path[0]) {
        LOGE("Could not find libart.so in /proc/self/maps");
        return NULL;
    }

    LOGI("libart.so base: 0x%lx, path: %s", (unsigned long)libart_base, libart_path);

    void* bridge = elf_find_symbol(libart_path, libart_base, "art_quick_to_interpreter_bridge");
    if (bridge) {
        g_interpreter_bridge = bridge;
        return bridge;
    }

    LOGE("Could not find art_quick_to_interpreter_bridge in ELF");
    return NULL;
}


#define ROUND_UP_PTR(x) (((x) + 7) & ~7)

const ArtMethodOffsets* get_art_method_offsets(void) {
    if (g_offsets.api_level > 0) {
        return &g_offsets;
    }

    int api = get_android_api_level();
    g_offsets.api_level = api;


    g_offsets.access_flags_offset = 4;


    // ArtMethod layout changed between Android 11 and Android 12:
    // - Android 11 (API 30) and earlier: has dex_code_item_offset_ field
    //   Layout: declaring_class(4) + access_flags(4) + dex_code_item_offset(4) +
    //           dex_method_index(4) + method_index(2) + hotness_count(2) = 20 bytes
    //   Aligned to 8: 24, then data_(8), then entry_point at offset 32
    //
    // - Android 12+ (API 31+): dex_code_item_offset_ was removed
    //   Layout: declaring_class(4) + access_flags(4) + dex_method_index(4) +
    //           method_index(2) + hotness_count(2) = 16 bytes
    //   Aligned to 8: 16, then data_(8), then entry_point at offset 24
    //
    // Sources:
    // - Android 11: https://android.googlesource.com/platform/art/+/android-11.0.0_r1/runtime/art_method.h
    // - Android 12: https://android.googlesource.com/platform/art/+/android-12.0.0_r1/runtime/art_method.h

    if (api >= 31) {
        // Android 12+ (API 31+): dex_code_item_offset_ removed, entry_point at offset 24
        g_offsets.entry_point_offset = ROUND_UP_PTR(4 + 4 + 4 + 2 + 2) + 8;  // = 24
        g_offsets.art_method_size = g_offsets.entry_point_offset + 8;  // = 32
    } else if (api >= 26) {
        // Android 8.0-11 (API 26-30): has dex_code_item_offset_, entry_point at offset 32
        g_offsets.entry_point_offset = ROUND_UP_PTR(4 + 4 + 4 + 4 + 2 + 2) + 8;  // = 32
        g_offsets.art_method_size = g_offsets.entry_point_offset + 8;  // = 40
    } else {
        // Older versions
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


static uint64_t java_hook_call_original(int hook_index, uint64_t* saved_regs);

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

    code[idx++] = 0xD2800000 | ((hook_index & 0xFFFF) << 5);
    code[idx++] = 0x910003E1;
    int call_original_ldr_idx = idx;
    code[idx++] = 0x58000010;  // ldr x16, [pc, #offset]
    code[idx++] = 0xD63F0200;  // blr x16

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

    int call_original_addr_idx = idx;
    *(uint64_t*)(&code[idx]) = (uint64_t)java_hook_call_original;
    idx += 2;

    *(uint64_t*)(&code[idx]) = (uint64_t)hook_index;
    idx += 2;

    // Patch LDR offsets
    int onenter_offset = (onenter_addr_idx - onenter_ldr_idx) * 4;
    code[onenter_ldr_idx] = 0x58000010 | ((onenter_offset / 4) << 5);

    int call_original_offset = (call_original_addr_idx - call_original_ldr_idx) * 4;
    code[call_original_ldr_idx] = 0x58000010 | ((call_original_offset / 4) << 5);

    int onleave_offset = (onleave_addr_idx - onleave_ldr_idx) * 4;
    code[onleave_ldr_idx] = 0x58000010 | ((onleave_offset / 4) << 5);

    __builtin___clear_cache((char*)trampoline, (char*)trampoline + idx * 4 + 32);

    LOGI("Created Java hook trampoline at %p (size=%d bytes)", trampoline, idx * 4);

    return trampoline;
}


typedef jobject (*CreateLocalRef_t)(void* thread, void* obj);
static CreateLocalRef_t g_create_local_ref = NULL;
static int g_create_local_ref_init_tried = 0;

static void init_create_local_ref(void) {
    if (g_create_local_ref_init_tried) return;
    g_create_local_ref_init_tried = 1;

    const char* symbols[] = {
        "_ZN3art6Thread14NewLocalRefLRTEPNS_6mirror6ObjectE",
        "_ZN3art6Thread16NewLocalRefLRTEEPNS_6mirror6ObjectE",
        "_ZN3art6Thread15AddLocalRefLRTEPNS_6mirror6ObjectE",
        "_ZN3art6Thread14CreateLocalRefEPNS_6mirror6ObjectE",
        "_ZNK3art6Thread14CreateLocalRefEPNS_6mirror6ObjectE",
        "_ZN3art9JNIEnvExt17AddLocalReferenceINS_6mirror6ObjectEEEP8_jobjectNS_6ObjPtrIT_EE",
        "_ZN3art9JNIEnvExt17AddLocalReferenceINS_6mirror6ObjectEEEP8_jobjectPT_",
        "_ZN3art6Thread13CreateJObjectEPNS_6mirror6ObjectE",
        NULL
    };

    void* handle = dlopen("libart.so", RTLD_NOW | RTLD_NOLOAD);
    if (handle) {
        for (int i = 0; symbols[i] && !g_create_local_ref; i++) {
            g_create_local_ref = (CreateLocalRef_t)dlsym(handle, symbols[i]);
            if (g_create_local_ref) {
                LOGI("Found CreateLocalRef via dlsym: %s at %p", symbols[i], g_create_local_ref);
                return;
            }
        }
    }

    for (int i = 0; symbols[i] && !g_create_local_ref; i++) {
        g_create_local_ref = (CreateLocalRef_t)dlsym(RTLD_DEFAULT, symbols[i]);
        if (g_create_local_ref) {
            LOGI("Found CreateLocalRef via RTLD_DEFAULT: %s at %p", symbols[i], g_create_local_ref);
            return;
        }
    }

    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("CreateLocalRef: Cannot open /proc/self/maps");
        return;
    }

    char line[512];
    uintptr_t libart_base = 0;
    char libart_path[256] = {0};

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libart.so")) {
            unsigned long start;
            char path[256] = {0};
            if (sscanf(line, "%lx-%*lx %*4s %*x %*s %*d %255s", &start, path) >= 1) {
                if (libart_base == 0 || start < libart_base) {
                    libart_base = start;
                    if (path[0]) strncpy(libart_path, path, sizeof(libart_path) - 1);
                }
            }
        }
    }
    fclose(fp);

    if (!libart_base || !libart_path[0]) {
        LOGE("CreateLocalRef: Could not find libart.so in maps");
        return;
    }

    LOGI("CreateLocalRef: libart.so at 0x%lx: %s", (unsigned long)libart_base, libart_path);

    for (int i = 0; symbols[i] && !g_create_local_ref; i++) {
        g_create_local_ref = (CreateLocalRef_t)elf_find_symbol(libart_path, libart_base, symbols[i]);
        if (g_create_local_ref) {
            LOGI("Found CreateLocalRef via ELF: %s at %p", symbols[i], g_create_local_ref);
            return;
        }
    }

    if (!g_create_local_ref) {
        char found_name[512] = {0};
        const char* patterns[] = {"LocalRef", "AddLocal", "CreateLocal", NULL};

        for (int i = 0; patterns[i] && !g_create_local_ref; i++) {
            g_create_local_ref = (CreateLocalRef_t)elf_find_symbol_containing(
                libart_path, libart_base, patterns[i], found_name, sizeof(found_name));
            if (g_create_local_ref) {
                LOGI("Found CreateLocalRef via pattern '%s': %s at %p",
                     patterns[i], found_name, g_create_local_ref);
                return;
            }
        }
    }

    if (!g_create_local_ref) {
        LOGW("CreateLocalRef not found - will use direct IndirectRef table access");
    }
}

typedef jobject (*IRT_Add_t)(void* table, uint32_t cookie, void* obj);
static IRT_Add_t g_irt_add = NULL;
static int g_irt_add_init_tried = 0;

static void init_irt_add(const char* libart_path, uintptr_t libart_base) {
    if (g_irt_add_init_tried) return;
    g_irt_add_init_tried = 1;

    const char* patterns[] = {
        "IndirectReferenceTable",
        NULL
    };

    char found_name[512] = {0};
    for (int i = 0; patterns[i] && !g_irt_add; i++) {
        void* func = elf_find_symbol_containing(libart_path, libart_base,
                                                 "Add", found_name, sizeof(found_name));
        if (func && strstr(found_name, "IndirectReferenceTable")) {
            g_irt_add = (IRT_Add_t)func;
            LOGI("Found IRT::Add: %s at %p", found_name, func);
        }
    }
}

static jobject raw_ptr_to_jni_ref(JNIEnv* env, void* raw_ptr) {
    if (!raw_ptr) return NULL;

    init_create_local_ref();

    if (g_create_local_ref) {
        void** env_ptr = (void**)env;
        void* thread = env_ptr[1];  // self is at offset 8

        if (thread) {
            jobject ref = g_create_local_ref(thread, raw_ptr);
            LOGI("raw_ptr_to_jni_ref: %p -> %p (via CreateLocalRef)", raw_ptr, ref);
            return ref;
        }
    }

    int api = get_android_api_level();
    if (api >= 29) {
        uintptr_t ptr_val = (uintptr_t)raw_ptr;
        if ((ptr_val & 0x3) == 0) {
            jobject stacked_ref = (jobject)(ptr_val | 0x1);
            LOGI("raw_ptr_to_jni_ref: %p -> %p (stacked ref attempt)", raw_ptr, stacked_ref);
            return stacked_ref;
        }
    }

    LOGW("raw_ptr_to_jni_ref: Cannot safely convert %p, CreateLocalRef unavailable", raw_ptr);
    return NULL;
}

static __thread uint32_t g_in_original_call_mask = 0;

static void call_original_via_jni(JavaHookInfo* hook, uint64_t* saved_regs) {
    int hook_index = hook->hook_index;
    uint32_t hook_bit = (hook_index < 32) ? (1u << hook_index) : 0;

    if (hook_bit && (g_in_original_call_mask & hook_bit)) {
        LOGW("call_original_via_jni: recursive call detected for hook #%d, skipping", hook_index);
        hook->stored_return_value = 0;
        hook->has_stored_return = true;
        return;
    }

    JNIEnv* env = get_jni_env();
    jobject receiver = (jobject)saved_regs[1];

    if (!env || !hook->method_id) {
        LOGE("call_original_via_jni: env=%p, method_id=%p (get_jni_env failed?)", env, hook->method_id);
        hook->stored_return_value = 0;
        hook->has_stored_return = true;
        return;
    }

    LOGI("call_original_via_jni: %s.%s%s (env=%p, receiver=%p)",
         hook->class_name, hook->method_name, hook->method_sig, env, receiver);

    const ArtMethodOffsets* offsets = get_art_method_offsets();
    uint32_t* access_flags_ptr = (uint32_t*)((uintptr_t)hook->art_method + offsets->access_flags_offset);

    void* page = (void*)((uintptr_t)access_flags_ptr & ~(PAGE_SIZE - 1));
    if (mprotect(page, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        LOGE("call_original_via_jni: mprotect failed: %s", strerror(errno));
        hook->stored_return_value = 0;
        hook->has_stored_return = true;
        return;
    }

    void** entry_point_ptr = (void**)((uintptr_t)hook->art_method + offsets->entry_point_offset);

    void* page_entry = (void*)((uintptr_t)entry_point_ptr & ~(PAGE_SIZE - 1));
    if (mprotect(page_entry, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        LOGE("call_original_via_jni: mprotect entry_point failed: %s", strerror(errno));
        hook->stored_return_value = 0;
        hook->has_stored_return = true;
        return;
    }

    uint32_t current_flags = *access_flags_ptr;
    void* current_entry = *entry_point_ptr;

    *access_flags_ptr = hook->original_access_flags;  // Remove kAccNative
    *entry_point_ptr = hook->original_entry_point;    // Restore original entry point

    __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    LOGI("  Temporarily restored flags: 0x%x -> 0x%x", current_flags, hook->original_access_flags);
    LOGI("  Temporarily restored entry_point: %p -> %p", current_entry, hook->original_entry_point);

    jvalue args[6] = {0};
    const char* sig = hook->method_sig;
    const char* p = sig;
    if (*p == '(') p++;

    int arg_idx = 0;
    int reg_idx = 2;

    while (*p && *p != ')' && arg_idx < 6) {
        switch (*p) {
            case 'Z': args[arg_idx].z = (jboolean)saved_regs[reg_idx]; break;
            case 'B': args[arg_idx].b = (jbyte)saved_regs[reg_idx]; break;
            case 'C': args[arg_idx].c = (jchar)saved_regs[reg_idx]; break;
            case 'S': args[arg_idx].s = (jshort)saved_regs[reg_idx]; break;
            case 'I': args[arg_idx].i = (jint)saved_regs[reg_idx]; break;
            case 'J': args[arg_idx].j = (jlong)saved_regs[reg_idx]; break;
            case 'F': args[arg_idx].f = *(float*)&saved_regs[reg_idx]; break;
            case 'D': args[arg_idx].d = *(double*)&saved_regs[reg_idx]; break;
            case 'L':
                args[arg_idx].l = (jobject)saved_regs[reg_idx];
                while (*p && *p != ';') p++;
                break;
            case '[':
                args[arg_idx].l = (jobject)saved_regs[reg_idx];
                p++;
                if (*p == 'L') {
                    while (*p && *p != ';') p++;
                }
                break;
        }
        LOGI("  arg[%d] = 0x%llx", arg_idx, (unsigned long long)saved_regs[reg_idx]);
        arg_idx++;
        reg_idx++;
        if (*p) p++;
    }

    while (*p && *p != ')') p++;
    if (*p == ')') p++;
    char return_type = *p;

    LOGI("  Calling method (return_type=%c, is_static=%d)", return_type, hook->is_static);

    if (hook_bit) {
        g_in_original_call_mask |= hook_bit;
    }

    if (hook->is_static) {
        switch (return_type) {
            case 'V':
                (*env)->CallStaticVoidMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                hook->stored_return_value = 0;
                break;
            case 'Z':
                hook->stored_return_value = (*env)->CallStaticBooleanMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                break;
            case 'B':
                hook->stored_return_value = (*env)->CallStaticByteMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                break;
            case 'C':
                hook->stored_return_value = (*env)->CallStaticCharMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                break;
            case 'S':
                hook->stored_return_value = (*env)->CallStaticShortMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                break;
            case 'I':
                hook->stored_return_value = (*env)->CallStaticIntMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                break;
            case 'J':
                hook->stored_return_value = (*env)->CallStaticLongMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                break;
            case 'F': {
                float f = (*env)->CallStaticFloatMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                hook->stored_return_value = *(uint32_t*)&f;
                break;
            }
            case 'D': {
                double d = (*env)->CallStaticDoubleMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                hook->stored_return_value = *(uint64_t*)&d;
                break;
            }
            case 'L':
            case '[': {
                jobject result = (*env)->CallStaticObjectMethodA(env, hook->clazz_global_ref, hook->method_id, args);
                hook->stored_return_value = (uint64_t)result;
                break;
            }
        }
    } else {
        switch (return_type) {
            case 'V':
                (*env)->CallVoidMethodA(env, receiver, hook->method_id, args);
                hook->stored_return_value = 0;
                break;
            case 'Z':
                hook->stored_return_value = (*env)->CallBooleanMethodA(env, receiver, hook->method_id, args);
                break;
            case 'B':
                hook->stored_return_value = (*env)->CallByteMethodA(env, receiver, hook->method_id, args);
                break;
            case 'C':
                hook->stored_return_value = (*env)->CallCharMethodA(env, receiver, hook->method_id, args);
                break;
            case 'S':
                hook->stored_return_value = (*env)->CallShortMethodA(env, receiver, hook->method_id, args);
                break;
            case 'I':
                hook->stored_return_value = (*env)->CallIntMethodA(env, receiver, hook->method_id, args);
                break;
            case 'J':
                hook->stored_return_value = (*env)->CallLongMethodA(env, receiver, hook->method_id, args);
                break;
            case 'F': {
                float f = (*env)->CallFloatMethodA(env, receiver, hook->method_id, args);
                hook->stored_return_value = *(uint32_t*)&f;
                break;
            }
            case 'D': {
                double d = (*env)->CallDoubleMethodA(env, receiver, hook->method_id, args);
                hook->stored_return_value = *(uint64_t*)&d;
                break;
            }
            case 'L':
            case '[': {
                jobject result = (*env)->CallObjectMethodA(env, receiver, hook->method_id, args);
                hook->stored_return_value = (uint64_t)result;
                break;
            }
        }
    }

    if (hook_bit) {
        g_in_original_call_mask &= ~hook_bit;
    }

    if ((*env)->ExceptionCheck(env)) {
        LOGE("call_original_via_jni: exception occurred");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        hook->stored_return_value = 0;
    }

    *access_flags_ptr = current_flags;
    *entry_point_ptr = current_entry;
    __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    hook->has_stored_return = true;
    LOGI("  Result: 0x%llx", (unsigned long long)hook->stored_return_value);
}

typedef uint64_t (*interpreter_call_t)(void* bridge, uint64_t* regs);

static uint64_t call_interpreter_bridge_asm(void* bridge, uint64_t* regs) {
    uint64_t result = 0;

    __asm__ volatile(
        // Prologue: proper frame setup for ART compatibility
        "stp x29, x30, [sp, #-96]!\n"  // Push frame and allocate 96 bytes
        "mov x29, sp\n"                 // Set frame pointer (CRITICAL for nested calls)
        "stp x19, x20, [sp, #16]\n"     // Save more callee-saved regs
        "stp x21, x22, [sp, #32]\n"

        // Store our parameters in callee-saved locations
        "mov x20, %[bridge]\n"          // x20 = bridge (callee-saved)
        "mov x21, %[regs]\n"            // x21 = regs (callee-saved)
        "mov x22, %[result_ptr]\n"      // x22 = result_ptr (callee-saved)

        // Load x19 from regs[19] (ART thread pointer for some ART versions)
        "ldr x19, [x21, #152]\n"        // x19 = regs[19]

        // Load argument registers from saved_regs
        "ldr x0, [x21, #0]\n"           // x0 = regs[0] (ArtMethod*)
        "ldr x1, [x21, #8]\n"           // x1 = regs[1] (receiver/this)
        "ldr x2, [x21, #16]\n"          // x2 = regs[2] (arg1)
        "ldr x3, [x21, #24]\n"          // x3 = regs[3] (arg2)
        "ldr x4, [x21, #32]\n"          // x4 = regs[4] (arg3)
        "ldr x5, [x21, #40]\n"          // x5 = regs[5] (arg4)
        "ldr x6, [x21, #48]\n"          // x6 = regs[6] (arg5)
        "ldr x7, [x21, #56]\n"          // x7 = regs[7] (arg6)

        // Call the original entry point
        "blr x20\n"

        // Store result - x22 is preserved across calls (callee-saved)
        "str x0, [x22]\n"

        // Epilogue: restore callee-saved registers
        "ldp x21, x22, [sp, #32]\n"
        "ldp x19, x20, [sp, #16]\n"
        "ldp x29, x30, [sp], #96\n"     // Restore frame and deallocate

        :
        : [bridge] "r"(bridge), [regs] "r"(regs), [result_ptr] "r"(&result)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
          "x16", "x17", "x18", "memory", "cc"
    );

    return result;
}

static void call_original_via_interpreter(JavaHookInfo* hook, uint64_t* saved_regs) {
    int hook_index = hook->hook_index;
    uint32_t hook_bit = (hook_index < 32) ? (1u << hook_index) : 0;

    if (hook_bit && (g_in_original_call_mask & hook_bit)) {
        LOGW("call_original_via_interpreter: recursive call detected for hook #%d, skipping", hook_index);
        hook->stored_return_value = 0;
        hook->has_stored_return = true;
        return;
    }

    const ArtMethodOffsets* offsets = get_art_method_offsets();

    uint32_t* access_flags_ptr = (uint32_t*)((uintptr_t)hook->art_method + offsets->access_flags_offset);
    void** entry_point_ptr = (void**)((uintptr_t)hook->art_method + offsets->entry_point_offset);

    uint32_t current_flags = *access_flags_ptr;
    void* current_entry = *entry_point_ptr;

    LOGI("call_original_via_interpreter: %s.%s%s",
         hook->class_name, hook->method_name, hook->method_sig);
    LOGI("  Current flags: 0x%x, original: 0x%x", current_flags, hook->original_access_flags);
    LOGI("  Current entry: %p, interpreter bridge: %p", current_entry, g_interpreter_bridge);

    if (!g_interpreter_bridge) {
        LOGE("call_original_via_interpreter: No interpreter bridge available");
        hook->stored_return_value = 0;
        hook->has_stored_return = true;
        return;
    }

    void* page = (void*)((uintptr_t)access_flags_ptr & ~(PAGE_SIZE - 1));
    if (mprotect(page, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        LOGE("call_original_via_interpreter: mprotect failed: %s", strerror(errno));
        hook->stored_return_value = 0;
        hook->has_stored_return = true;
        return;
    }

    *access_flags_ptr = hook->original_access_flags;
    __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);

    *entry_point_ptr = g_interpreter_bridge;
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    LOGI("  Temporarily restored: flags=0x%x, entry=%p",
         *access_flags_ptr, *entry_point_ptr);

    LOGI("  Calling interpreter bridge with x0=%p x1=%p x2=%p x3=%p x19=%p",
         (void*)saved_regs[0], (void*)saved_regs[1],
         (void*)saved_regs[2], (void*)saved_regs[3], (void*)saved_regs[19]);

    if (hook_bit) {
        g_in_original_call_mask |= hook_bit;
    }

    uint64_t result = call_interpreter_bridge_asm(g_interpreter_bridge, saved_regs);

    if (hook_bit) {
        g_in_original_call_mask &= ~hook_bit;
    }

    LOGI("  Interpreter bridge returned: 0x%llx", (unsigned long long)result);

    *entry_point_ptr = current_entry;
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    *access_flags_ptr = current_flags;
    __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);

    LOGI("  Restored: flags=0x%x, entry=%p", *access_flags_ptr, *entry_point_ptr);

    hook->stored_return_value = result;
    hook->has_stored_return = true;
}

static uint64_t java_hook_call_original(int hook_index, uint64_t* saved_regs) {
    if (hook_index < 0 || hook_index >= g_java_hook_count) {
        LOGE("java_hook_call_original: Invalid hook index: %d", hook_index);
        return 0;
    }

    JavaHookInfo* hook = &g_java_hooks[hook_index];

    LOGI("java_hook_call_original: hook #%d, was_nativized=%d",
         hook_index, hook->was_nativized);

    const ArtMethodOffsets* offsets = get_art_method_offsets();
    uint32_t* access_flags_ptr = (uint32_t*)((uintptr_t)hook->art_method + offsets->access_flags_offset);
    void** entry_point_ptr = (void**)((uintptr_t)hook->art_method + offsets->entry_point_offset);

    uint32_t current_flags = *access_flags_ptr;
    void* current_entry = *entry_point_ptr;

    void* page = (void*)((uintptr_t)access_flags_ptr & ~(PAGE_SIZE - 1));
    if (mprotect(page, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        LOGE("java_hook_call_original: mprotect failed: %s", strerror(errno));
        return 0;
    }

    *access_flags_ptr = hook->original_access_flags;
    *entry_point_ptr = hook->original_entry_point;
    __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    LOGI("  Temporarily restored: flags 0x%x -> 0x%x, entry %p -> %p",
         current_flags, hook->original_access_flags,
         current_entry, hook->original_entry_point);

    uint64_t result = call_interpreter_bridge_asm(hook->original_entry_point, saved_regs);

    LOGI("  Original entry point returned: 0x%llx", (unsigned long long)result);

    *access_flags_ptr = current_flags;
    *entry_point_ptr = current_entry;
    __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    return result;
}

void java_hook_on_enter(int hook_index, uint64_t* saved_regs) {
    if (hook_index < 0 || hook_index >= g_java_hook_count) {
        LOGE("Invalid Java hook index: %d", hook_index);
        return;
    }

    JavaHookInfo* hook = &g_java_hooks[hook_index];

    if (g_hook_call_stack.depth < MAX_HOOK_CALL_DEPTH) {
        g_hook_call_stack.hook_indices[g_hook_call_stack.depth] = hook_index;
        g_hook_call_stack.depth++;
    } else {
        LOGW("Hook call stack overflow! depth=%d, skipping hook #%d",
             g_hook_call_stack.depth, hook_index);
        return;
    }

    g_current_java_hook_index = hook_index;

    LOGI("=== Java Hook #%d onEnter: %s.%s%s (depth=%d) ===",
         hook_index, hook->class_name, hook->method_name, hook->method_sig,
         g_hook_call_stack.depth);

    uint64_t x0 = saved_regs[0];
    uint64_t x1 = saved_regs[1];
    uint64_t x2 = saved_regs[2];
    uint64_t x3 = saved_regs[3];

    LOGI("  Args: X0=0x%llx X1=0x%llx X2=0x%llx X3=0x%llx",
         (unsigned long long)x0, (unsigned long long)x1,
         (unsigned long long)x2, (unsigned long long)x3);

    if (hook->lua_onEnter_ref != LUA_NOREF && g_lua_engine) {
        pthread_mutex_lock(&g_java_lua_mutex);
        lua_State* L = lua_engine_get_state(g_lua_engine);
        if (L) {
            lua_rawgeti(L, LUA_REGISTRYINDEX, hook->lua_onEnter_ref);

            lua_newtable(L);

            lua_pushstring(L, hook->class_name);
            lua_setfield(L, -2, "class");
            lua_pushstring(L, hook->method_name);
            lua_setfield(L, -2, "method");
            lua_pushstring(L, hook->method_sig);
            lua_setfield(L, -2, "signature");
            lua_pushboolean(L, hook->is_static);
            lua_setfield(L, -2, "isStatic");

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

uint64_t java_hook_on_leave(int hook_index, uint64_t ret_val) {
    if (hook_index < 0 || hook_index >= g_java_hook_count) {
        LOGE("Invalid Java hook index in onLeave: %d", hook_index);
        return ret_val;
    }

    JavaHookInfo* hook = &g_java_hooks[hook_index];

    LOGI("=== Java Hook #%d onLeave: %s.%s%s (depth=%d) ===",
         hook_index, hook->class_name, hook->method_name, hook->method_sig,
         g_hook_call_stack.depth);
    LOGI("  Return value: 0x%llx (%lld)", (unsigned long long)ret_val, (long long)ret_val);

    if (hook->lua_onLeave_ref != LUA_NOREF && g_lua_engine) {
        pthread_mutex_lock(&g_java_lua_mutex);
        lua_State* L = lua_engine_get_state(g_lua_engine);
        if (L) {
            lua_rawgeti(L, LUA_REGISTRYINDEX, hook->lua_onLeave_ref);
            lua_pushinteger(L, ret_val);

            if (lua_pcall(L, 1, 1, 0) == LUA_OK) {
                int api = get_android_api_level();
                bool method_expects_jni_refs = hook->was_nativized;
                bool can_modify_objects = (api < 30 || api >= 35 || method_expects_jni_refs);

                if (lua_isnil(L, -1)) {
                } else if (lua_istable(L, -1)) {
                    lua_getfield(L, -1, "__jni_type");
                    if (lua_isstring(L, -1)) {
                        const char* jni_type = lua_tostring(L, -1);
                        lua_pop(L, 1);
                        lua_getfield(L, -1, "value");

                        if (strcmp(jni_type, "string") == 0 && lua_isstring(L, -1)) {
                            if (can_modify_objects) {
                                const char* str_value = lua_tostring(L, -1);
                                if (g_current_jni_env && str_value) {
                                    jstring new_str = (*g_current_jni_env)->NewStringUTF(g_current_jni_env, str_value);
                                    ret_val = (uint64_t)new_str;
                                    LOGI("  Modified to jstring: \"%s\"", str_value);
                                }
                            } else {
                                LOGW("  Return value modification (string) not supported on API %d", api);
                            }
                        } else if (strcmp(jni_type, "int") == 0 || strcmp(jni_type, "long") == 0) {
                            ret_val = (uint64_t)lua_tointeger(L, -1);
                            LOGI("  Modified to %s: %lld", jni_type, (long long)ret_val);
                        } else if (strcmp(jni_type, "boolean") == 0) {
                            ret_val = lua_toboolean(L, -1) ? 1 : 0;
                            LOGI("  Modified to boolean: %s", ret_val ? "true" : "false");
                        }
                        lua_pop(L, 1);
                    } else {
                        lua_pop(L, 1);
                    }
                } else if (lua_isinteger(L, -1) || lua_isnumber(L, -1)) {
                    uint64_t new_val = (uint64_t)lua_tointeger(L, -1);
                    if (!can_modify_objects && new_val < 0x10000) {
                        LOGW("  Return value modification (0x%llx) blocked - method not nativized on API %d",
                             (unsigned long long)new_val, api);
                    } else {
                        ret_val = new_val;
                        if (method_expects_jni_refs && new_val < 0x10000) {
                            LOGI("  Modified to JNI ref: 0x%llx", (unsigned long long)ret_val);
                        } else {
                            LOGI("  Modified to: 0x%llx", (unsigned long long)ret_val);
                        }
                    }
                }
                lua_pop(L, 1);
            } else {
                LOGE("Java hook onLeave callback failed: %s", lua_tostring(L, -1));
                lua_pop(L, 1);
            }
        }
        pthread_mutex_unlock(&g_java_lua_mutex);
    }

    if (g_hook_call_stack.depth > 0) {
        g_hook_call_stack.depth--;
        if (g_hook_call_stack.depth > 0) {
            g_current_java_hook_index = g_hook_call_stack.hook_indices[g_hook_call_stack.depth - 1];
        } else {
            g_current_java_hook_index = -1;
        }
    }

    return ret_val;
}


int java_hook_init(JNIEnv* env) {
    pthread_once(&g_lua_mutex_init_once, init_recursive_lua_mutex);

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

    if (!g_interpreter_bridge) {
        g_interpreter_bridge = find_interpreter_bridge(env);
        if (g_interpreter_bridge) {
            LOGI("Interpreter bridge found during init: %p", g_interpreter_bridge);
        } else {
            LOGW("Interpreter bridge not found during init - will try again later");
        }
    }

    g_java_hook_initialized = true;

    pthread_mutex_unlock(&g_java_hook_mutex);

    LOGI("Java hook subsystem initialized (API %d)", get_android_api_level());
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

    uint32_t* access_flags_ptr = (uint32_t*)((uintptr_t)art_method + offsets->access_flags_offset);
    uint32_t original_flags = *access_flags_ptr;
    bool need_nativize = false;

    LOGI("Original access_flags: 0x%x (native=%d)", original_flags, (original_flags & kAccNative) ? 1 : 0);

    if (original_entry == NULL || original_entry == (void*)0) {
        LOGI("Entry point is NULL - method not JIT compiled, using nativization approach");

        void* bridge = find_interpreter_bridge(env);
        if (bridge) {
            LOGI("Found interpreter bridge: %p", bridge);
            original_entry = bridge;
        }

        if (original_entry == NULL || original_entry == (void*)0) {
            jclass system_class = (*env)->FindClass(env, "java/lang/System");
            if (system_class) {
                jmethodID arraycopy = (*env)->GetStaticMethodID(env, system_class,
                    "arraycopy", "(Ljava/lang/Object;ILjava/lang/Object;II)V");
                if (arraycopy) {
                    void* arraycopy_art = jmethodid_to_art_method(env, arraycopy, system_class);
                    if (arraycopy_art) {
                        void** arraycopy_entry_ptr = (void**)((uintptr_t)arraycopy_art + offsets->entry_point_offset);
                        void* arraycopy_entry = *arraycopy_entry_ptr;
                        if (arraycopy_entry && arraycopy_entry != (void*)0) {
                            LOGI("Found entry point from System.arraycopy (native): %p", arraycopy_entry);
                        }
                    }
                }
                (*env)->DeleteLocalRef(env, system_class);
            }

            jclass runtime_class = (*env)->FindClass(env, "java/lang/Runtime");
            if (runtime_class) {
                jmethodID gc = (*env)->GetMethodID(env, runtime_class, "gc", "()V");
                if (gc) {
                    void* gc_art = jmethodid_to_art_method(env, gc, runtime_class);
                    if (gc_art) {
                        void** gc_entry_ptr = (void**)((uintptr_t)gc_art + offsets->entry_point_offset);
                        void* gc_entry = *gc_entry_ptr;
                        if (gc_entry && gc_entry != (void*)0) {
                            LOGI("Found entry point from Runtime.gc (native): %p", gc_entry);
                        }
                    }
                }
                (*env)->DeleteLocalRef(env, runtime_class);
            }
        }

        if (original_entry == NULL || original_entry == (void*)0) {
            LOGI("No interpreter bridge found, will nativize method (callbacks only mode)");
            need_nativize = true;
            original_entry = (void*)nativized_method_stub;
            LOGI("Using nativized_method_stub as fallback original: %p", original_entry);
        }
    }

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
    hook->original_access_flags = original_flags;
    hook->was_nativized = need_nativize;

    hook->clazz_global_ref = (*env)->NewGlobalRef(env, clazz);
    hook->method_id = method_id;
    hook->stored_return_value = 0;
    hook->has_stored_return = false;

    void* trampoline = create_java_hook_trampoline(hook_index);
    if (!trampoline) {
        LOGE("Failed to create trampoline");
        (*env)->DeleteLocalRef(env, clazz);
        pthread_mutex_unlock(&g_java_hook_mutex);
        return -1;
    }

    hook->hook_trampoline = trampoline;

    int api = get_android_api_level();
    if (api >= 30 && !(original_flags & kAccNative)) {
        LOGI("Setting kAccNative flag for proper hook on API %d (0x%x -> 0x%x)",
             api, original_flags, original_flags | kAccNative);
        *access_flags_ptr = original_flags | kAccNative;
        __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);
        hook->was_nativized = true;

        LOGI("Method was nativized - will use JNI reflection to call original (nested hooks supported)");
    } else if (need_nativize) {
        LOGI("Nativizing method: setting kAccNative flag (0x%x -> 0x%x)",
             original_flags, original_flags | kAccNative);
        *access_flags_ptr = original_flags | kAccNative;
        __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);
    }


    LOGI("Setting entry_point: %p -> %p", *entry_point_ptr, trampoline);
    *entry_point_ptr = trampoline;
    __builtin___clear_cache((char*)entry_point_ptr, (char*)entry_point_ptr + 8);

    void* verify = *entry_point_ptr;
    if (verify == trampoline) {
        LOGI("Entry point successfully changed to trampoline");
    } else {
        LOGE("Entry point write FAILED! Expected %p, got %p", trampoline, verify);
    }

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

    if (hook->was_nativized) {
        uint32_t* access_flags_ptr = (uint32_t*)((uintptr_t)hook->art_method + offsets->access_flags_offset);
        LOGI("Restoring original access_flags: 0x%x", hook->original_access_flags);
        *access_flags_ptr = hook->original_access_flags;
        __builtin___clear_cache((char*)access_flags_ptr, (char*)access_flags_ptr + 4);
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
