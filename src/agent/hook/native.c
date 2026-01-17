#include <agent/hook.h>
#include <agent/globals.h>
#include <agent/proc.h>

#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <capstone/capstone.h>
#include <capstone/arm64.h>

HookInfo g_hooks[MAX_HOOKS];
int g_hook_count = 0;

__thread int g_current_hook_index = -1;

static pthread_mutex_t g_lua_mutex = PTHREAD_MUTEX_INITIALIZER;

int change_page_protection(void* addr, int prot) {
    void* page = PAGE_START(addr);
    if (mprotect(page, PAGE_SIZE, prot) != 0) {
        LOGE("mprotect failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

uint32_t create_branch_insn(void* from, void* to) {
    int64_t offset = (int64_t)to - (int64_t)from;
    offset >>= 2;
    return 0x14000000 | (offset & 0x03FFFFFF);
}

void* allocate_trampoline(size_t size) {
    size_t aligned_size = ALIGN_UP(size, PAGE_SIZE);
    void* mem = mmap(NULL, aligned_size,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        LOGE("mmap failed: %s", strerror(errno));
        return NULL;
    }
    return mem;
}

size_t disassemble_instructions(void* addr, void** insn_out, size_t min_bytes) {
    csh handle;
    size_t count;
    cs_insn** out = (cs_insn**)insn_out;

    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        LOGE("cs_open failed");
        return 0;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(handle, (uint8_t*)addr, 16, (uint64_t)addr, 0, out);
    if (count == 0) {
        LOGE("cs_disasm failed");
        cs_close(&handle);
        return 0;
    }

    size_t total_bytes = 0;
    for (size_t i = 0; i < count && total_bytes < min_bytes; i++) {
        total_bytes += (*out)[i].size;
    }

    cs_close(&handle);
    return total_bytes;
}

bool is_pc_relative(void* insn_ptr) {
    cs_insn* insn = (cs_insn*)insn_ptr;

    switch (insn->id) {
        case ARM64_INS_ADRP:
        case ARM64_INS_ADR:
        case ARM64_INS_B:
        case ARM64_INS_BL:
        case ARM64_INS_CBZ:
        case ARM64_INS_CBNZ:
        case ARM64_INS_TBZ:
        case ARM64_INS_TBNZ:
            return true;

        case ARM64_INS_LDR:
            if (insn->detail->arm64.op_count == 2) {
                cs_arm64_op *op = &insn->detail->arm64.operands[1];
                if (op->type == ARM64_OP_MEM && op->mem.base == ARM64_REG_INVALID) {
                    return true;
                }
            }
            return false;

        default:
            return false;
    }
}

void** find_got_entry(void* func_addr) {


    uint32_t* insns = (uint32_t*)func_addr;

    if ((insns[0] & 0x9F000000) == 0x90000000) {
        uint64_t page = ((uint64_t)func_addr & ~0xFFFULL);
        int64_t immhi = (insns[0] >> 5) & 0x7FFFF;
        int64_t immlo = (insns[0] >> 29) & 0x3;
        int64_t imm = ((immhi << 2) | immlo) << 12;
        if (imm & (1ULL << 32)) {
            imm |= 0xFFFFFFFF00000000ULL;
        }
        page += imm;

        if ((insns[1] & 0xFFC00000) == 0xF9400000) {
            uint32_t ldr_imm = (insns[1] >> 10) & 0xFFF;
            uint64_t got_addr = page + (ldr_imm * 8);
            return (void**)got_addr;
        }
    }

    LOGE("Could not find GOT entry for function at %p", func_addr);
    return NULL;
}

int install_plt_got_hook(void* target_func, void* hook_func, HookInfo* hook_info) {
    LOGI("Installing PLT/GOT hook: target=%p hook=%p", target_func, hook_func);

    void** got_entry = find_got_entry(target_func);
    if (!got_entry) {
        LOGE("Failed to find GOT entry");
        return -1;
    }

    LOGI("Found GOT entry at %p, current value: %p", got_entry, *got_entry);

    if (change_page_protection(got_entry, PROT_READ | PROT_WRITE) != 0) {
        LOGE("Failed to change GOT page protection");
        return -1;
    }

    void* original_func = *got_entry;

    *got_entry = hook_func;

    hook_info->type = HOOK_PLT_GOT;
    hook_info->data.plt_got.got_entry = got_entry;
    hook_info->data.plt_got.original_func = original_func;
    hook_info->data.plt_got.hook_func = hook_func;

    LOGI("PLT/GOT hook installed: GOT entry=%p, original=%p, hook=%p",
         got_entry, original_func, hook_func);

    return 0;
}

int install_trampoline_hook(void* target_func, void* hook_func, HookInfo* hook_info) {
    LOGI("Installing trampoline hook: target=%p hook=%p", target_func, hook_func);

    cs_insn* insn = NULL;
    size_t bytes_to_copy = disassemble_instructions(target_func, (void**)&insn, 16);
    if (bytes_to_copy == 0) {
        LOGE("Failed to disassemble target function");
        return -1;
    }

    LOGI("Will copy %zu bytes from target function", bytes_to_copy);

    size_t insn_count = bytes_to_copy / 4;
    for (size_t i = 0; i < insn_count; i++) {
        if (is_pc_relative(&insn[i])) {
            LOGW("PC-relative instruction at offset %zu: %s", i * 4, insn[i].mnemonic);
        }
    }

    size_t trampoline_size = bytes_to_copy + 16;
    void* trampoline = allocate_trampoline(trampoline_size);
    if (!trampoline) {
        LOGE("Failed to allocate trampoline");
        cs_free(insn, insn_count);
        return -1;
    }

    memcpy(trampoline, target_func, bytes_to_copy);

    LOGI("Copied %zu bytes to trampoline at %p", bytes_to_copy, trampoline);

    void* return_addr = (void*)((uintptr_t)target_func + bytes_to_copy);
    void* branch_location = (void*)((uintptr_t)trampoline + bytes_to_copy);

    uint32_t* branch_insns = (uint32_t*)branch_location;
    branch_insns[0] = 0x58000050;
    branch_insns[1] = 0xd61f0200;
    *(uint64_t*)(&branch_insns[2]) = (uint64_t)return_addr;

    LOGI("Added branch back: from %p to %p", branch_location, return_addr);

    __builtin___clear_cache((char*)trampoline, (char*)((uintptr_t)trampoline + trampoline_size));

    if (change_page_protection(target_func, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("Failed to change target page protection");
        munmap(trampoline, ALIGN_UP(trampoline_size, PAGE_SIZE));
        cs_free(insn, insn_count);
        return -1;
    }

    uint32_t* target = (uint32_t*)target_func;
    hook_info->data.trampoline.original_insn[0] = target[0];
    if (bytes_to_copy > 4)  hook_info->data.trampoline.original_insn[1] = target[1];
    if (bytes_to_copy > 8)  hook_info->data.trampoline.original_insn[2] = target[2];
    if (bytes_to_copy > 12) hook_info->data.trampoline.original_insn[3] = target[3];

    target[0] = 0x58000050;
    target[1] = 0xd61f0200;
    *(uint64_t*)(&target[2]) = (uint64_t)hook_func;

    LOGI("Wrote hook sequence at %p", target_func);

    __builtin___clear_cache((char*)target_func, (char*)((uintptr_t)target_func + 16));

    hook_info->type = HOOK_TRAMPOLINE;
    hook_info->data.trampoline.target_addr = target_func;
    hook_info->data.trampoline.trampoline_addr = trampoline;
    hook_info->data.trampoline.hook_addr = hook_func;
    hook_info->data.trampoline.original_size = bytes_to_copy;

    cs_free(insn, insn_count);

    LOGI("Trampoline hook installed: target=%p trampoline=%p", target_func, trampoline);
    return 0;
}

int uninstall_hook(int hook_id) {
    if (hook_id < 0 || hook_id >= g_hook_count) {
        LOGE("Invalid hook ID: %d", hook_id);
        return -1;
    }

    HookInfo* hook = &g_hooks[hook_id];

    if (hook->type == HOOK_TRAMPOLINE) {
        if (hook->data.trampoline.target_addr == NULL) {
            LOGI("Hook %d already uninstalled", hook_id);
            return 0;
        }

        void* target = hook->data.trampoline.target_addr;

        if (change_page_protection(target, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            LOGE("Failed to change page protection for unhook");
            return -1;
        }

        uint32_t* target_insns = (uint32_t*)target;
        target_insns[0] = hook->data.trampoline.original_insn[0];
        target_insns[1] = hook->data.trampoline.original_insn[1];
        target_insns[2] = hook->data.trampoline.original_insn[2];
        target_insns[3] = hook->data.trampoline.original_insn[3];

        __builtin___clear_cache((char*)target, (char*)((uintptr_t)target + 16));

        if (hook->data.trampoline.trampoline_addr) {
            munmap(hook->data.trampoline.trampoline_addr, PAGE_SIZE);
        }

        hook->data.trampoline.target_addr = NULL;
        hook->data.trampoline.trampoline_addr = NULL;

    } else if (hook->type == HOOK_PLT_GOT) {
        if (hook->data.plt_got.got_entry == NULL) {
            LOGI("Hook %d already uninstalled", hook_id);
            return 0;
        }

        void** got_entry = hook->data.plt_got.got_entry;

        if (change_page_protection(got_entry, PROT_READ | PROT_WRITE) != 0) {
            LOGE("Failed to change page protection for unhook");
            return -1;
        }

        *got_entry = hook->data.plt_got.original_func;

        LOGI("Restored GOT entry at %p to %p", got_entry, hook->data.plt_got.original_func);

        hook->data.plt_got.got_entry = NULL;
        hook->data.plt_got.original_func = NULL;
    }

    if (hook->thunk_addr) {
        munmap(hook->thunk_addr, PAGE_SIZE);
        hook->thunk_addr = NULL;
    }

    if (g_lua_engine && hook->lua_onEnter_ref != LUA_NOREF) {
        lua_State* L = lua_engine_get_state(g_lua_engine);
        if (L) {
            luaL_unref(L, LUA_REGISTRYINDEX, hook->lua_onEnter_ref);
        }
    }
    if (g_lua_engine && hook->lua_onLeave_ref != LUA_NOREF) {
        lua_State* L = lua_engine_get_state(g_lua_engine);
        if (L) {
            luaL_unref(L, LUA_REGISTRYINDEX, hook->lua_onLeave_ref);
        }
    }

    hook->lua_onEnter_ref = LUA_NOREF;
    hook->lua_onLeave_ref = LUA_NOREF;

    LOGI("Hook %d uninstalled", hook_id);
    return 0;
}

int uninstall_all_hooks(void) {
    int count = 0;
    for (int i = 0; i < g_hook_count; i++) {
        bool is_installed = false;

        if (g_hooks[i].type == HOOK_TRAMPOLINE) {
            is_installed = (g_hooks[i].data.trampoline.target_addr != NULL);
        } else if (g_hooks[i].type == HOOK_PLT_GOT) {
            is_installed = (g_hooks[i].data.plt_got.got_entry != NULL);
        }

        if (is_installed && uninstall_hook(i) == 0) {
            count++;
        }
    }
    LOGI("Uninstalled %d hooks", count);
    return count;
}

void* create_hook_thunk(int hook_index) {
    void* thunk = mmap(NULL, PAGE_SIZE,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (thunk == MAP_FAILED) {
        LOGE("Failed to allocate thunk");
        return NULL;
    }

    uint32_t* code = (uint32_t*)thunk;

    code[0] = 0xD2800011 | ((hook_index & 0xFFFF) << 5);

    code[1] = 0x58000070;

    code[2] = 0xD61F0200;

    code[3] = 0xD503201F;

    *(uint64_t*)(&code[4]) = (uint64_t)generic_hook_handler;

    __builtin___clear_cache((char*)thunk, (char*)thunk + 32);

    LOGI("Created thunk at %p for hook index %d", thunk, hook_index);
    return thunk;
}

bool install_lua_hook(const char* lib_name, uintptr_t offset, int onEnter_ref, int onLeave_ref) {
    LOGI("Installing Lua hook: %s+0x%lx", lib_name, offset);

    uintptr_t base = (uintptr_t)find_library_base(lib_name);
    if (base == 0) {
        LOGE("Library not found: %s", lib_name);
        return false;
    }

    uintptr_t target_addr = base + offset;
    LOGI("Hook target address: 0x%lx", target_addr);

    if (g_hook_count >= MAX_HOOKS) {
        LOGE("Maximum hooks reached");
        return false;
    }

    int hook_index = g_hook_count;
    HookInfo* hook_info = &g_hooks[hook_index];
    hook_info->lua_onEnter_ref = onEnter_ref;
    hook_info->lua_onLeave_ref = onLeave_ref;
    hook_info->hook_index = hook_index;

    void* thunk = create_hook_thunk(hook_index);
    if (!thunk) {
        LOGE("Failed to create hook thunk");
        return false;
    }
    hook_info->thunk_addr = thunk;

    int result = -1;
    if (g_default_hook_type == HOOK_PLT_GOT) {
        LOGI("Using PLT/GOT hooking method");
        result = install_plt_got_hook((void*)target_addr, thunk, hook_info);
    } else {
        LOGI("Using trampoline hooking method");
        result = install_trampoline_hook((void*)target_addr, thunk, hook_info);
    }

    if (result != 0) {
        LOGE("Failed to install hook");
        munmap(thunk, PAGE_SIZE);
        return false;
    }

    g_hook_count++;

    LOGI("Lua hook #%d installed (type=%s, onEnter=%d, onLeave=%d)",
         hook_index,
         g_default_hook_type == HOOK_PLT_GOT ? "PLT/GOT" : "Trampoline",
         onEnter_ref, onLeave_ref);
    return true;
}

__attribute__((naked)) void generic_hook_handler(void) {
    __asm__ __volatile__(
        "stp x29, x30, [sp, #-16]!\n"
        "mov x29, sp\n"
        "sub sp, sp, #288\n"  

        "str x17, [sp, #256]\n"

        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "stp x18, x19, [sp, #144]\n"
        "stp x20, x21, [sp, #160]\n"
        "stp x22, x23, [sp, #176]\n"
        "stp x24, x25, [sp, #192]\n"
        "stp x26, x27, [sp, #208]\n"
        "stp x28, xzr, [sp, #224]\n"

        "ldr x0, [sp, #256]\n"
        "bl set_current_hook_index\n"

        "mov x0, sp\n"
        "bl hook_logger\n"

        "bl get_current_trampoline\n"
        "str x0, [sp, #264]\n"  

        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"

        "ldr x16, [sp, #264]\n"

        "blr x16\n"

        "bl log_return_value\n"

        "add sp, sp, #288\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n"
    );
}

void set_current_hook_index(int index) {
    g_current_hook_index = index;
    LOGI("Set current hook index to %d", index);
}

void hook_logger(uint64_t* saved_regs) {
    uint64_t x0 = saved_regs[0];
    uint64_t x1 = saved_regs[1];
    uint64_t x2 = saved_regs[2];
    uint64_t x3 = saved_regs[3];
    uint64_t x4 = saved_regs[4];
    uint64_t x5 = saved_regs[5];
    uint64_t x6 = saved_regs[6];
    uint64_t x7 = saved_regs[7];

    if (x0 != 0) {
        g_current_jni_env = (JNIEnv*)x0;
    }

    LOGI("=== HOOK #%d: Function Called ===", g_current_hook_index);
    LOGI("  x0-x3: 0x%llx 0x%llx 0x%llx 0x%llx",
         (unsigned long long)x0, (unsigned long long)x1,
         (unsigned long long)x2, (unsigned long long)x3);

    LOGI("  [DEBUG] g_lua_engine=%p, hook_index=%d", g_lua_engine, g_current_hook_index);

    if (g_current_hook_index >= 0 && g_lua_engine) {
        HookInfo* hook = &g_hooks[g_current_hook_index];
        LOGI("  [DEBUG] onEnter_ref=%d (NOREF=%d)", hook->lua_onEnter_ref, LUA_NOREF);

        if (hook->lua_onEnter_ref != LUA_NOREF) {
            pthread_mutex_lock(&g_lua_mutex);
            lua_State* L = lua_engine_get_state(g_lua_engine);
            LOGI("  [DEBUG] lua_State=%p", L);
            if (L) {
                lua_rawgeti(L, LUA_REGISTRYINDEX, hook->lua_onEnter_ref);
                lua_newtable(L);

                uint64_t params[] = {x0, x1, x2, x3, x4, x5, x6, x7};

                for (int i = 0; i < 8; i++) {
                    lua_pushinteger(L, params[i]);
                    lua_rawseti(L, -2, i);
                }

                LOGI("  [DEBUG] Calling lua_pcall...");
                if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                    LOGE("onEnter callback failed: %s", lua_tostring(L, -1));
                    lua_pop(L, 1);
                } else {
                    LOGI("  [DEBUG] lua_pcall succeeded");
                }
            }
            pthread_mutex_unlock(&g_lua_mutex);
        }
    } else {
        LOGI("  [DEBUG] Skipped: engine=%p, index=%d", g_lua_engine, g_current_hook_index);
    }
}

uint64_t log_return_value(uint64_t ret_val) {
    LOGI("=== HOOK: Function Returned ===");
    LOGI("  x0 (return): 0x%llx (%lld)", (unsigned long long)ret_val, (long long)ret_val);

    if (g_current_hook_index >= 0 && g_lua_engine) {
        HookInfo* hook = &g_hooks[g_current_hook_index];

        if (hook->lua_onLeave_ref != LUA_NOREF) {
            pthread_mutex_lock(&g_lua_mutex);
            lua_State* L = lua_engine_get_state(g_lua_engine);
            if (L) {
                lua_rawgeti(L, LUA_REGISTRYINDEX, hook->lua_onLeave_ref);
                lua_pushinteger(L, ret_val);

                if (lua_pcall(L, 1, 1, 0) == LUA_OK) {
                    if (lua_isnil(L, -1)) {
                    } else if (lua_istable(L, -1)) {
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
                            lua_pop(L, 1);
                        } else {
                            lua_pop(L, 1);
                        }
                    } else if (lua_isinteger(L, -1) || lua_isnumber(L, -1)) {
                        ret_val = (uint64_t)lua_tointeger(L, -1);
                        LOGI("  Modified to: 0x%llx", (unsigned long long)ret_val);
                    }
                    lua_pop(L, 1);
                } else {
                    LOGE("onLeave callback failed: %s", lua_tostring(L, -1));
                    lua_pop(L, 1);
                }
            }
            pthread_mutex_unlock(&g_lua_mutex);
        }
    }
    return ret_val;
}

void* get_current_trampoline(void) {
    if (g_current_hook_index >= 0) {
        HookInfo* hook = &g_hooks[g_current_hook_index];

        if (hook->type == HOOK_TRAMPOLINE) {
            return hook->data.trampoline.trampoline_addr;
        } else if (hook->type == HOOK_PLT_GOT) {
            return hook->data.plt_got.original_func;
        }
    }
    return NULL;
}

bool install_lua_java_hook(const char* class_name, const char* method_name,
                           const char* signature, int onEnter_ref, int onLeave_ref) {
    if (!g_current_jni_env) {
        LOGE("JNIEnv not available for Java hook");
        return false;
    }

    int result = install_java_hook(g_current_jni_env,
                                   class_name,
                                   method_name,
                                   signature,
                                   onEnter_ref,
                                   onLeave_ref);
    return result >= 0;
}
