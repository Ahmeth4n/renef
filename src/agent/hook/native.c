#include <agent/hook.h>
#include <agent/globals.h>
#include <agent/proc.h>
#include <agent/lua_thread.h>

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sched.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <capstone/capstone.h>

// Reentrancy guard: prevents infinite recursion when a hooked function
// (e.g. __android_log_print, strlen, fopen) is called from inside the
// hook handler itself (via LOGI, verbose_log, etc.)
static __thread int g_hook_reentrant = 0;
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

// --- Dynamic PLT/GOT resolution via dl_iterate_phdr ---

struct got_scan_ctx {
    const char* sym_name;       // Symbol name to find (e.g. "memcpy")
    const char* caller_lib;     // Optional: only patch this library's GOT
    void* hook_func;            // The hook thunk to redirect to
    HookInfo* hook_info;        // Where to store patched GOT entries
    void* original_func;        // The resolved original function address
};

static int got_scan_callback(struct dl_phdr_info *info, size_t size, void *data) {
    struct got_scan_ctx *ctx = (struct got_scan_ctx *)data;

    // Skip entries with no name (vdso, main executable)
    if (!info->dlpi_name || strlen(info->dlpi_name) == 0) {
        return 0;
    }

    // If caller_lib is specified, only scan matching libraries
    // caller_lib can be a single name or comma-separated list
    if (ctx->caller_lib && strlen(ctx->caller_lib) > 0) {
        // "*" wildcard — scan all libraries
        if (strcmp(ctx->caller_lib, "*") != 0) {
            bool match = false;
            char callers_copy[1024];
            strncpy(callers_copy, ctx->caller_lib, sizeof(callers_copy) - 1);
            callers_copy[sizeof(callers_copy) - 1] = '\0';

            char* saveptr = NULL;
            char* token = strtok_r(callers_copy, ",", &saveptr);
            while (token) {
                if (strstr(info->dlpi_name, token)) {
                    match = true;
                    break;
                }
                token = strtok_r(NULL, ",", &saveptr);
            }
            if (!match) return 0;
        }
    } else {
        // No caller specified — should not reach here for PLT/GOT
        return 0;
    }

    ElfW(Addr) base = info->dlpi_addr;

    // Find PT_DYNAMIC segment
    const ElfW(Dyn)* dyn = NULL;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = (const ElfW(Dyn)*)(base + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }

    if (!dyn) return 0;

    // Extract dynamic entries
    ElfW(Addr) jmprel_addr = 0;
    size_t pltrelsz = 0;
    ElfW(Addr) symtab_addr = 0;
    ElfW(Addr) strtab_addr = 0;

    for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_JMPREL:   jmprel_addr  = d->d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrelsz     = d->d_un.d_val; break;
            case DT_SYMTAB:   symtab_addr  = d->d_un.d_ptr; break;
            case DT_STRTAB:   strtab_addr  = d->d_un.d_ptr; break;
        }
    }

    if (!jmprel_addr || !symtab_addr || !strtab_addr || pltrelsz == 0) {
        return 0;
    }

    // On Android, d_ptr values may be relative offsets (not relocated by linker).
    // Detect this: if the value is smaller than the module base, it's relative.
    if (jmprel_addr < base)  jmprel_addr  += base;
    if (symtab_addr < base)  symtab_addr  += base;
    if (strtab_addr < base)  strtab_addr  += base;

    const ElfW(Rela)* jmprel = (const ElfW(Rela)*)jmprel_addr;
    const ElfW(Sym)* symtab  = (const ElfW(Sym)*)symtab_addr;
    const char* strtab       = (const char*)strtab_addr;

    size_t rela_count = pltrelsz / sizeof(ElfW(Rela));

    verbose_log("Scanning GOT of %s (%zu relocation entries)", info->dlpi_name, rela_count);

    for (size_t i = 0; i < rela_count; i++) {
        unsigned long sym_idx = ELF64_R_SYM(jmprel[i].r_info);
        const char* name = strtab + symtab[sym_idx].st_name;

        if (strcmp(name, ctx->sym_name) == 0) {
            void** got_addr = (void**)(base + jmprel[i].r_offset);

            LOGI("Found GOT entry for '%s' in %s at %p (current value: %p)",
                 ctx->sym_name, info->dlpi_name, got_addr, *got_addr);

            int idx = ctx->hook_info->data.plt_got.patched_count;
            if (idx >= 64) {
                LOGW("Maximum GOT patches reached (64)");
                return 1;
            }

            ctx->hook_info->data.plt_got.got_entries[idx] = got_addr;
            ctx->hook_info->data.plt_got.original_funcs[idx] = *got_addr;
            if (idx == 0) {
                ctx->original_func = *got_addr;
            }

            void* new_val = ctx->hook_func;
            int got_fd = open("/proc/self/mem", O_RDWR);
            if (got_fd >= 0) {
                pwrite(got_fd, &new_val, sizeof(void*), (off_t)(uintptr_t)got_addr);
                close(got_fd);
            } else {
                if (change_page_protection(got_addr, PROT_READ | PROT_WRITE) != 0) {
                    LOGE("Failed to change GOT page protection for %p", got_addr);
                    continue;
                }
                *got_addr = ctx->hook_func;
            }
            ctx->hook_info->data.plt_got.patched_count++;

            LOGI("Patched GOT entry at %p: %p -> %p",
                 got_addr, ctx->hook_info->data.plt_got.original_funcs[idx], ctx->hook_func);
        }
    }

    return 0;
}

int install_plt_got_hook(void* target_func, void* hook_func, HookInfo* hook_info, const char* caller_lib) {
    LOGI("Installing PLT/GOT hook: target=%p hook=%p", target_func, hook_func);

    // Step 1: Resolve symbol name via dladdr
    Dl_info dl_info;
    if (!dladdr(target_func, &dl_info) || !dl_info.dli_sname) {
        LOGE("dladdr failed: cannot resolve symbol name for %p", target_func);
        return -1;
    }

    LOGI("Resolved symbol: %s (from %s)", dl_info.dli_sname, dl_info.dli_fname);

    // Step 2: Initialize hook_info for PLT/GOT
    hook_info->type = HOOK_PLT_GOT;
    hook_info->data.plt_got.patched_count = 0;
    hook_info->data.plt_got.hook_func = hook_func;

    // Step 3: Scan loaded modules for GOT entries matching the symbol
    struct got_scan_ctx ctx = {
        .sym_name = dl_info.dli_sname,
        .caller_lib = caller_lib,
        .hook_func = hook_func,
        .hook_info = hook_info,
        .original_func = NULL
    };

    dl_iterate_phdr(got_scan_callback, &ctx);

    if (hook_info->data.plt_got.patched_count == 0) {
        LOGE("No GOT entries found for symbol '%s'", dl_info.dli_sname);
        return -1;
    }

    LOGI("PLT/GOT hook installed: %d GOT entries patched for '%s'",
         hook_info->data.plt_got.patched_count, dl_info.dli_sname);

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

    uint32_t* target = (uint32_t*)target_func;
    hook_info->data.trampoline.original_insn[0] = target[0];
    if (bytes_to_copy > 4)  hook_info->data.trampoline.original_insn[1] = target[1];
    if (bytes_to_copy > 8)  hook_info->data.trampoline.original_insn[2] = target[2];
    if (bytes_to_copy > 12) hook_info->data.trampoline.original_insn[3] = target[3];

    uint8_t hook_bytes[16];
    uint32_t* hb = (uint32_t*)hook_bytes;
    hb[0] = 0x58000050;
    hb[1] = 0xd61f0200;
    *(uint64_t*)(&hb[2]) = (uint64_t)hook_func;

    int mem_fd = open("/proc/self/mem", O_RDWR);
    if (mem_fd >= 0) {
        ssize_t written = pwrite(mem_fd, hook_bytes, 16, (off_t)(uintptr_t)target_func);
        close(mem_fd);
        if (written != 16) {
            LOGE("pwrite failed (%zd): %s, falling back to mprotect", written, strerror(errno));
            goto mprotect_fallback;
        }
        LOGI("Wrote hook via /proc/self/mem (no mprotect)");
    } else {
        mprotect_fallback:
        if (change_page_protection(target_func, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            LOGE("Failed to change target page protection");
            munmap(trampoline, ALIGN_UP(trampoline_size, PAGE_SIZE));
            cs_free(insn, insn_count);
            return -1;
        }
        memcpy(target_func, hook_bytes, 16);
        LOGI("Wrote hook via mprotect fallback");
    }

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
        if (hook->data.plt_got.patched_count == 0) {
            LOGI("Hook %d already uninstalled", hook_id);
            return 0;
        }

        for (int i = 0; i < hook->data.plt_got.patched_count; i++) {
            void** got_entry = hook->data.plt_got.got_entries[i];
            if (!got_entry) continue;

            if (change_page_protection(got_entry, PROT_READ | PROT_WRITE) != 0) {
                LOGE("Failed to change GOT page protection for uninstall (entry %d)", i);
                continue;
            }

            *got_entry = hook->data.plt_got.original_funcs[i];
            __builtin___clear_cache((char*)got_entry, (char*)got_entry + sizeof(void*));
            hook->data.plt_got.got_entries[i] = NULL;
        }

        hook->data.plt_got.patched_count = 0;

        if (hook->thunk_addr) {
            munmap(hook->thunk_addr, PAGE_SIZE);
            hook->thunk_addr = NULL;
        }
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
            is_installed = (g_hooks[i].data.plt_got.patched_count > 0);
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

// ============================================================
// Deferred hooks: installed automatically when a library loads
// ============================================================

typedef struct {
    char lib_name[128];
    uintptr_t offset;
    int onEnter_ref;
    int onLeave_ref;
    char caller_lib[128];
    bool active;
} PendingHook;

#define MAX_PENDING_HOOKS 16
static PendingHook g_pending_hooks[MAX_PENDING_HOOKS];
static int g_pending_hook_count = 0;
static bool g_dlopen_hooked = false;

static void try_install_pending_hooks(void);

static void* deferred_poll_thread(void* arg) {
    (void)arg;
    LOGI("[deferred] Poll thread started (busy-wait for lib load)");

    // Busy-wait poll: no sleep between iterations. Maximizes chances of
    // installing the hook between dlopen() returning and the first call
    // to the hooked function. sched_yield() lets other threads run but
    // we resume polling as soon as the scheduler gives us CPU.
    while (1) {
        bool all_done = true;
        for (int i = 0; i < g_pending_hook_count; i++) {
            if (g_pending_hooks[i].active) {
                all_done = false;
                break;
            }
        }
        if (all_done) break;

        try_install_pending_hooks();
        sched_yield(); // give other threads a chance, but no sleep
    }

    LOGI("[deferred] All pending hooks installed, poll thread exiting");
    return NULL;
}

static void start_deferred_poll(void) {
    if (g_dlopen_hooked) return;
    g_dlopen_hooked = true;

    pthread_t tid;
    pthread_create(&tid, NULL, deferred_poll_thread, NULL);
    pthread_detach(tid);
    LOGI("[deferred] Started library load watcher (busy-wait)");
}

static void try_install_pending_hooks(void) {
    for (int i = 0; i < g_pending_hook_count; i++) {
        PendingHook* ph = &g_pending_hooks[i];
        if (!ph->active) continue;

        uintptr_t base = (uintptr_t)find_library_base(ph->lib_name);
        if (base == 0) continue;

        LOGI("[deferred] Library %s now loaded at 0x%lx, installing hook at +0x%lx",
             ph->lib_name, base, ph->offset);

        // Install the hook now
        ph->active = false;
        install_lua_hook(ph->lib_name, ph->offset,
                        ph->onEnter_ref, ph->onLeave_ref,
                        ph->caller_lib[0] ? ph->caller_lib : NULL);
    }
}

static bool add_pending_hook(const char* lib_name, uintptr_t offset,
                             int onEnter_ref, int onLeave_ref,
                             const char* caller_lib) {
    if (g_pending_hook_count >= MAX_PENDING_HOOKS) {
        LOGE("[deferred] Maximum pending hooks reached");
        return false;
    }

    PendingHook* ph = &g_pending_hooks[g_pending_hook_count++];
    strncpy(ph->lib_name, lib_name, sizeof(ph->lib_name) - 1);
    ph->offset = offset;
    ph->onEnter_ref = onEnter_ref;
    ph->onLeave_ref = onLeave_ref;
    if (caller_lib) {
        strncpy(ph->caller_lib, caller_lib, sizeof(ph->caller_lib) - 1);
    } else {
        ph->caller_lib[0] = '\0';
    }
    ph->active = true;

    // Start polling for library loads
    start_deferred_poll();

    LOGI("[deferred] Pending hook registered: %s+0x%lx (will install on load)",
         lib_name, offset);
    return true;
}

// ============================================================

bool install_lua_hook(const char* lib_name, uintptr_t offset, int onEnter_ref, int onLeave_ref, const char* caller_lib) {
    LOGI("Installing Lua hook: %s+0x%lx", lib_name, offset);

    uintptr_t base = (uintptr_t)find_library_base(lib_name);
    if (base == 0) {
        LOGI("Library %s not loaded yet, deferring hook", lib_name);
        return add_pending_hook(lib_name, offset, onEnter_ref, onLeave_ref, caller_lib);
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
    if (caller_lib && strlen(caller_lib) > 0) {
        LOGI("Using PLT/GOT hooking method (caller: %s)", caller_lib);
        result = install_plt_got_hook((void*)target_addr, thunk, hook_info, caller_lib);
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
         (caller_lib && strlen(caller_lib) > 0) ? "PLT/GOT" : "Trampoline",
         onEnter_ref, onLeave_ref);
    return true;
}

// Check reentrancy and return trampoline address for bypass.
// Returns NULL if not reentrant (normal path), or trampoline addr to skip handler.
void* check_hook_reentrant(int hook_index) {
    if (g_hook_reentrant) {
        // Reentrant: return trampoline so handler can be bypassed
        g_current_hook_index = hook_index;
        return get_current_trampoline();
    }
    g_hook_reentrant = 1;
    return NULL;
}

__attribute__((naked)) void generic_hook_handler(void) {
    __asm__ __volatile__(
        "stp x29, x30, [sp, #-16]!\n"
        "mov x29, sp\n"
        "sub sp, sp, #288\n"

        "str x17, [sp, #256]\n"

        // Save all regs FIRST (before any C call)
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

        // Check reentrancy BEFORE any logging
        "ldr x0, [sp, #256]\n"       // x0 = hook_index
        "bl check_hook_reentrant\n"
        "cbnz x0, .Lreentrant_bypass\n" // if non-NULL, skip handler

        // Normal path: run hook handler
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

        // Reentrant bypass: skip handler, go straight to trampoline
        ".Lreentrant_bypass:\n"
        "str x0, [sp, #264]\n"       // store trampoline addr

        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"

        "ldr x16, [sp, #264]\n"

        "add sp, sp, #288\n"
        "ldp x29, x30, [sp], #16\n"
        "br x16\n"                    // tail-call trampoline (no blr — don't return here)
    );
}

void set_current_hook_index(int index) {
    g_current_hook_index = index;
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

    verbose_log("=== HOOK #%d: Function Called ===", g_current_hook_index);
    verbose_log("  x0-x3: 0x%llx 0x%llx 0x%llx 0x%llx",
         (unsigned long long)x0, (unsigned long long)x1,
         (unsigned long long)x2, (unsigned long long)x3);

    verbose_log("  [DEBUG] g_lua_engine=%p, hook_index=%d", g_lua_engine, g_current_hook_index);

    g_hook_caller_fp = saved_regs[36];
    g_hook_caller_lr = saved_regs[37];

    if (g_current_hook_index >= 0 && g_lua_engine) {
        HookInfo* hook = &g_hooks[g_current_hook_index];
        verbose_log("  [DEBUG] onEnter_ref=%d (NOREF=%d)", hook->lua_onEnter_ref, LUA_NOREF);

        if (hook->lua_onEnter_ref != LUA_NOREF) {
            pthread_mutex_lock(&g_lua_mutex);
            lua_State* L = lua_engine_get_state(g_lua_engine);
            verbose_log("  [DEBUG] lua_State=%p", L);
            if (L) {
                lua_rawgeti(L, LUA_REGISTRYINDEX, hook->lua_onEnter_ref);
                lua_newtable(L);

                uint64_t params[] = {x0, x1, x2, x3, x4, x5, x6, x7};

                for (int i = 0; i < 8; i++) {
                    lua_pushinteger(L, params[i]);
                    lua_rawseti(L, -2, i);
                }

                lua_pushvalue(L, -1);
                int args_ref = luaL_ref(L, LUA_REGISTRYINDEX);

                verbose_log("  [DEBUG] Calling lua_pcall...");
                if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                    LOGE("onEnter callback failed: %s", lua_tostring(L, -1));
                    lua_pop(L, 1);
                } else {
                    verbose_log("  [DEBUG] lua_pcall succeeded");

                    lua_rawgeti(L, LUA_REGISTRYINDEX, args_ref);
                    for (int i = 0; i < 8; i++) {
                        lua_rawgeti(L, -1, i);
                        if (lua_isinteger(L, -1)) {
                            uint64_t new_val = (uint64_t)lua_tointeger(L, -1);
                            if (new_val != saved_regs[i]) {
                                verbose_log("  Arg %d modified: 0x%llx -> 0x%llx", i,
                                    (unsigned long long)saved_regs[i], (unsigned long long)new_val);
                                saved_regs[i] = new_val;
                            }
                        }
                        lua_pop(L, 1);
                    }
                    lua_pop(L, 1);
                }

                luaL_unref(L, LUA_REGISTRYINDEX, args_ref);
            }
            pthread_mutex_unlock(&g_lua_mutex);
        }
    } else {
        verbose_log("  [DEBUG] Skipped: engine=%p, index=%d", g_lua_engine, g_current_hook_index);
    }

    g_hook_caller_fp = 0;
    g_hook_caller_lr = 0;
    // Note: don't reset g_hook_reentrant here — log_return_value still needs it
}

uint64_t log_return_value(uint64_t ret_val) {
    verbose_log("=== HOOK: Function Returned ===");
    verbose_log("  x0 (return): 0x%llx (%lld)", (unsigned long long)ret_val, (long long)ret_val);

    uintptr_t my_fp;
    __asm__ volatile("mov %0, x29" : "=r"(my_fp));
    uintptr_t handler_fp = *(uintptr_t*)my_fp;
    g_hook_caller_fp = *(uintptr_t*)handler_fp;
    g_hook_caller_lr = *(uintptr_t*)(handler_fp + 8);

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
                                    verbose_log("  Modified to jstring: \"%s\"", str_value);
                                }
                            } else if (strcmp(jni_type, "int") == 0 || strcmp(jni_type, "long") == 0) {
                                ret_val = (uint64_t)lua_tointeger(L, -1);
                                verbose_log("  Modified to %s: %lld", jni_type, (long long)ret_val);
                            } else if (strcmp(jni_type, "boolean") == 0) {
                                ret_val = lua_toboolean(L, -1) ? 1 : 0;
                                verbose_log("  Modified to boolean: %s", ret_val ? "true" : "false");
                            }
                            lua_pop(L, 1);
                        } else {
                            lua_pop(L, 1);
                        }
                    } else if (lua_isinteger(L, -1) || lua_isnumber(L, -1)) {
                        ret_val = (uint64_t)lua_tointeger(L, -1);
                        verbose_log("  Modified to: 0x%llx", (unsigned long long)ret_val);
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

    g_hook_caller_fp = 0;
    g_hook_caller_lr = 0;
    g_hook_reentrant = 0;  // Reset guard at the very end of hook processing
    return ret_val;
}

void* get_current_trampoline(void) {
    if (g_current_hook_index >= 0) {
        HookInfo* hook = &g_hooks[g_current_hook_index];

        if (hook->type == HOOK_TRAMPOLINE) {
            return hook->data.trampoline.trampoline_addr;
        } else if (hook->type == HOOK_PLT_GOT) {
            return (hook->data.plt_got.patched_count > 0)
                ? hook->data.plt_got.original_funcs[0]
                : NULL;
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
