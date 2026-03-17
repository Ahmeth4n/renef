#include <agent/strace.h>
#include <agent/globals.h>
#include <agent/proc.h>
#include <agent/lua_thread.h>

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <lua.h>
#include <lauxlib.h>

static SyscallDef s_syscall_defs[] = {
    {"openat",    "openat",    "__openat",   4, {ARG_FD, ARG_STR, ARG_FLAGS_OPEN, ARG_MODE},      "file"},
    {"open",      "open",      "__open",     3, {ARG_STR, ARG_FLAGS_OPEN, ARG_MODE, 0, 0, 0},     "file"},
    {"close",     "close",     NULL,         1, {ARG_FD, 0, 0, 0, 0, 0},                          "file"},
    {"read",      "read",      NULL,         3, {ARG_FD, ARG_BUF, ARG_SIZE, 0, 0, 0},             "file"},
    {"write",     "write",     NULL,         3, {ARG_FD, ARG_BUF, ARG_SIZE, 0, 0, 0},             "file"},
    {"lseek",     "lseek",     "lseek64",    3, {ARG_FD, ARG_INT, ARG_INT, 0, 0, 0},              "file"},
    {"pread64",   "pread64",   NULL,         4, {ARG_FD, ARG_BUF, ARG_SIZE, ARG_INT},             "file"},
    {"pwrite64",  "pwrite64",  NULL,         4, {ARG_FD, ARG_BUF, ARG_SIZE, ARG_INT},             "file"},
    {"fstat",     "fstat",     "__fstat",    2, {ARG_FD, ARG_PTR, 0, 0, 0, 0},                    "file"},
    {"stat",      "stat",      "__stat",     2, {ARG_STR, ARG_PTR, 0, 0, 0, 0},                   "file"},
    {"access",    "access",    NULL,         2, {ARG_STR, ARG_INT, 0, 0, 0, 0},                   "file"},
    {"readlink",  "readlink",  NULL,         3, {ARG_STR, ARG_BUF, ARG_SIZE, 0, 0, 0},            "file"},
    {"rename",    "rename",    NULL,         2, {ARG_STR, ARG_STR, 0, 0, 0, 0},                   "file"},
    {"unlink",    "unlink",    NULL,         1, {ARG_STR, 0, 0, 0, 0, 0},                         "file"},
    {"mkdir",     "mkdir",     NULL,         2, {ARG_STR, ARG_MODE, 0, 0, 0, 0},                  "file"},
    {"chmod",     "chmod",     NULL,         2, {ARG_STR, ARG_MODE, 0, 0, 0, 0},                  "file"},

    {"socket",    "socket",    NULL,         3, {ARG_INT, ARG_INT, ARG_INT, 0, 0, 0},             "network"},
    {"connect",   "connect",   NULL,         3, {ARG_FD, ARG_PTR, ARG_UINT, 0, 0, 0},            "network"},
    {"bind",      "bind",      NULL,         3, {ARG_FD, ARG_PTR, ARG_UINT, 0, 0, 0},            "network"},
    {"listen",    "listen",    NULL,         2, {ARG_FD, ARG_INT, 0, 0, 0, 0},                    "network"},
    {"accept4",   "accept4",   NULL,         4, {ARG_FD, ARG_PTR, ARG_PTR, ARG_INT},              "network"},
    {"sendto",    "sendto",    NULL,         6, {ARG_FD, ARG_BUF, ARG_SIZE, ARG_INT, ARG_PTR, ARG_UINT}, "network"},
    {"recvfrom",  "recvfrom",  NULL,         6, {ARG_FD, ARG_BUF, ARG_SIZE, ARG_INT, ARG_PTR, ARG_PTR},  "network"},

    {"mmap",      "mmap",      "mmap64",     6, {ARG_PTR, ARG_SIZE, ARG_INT, ARG_INT, ARG_FD, ARG_INT},  "memory"},
    {"munmap",    "munmap",    NULL,         2, {ARG_PTR, ARG_SIZE, 0, 0, 0, 0},                  "memory"},
    {"mprotect",  "mprotect",  NULL,         3, {ARG_PTR, ARG_SIZE, ARG_INT, 0, 0, 0},            "memory"},

    {"fork",      "fork",      NULL,         0, {0, 0, 0, 0, 0, 0},                               "process"},
    {"execve",    "execve",    NULL,         3, {ARG_STR, ARG_PTR, ARG_PTR, 0, 0, 0},             "process"},
    {"kill",      "kill",      NULL,         2, {ARG_INT, ARG_INT, 0, 0, 0, 0},                   "process"},
    {"getpid",    "getpid",    NULL,         0, {0, 0, 0, 0, 0, 0},                               "process"},
    {"getuid",    "getuid",    NULL,         0, {0, 0, 0, 0, 0, 0},                               "process"},
    {"exit_group","exit_group",NULL,         1, {ARG_INT, 0, 0, 0, 0, 0},                         "process"},

    {"ioctl",     "ioctl",     NULL,         3, {ARG_FD, ARG_UINT, ARG_PTR, 0, 0, 0},             "ipc"},
    {"fcntl",     "fcntl",     NULL,         3, {ARG_FD, ARG_INT, ARG_INT, 0, 0, 0},              "ipc"},
    {"dup",       "dup",       NULL,         1, {ARG_FD, 0, 0, 0, 0, 0},                          "ipc"},
    {"dup2",      "dup2",      NULL,         2, {ARG_FD, ARG_FD, 0, 0, 0, 0},                     "ipc"},
    {"pipe",      "pipe",      NULL,         1, {ARG_PTR, 0, 0, 0, 0, 0},                         "ipc"},

    {NULL, NULL, NULL, 0, {0}, NULL}
};

StraceEntry g_strace_hooks[MAX_STRACE_HOOKS];
int g_strace_count = 0;

static __thread int g_strace_current_index = -1;
static __thread int g_strace_depth = 0;
static __thread char g_strace_enter_buf[1024];

static pthread_mutex_t g_strace_lua_mutex = PTHREAD_MUTEX_INITIALIZER;

extern int g_output_client_fd;

SyscallDef* strace_find_def(const char* name) {
    for (int i = 0; s_syscall_defs[i].name != NULL; i++) {
        if (strcmp(s_syscall_defs[i].name, name) == 0) {
            return &s_syscall_defs[i];
        }
    }
    return NULL;
}

int strace_get_defs_by_category(const char* category, SyscallDef** out, int max) {
    int count = 0;
    for (int i = 0; s_syscall_defs[i].name != NULL && count < max; i++) {
        if (strcmp(s_syscall_defs[i].category, category) == 0) {
            out[count++] = &s_syscall_defs[i];
        }
    }
    return count;
}

int strace_get_all_defs(SyscallDef** out, int max) {
    int count = 0;
    for (int i = 0; s_syscall_defs[i].name != NULL && count < max; i++) {
        out[count++] = &s_syscall_defs[i];
    }
    return count;
}

static void format_fd_path(int fd, char* buf, size_t bufsize) {
    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(link_path, buf, bufsize - 1);
    if (len > 0) {
        buf[len] = '\0';
    } else {
        buf[0] = '\0';
    }
}

static void format_safe_string(const char* str, char* buf, size_t bufsize, size_t maxlen) {
    if (!str) {
        snprintf(buf, bufsize, "NULL");
        return;
    }

    size_t i = 0;
    buf[0] = '"';
    size_t pos = 1;
    while (i < maxlen && pos < bufsize - 4) {
        char c = str[i];
        if (c == '\0') break;
        if (c >= 32 && c < 127) {
            buf[pos++] = c;
        } else {
            if (pos + 4 >= bufsize - 4) break;
            snprintf(buf + pos, bufsize - pos, "\\x%02x", (unsigned char)c);
            pos += 4;
        }
        i++;
    }
    if (str[i] != '\0') {
        if (pos + 3 < bufsize) {
            buf[pos++] = '.';
            buf[pos++] = '.';
            buf[pos++] = '.';
        }
    }
    if (pos < bufsize - 1) buf[pos++] = '"';
    buf[pos] = '\0';
}

static const char* format_open_flags(int flags) {
    static __thread char flag_buf[256];
    flag_buf[0] = '\0';

    if ((flags & 3) == 0) strcat(flag_buf, "O_RDONLY");
    else if ((flags & 3) == 1) strcat(flag_buf, "O_WRONLY");
    else if ((flags & 3) == 2) strcat(flag_buf, "O_RDWR");

    if (flags & 0x40)   { strcat(flag_buf, "|O_CREAT"); }
    if (flags & 0x80)   { strcat(flag_buf, "|O_EXCL"); }
    if (flags & 0x200)  { strcat(flag_buf, "|O_TRUNC"); }
    if (flags & 0x400)  { strcat(flag_buf, "|O_APPEND"); }
    if (flags & 0x800)  { strcat(flag_buf, "|O_NONBLOCK"); }
    if (flags & 0x80000) { strcat(flag_buf, "|O_CLOEXEC"); }

    return flag_buf;
}

static void format_arg(enum SyscallArgType type, uint64_t val, char* buf, size_t bufsize,
                        uint64_t* all_args) {
    (void)all_args;
    switch (type) {
        case ARG_INT:
            snprintf(buf, bufsize, "%d", (int)val);
            break;
        case ARG_UINT:
            snprintf(buf, bufsize, "%u", (unsigned)val);
            break;
        case ARG_FD: {
            char path[128];
            format_fd_path((int)val, path, sizeof(path));
            if (path[0]) {
                snprintf(buf, bufsize, "%d<%s>", (int)val, path);
            } else {
                if ((int)val == -100) {
                    snprintf(buf, bufsize, "AT_FDCWD");
                } else {
                    snprintf(buf, bufsize, "%d", (int)val);
                }
            }
            break;
        }
        case ARG_PTR:
            if (val == 0)
                snprintf(buf, bufsize, "NULL");
            else
                snprintf(buf, bufsize, "%p", (void*)val);
            break;
        case ARG_STR:
            format_safe_string((const char*)val, buf, bufsize, 64);
            break;
        case ARG_BUF:
            if (val == 0)
                snprintf(buf, bufsize, "NULL");
            else
                snprintf(buf, bufsize, "%p", (void*)val);
            break;
        case ARG_FLAGS_OPEN:
            snprintf(buf, bufsize, "%s", format_open_flags((int)val));
            break;
        case ARG_MODE:
            snprintf(buf, bufsize, "0%o", (unsigned)val);
            break;
        case ARG_SIZE:
            snprintf(buf, bufsize, "%zu", (size_t)val);
            break;
    }
}

static void strace_output(const char* msg) {
    if (g_output_client_fd >= 0 && msg) {
        size_t len = strlen(msg);
        write(g_output_client_fd, msg, len);
        write(g_output_client_fd, "\n", 1);
    }
}

void strace_set_current_index(int index) {
    g_strace_current_index = index;
}

void strace_on_enter(uint64_t* saved_regs) {
    if (g_strace_depth > 0) return;
    g_strace_depth++;

    g_hook_caller_fp = saved_regs[36];
    g_hook_caller_lr = saved_regs[37];

    int idx = g_strace_current_index;
    if (idx < 0 || idx >= g_strace_count) {
        g_strace_depth--;
        return;
    }

    StraceEntry* entry = &g_strace_hooks[idx];
    if (!entry->active || !entry->def) {
        g_strace_depth--;
        return;
    }

    pid_t tid = (pid_t)syscall(SYS_gettid);
    SyscallDef* def = entry->def;

    char output[1024];
    char args_str[768];
    args_str[0] = '\0';
    size_t args_pos = 0;

    for (int i = 0; i < def->nr_args && i < STRACE_MAX_ARGS; i++) {
        char arg_buf[192];
        format_arg(def->arg_types[i], saved_regs[i], arg_buf, sizeof(arg_buf), saved_regs);

        if (i > 0 && args_pos < sizeof(args_str) - 2) {
            args_str[args_pos++] = ',';
            args_str[args_pos++] = ' ';
        }
        size_t arg_len = strlen(arg_buf);
        if (args_pos + arg_len < sizeof(args_str) - 1) {
            memcpy(args_str + args_pos, arg_buf, arg_len);
            args_pos += arg_len;
        }
    }
    args_str[args_pos] = '\0';

    snprintf(output, sizeof(output), "[tid:%d] %s(%s)", tid, def->name, args_str);

    strncpy(g_strace_enter_buf, output, sizeof(g_strace_enter_buf) - 1);
    g_strace_enter_buf[sizeof(g_strace_enter_buf) - 1] = '\0';

    if (entry->lua_onCall_ref != LUA_NOREF && g_lua_engine) {
        pthread_mutex_lock(&g_strace_lua_mutex);
        lua_State* L = lua_engine_get_state(g_lua_engine);
        if (L) {
            lua_rawgeti(L, LUA_REGISTRYINDEX, entry->lua_onCall_ref);
            lua_newtable(L);

            lua_pushstring(L, def->name);
            lua_setfield(L, -2, "name");

            lua_pushinteger(L, tid);
            lua_setfield(L, -2, "tid");

            lua_pushstring(L, output);
            lua_setfield(L, -2, "formatted");

            lua_newtable(L);
            for (int i = 0; i < def->nr_args && i < STRACE_MAX_ARGS; i++) {
                lua_pushinteger(L, saved_regs[i]);
                lua_rawseti(L, -2, i + 1);
            }
            lua_setfield(L, -2, "args");

            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                LOGE("strace onCall callback failed: %s", lua_tostring(L, -1));
                lua_pop(L, 1);
            }
        }
        pthread_mutex_unlock(&g_strace_lua_mutex);
    }

    verbose_log("STRACE: %s", output);

    g_hook_caller_fp = 0;
    g_hook_caller_lr = 0;
    g_strace_depth--;
}

uint64_t strace_on_return(uint64_t ret_val) {
    if (g_strace_depth > 0) return ret_val;
    g_strace_depth++;

    uintptr_t my_fp;
    __asm__ volatile("mov %0, x29" : "=r"(my_fp));
    uintptr_t handler_fp = *(uintptr_t*)my_fp;
    g_hook_caller_fp = *(uintptr_t*)handler_fp;
    g_hook_caller_lr = *(uintptr_t*)(handler_fp + 8);

    int idx = g_strace_current_index;
    if (idx < 0 || idx >= g_strace_count) {
        g_strace_depth--;
        return ret_val;
    }

    StraceEntry* entry = &g_strace_hooks[idx];
    if (!entry->active || !entry->def) {
        g_strace_depth--;
        return ret_val;
    }

    pid_t tid = (pid_t)syscall(SYS_gettid);

    if (entry->lua_onReturn_ref != LUA_NOREF && g_lua_engine) {
        pthread_mutex_lock(&g_strace_lua_mutex);
        lua_State* L = lua_engine_get_state(g_lua_engine);
        if (L) {
            lua_rawgeti(L, LUA_REGISTRYINDEX, entry->lua_onReturn_ref);
            lua_newtable(L);

            lua_pushstring(L, entry->def->name);
            lua_setfield(L, -2, "name");
            lua_pushinteger(L, tid);
            lua_setfield(L, -2, "tid");
            lua_pushinteger(L, (lua_Integer)ret_val);
            lua_setfield(L, -2, "retval");

            if ((int64_t)ret_val < 0) {
                lua_pushstring(L, strerror(errno));
                lua_setfield(L, -2, "errno_str");
            }

            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                LOGE("strace onReturn callback failed: %s", lua_tostring(L, -1));
                lua_pop(L, 1);
            }
        }
        pthread_mutex_unlock(&g_strace_lua_mutex);
    }

    if (entry->lua_onCall_ref == LUA_NOREF) {
        char full_output[1200];
        if ((int64_t)ret_val < 0) {
            snprintf(full_output, sizeof(full_output), "%s = %d (%s)",
                     g_strace_enter_buf, (int)ret_val, strerror(errno));
        } else {
            snprintf(full_output, sizeof(full_output), "%s = %lld",
                     g_strace_enter_buf, (long long)ret_val);
        }
        strace_output(full_output);
    }

    verbose_log("STRACE: %s() = %lld", entry->def->name, (long long)ret_val);
    (void)tid;

    g_hook_caller_fp = 0;
    g_hook_caller_lr = 0;
    g_strace_depth--;
    return ret_val;
}

void* strace_get_original(void) {
    int idx = g_strace_current_index;
    if (idx >= 0 && idx < g_strace_count) {
        StraceEntry* entry = &g_strace_hooks[idx];
        if (entry->hook.type == HOOK_PLT_GOT && entry->hook.data.plt_got.patched_count > 0) {
            return entry->hook.data.plt_got.original_funcs[0];
        }
    }
    return NULL;
}

__attribute__((naked)) void strace_hook_handler(void) {
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
        "bl strace_set_current_index\n"

        "mov x0, sp\n"
        "bl strace_on_enter\n"

        "bl strace_get_original\n"
        "str x0, [sp, #264]\n"

        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"

        "ldr x16, [sp, #264]\n"
        "blr x16\n"

        "bl strace_on_return\n"

        "add sp, sp, #288\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n"
    );
}

static void* create_strace_thunk(int hook_index) {
    void* thunk = mmap(NULL, PAGE_SIZE,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (thunk == MAP_FAILED) {
        LOGE("strace: Failed to allocate thunk");
        return NULL;
    }

    uint32_t* code = (uint32_t*)thunk;

    code[0] = 0xD2800011 | ((hook_index & 0xFFFF) << 5);
    code[1] = 0x58000070;
    code[2] = 0xD61F0200;
    code[3] = 0xD503201F;

    *(uint64_t*)(&code[4]) = (uint64_t)strace_hook_handler;

    __builtin___clear_cache((char*)thunk, (char*)thunk + 32);

    LOGI("strace: Created thunk at %p for index %d", thunk, hook_index);
    return thunk;
}

int strace_install(const char* syscall_name, const char* caller_lib,
                   int onCall_ref, int onReturn_ref) {
    SyscallDef* def = strace_find_def(syscall_name);
    if (!def) {
        LOGE("strace: Unknown syscall: %s", syscall_name);
        return -1;
    }

    for (int i = 0; i < g_strace_count; i++) {
        if (g_strace_hooks[i].active && g_strace_hooks[i].def == def) {
            LOGI("strace: %s already traced", syscall_name);
            return i;
        }
    }

    if (g_strace_count >= MAX_STRACE_HOOKS) {
        LOGE("strace: Maximum hooks reached (%d)", MAX_STRACE_HOOKS);
        return -1;
    }

    void* addr = dlsym(RTLD_DEFAULT, def->symbol);
    if (!addr && def->alt_symbol) {
        addr = dlsym(RTLD_DEFAULT, def->alt_symbol);
        if (addr) {
            LOGI("strace: Resolved %s via alt_symbol %s", def->name, def->alt_symbol);
        }
    }
    if (!addr) {
        LOGE("strace: Cannot resolve symbol for %s", syscall_name);
        return -1;
    }

    LOGI("strace: Resolved %s at %p", def->name, addr);

    int idx = g_strace_count;
    StraceEntry* entry = &g_strace_hooks[idx];
    memset(entry, 0, sizeof(StraceEntry));

    entry->def = def;
    entry->resolved_addr = addr;
    entry->lua_onCall_ref = onCall_ref;
    entry->lua_onReturn_ref = onReturn_ref;

    void* thunk = create_strace_thunk(idx);
    if (!thunk) {
        LOGE("strace: Failed to create thunk for %s", syscall_name);
        return -1;
    }
    entry->thunk_addr = thunk;

    const char* effective_caller = (caller_lib && strlen(caller_lib) > 0) ? caller_lib : "*";

    int result = install_plt_got_hook(addr, thunk, &entry->hook, effective_caller);
    if (result != 0) {
        LOGE("strace: Failed to install PLT/GOT hook for %s", syscall_name);
        munmap(thunk, PAGE_SIZE);
        return -1;
    }

    entry->active = true;
    g_strace_count++;

    LOGI("strace: Installed trace for %s (index=%d, patched=%d GOT entries)",
         def->name, idx, entry->hook.data.plt_got.patched_count);

    return idx;
}

int strace_remove(const char* syscall_name) {
    for (int i = 0; i < g_strace_count; i++) {
        StraceEntry* entry = &g_strace_hooks[i];
        if (!entry->active || !entry->def) continue;
        if (strcmp(entry->def->name, syscall_name) != 0) continue;

        for (int j = 0; j < entry->hook.data.plt_got.patched_count; j++) {
            void** got_entry = entry->hook.data.plt_got.got_entries[j];
            if (!got_entry) continue;
            if (change_page_protection(got_entry, PROT_READ | PROT_WRITE) == 0) {
                *got_entry = entry->hook.data.plt_got.original_funcs[j];
                __builtin___clear_cache((char*)got_entry, (char*)got_entry + sizeof(void*));
            }
        }
        entry->hook.data.plt_got.patched_count = 0;

        if (entry->thunk_addr) {
            munmap(entry->thunk_addr, PAGE_SIZE);
            entry->thunk_addr = NULL;
        }

        if (g_lua_engine) {
            lua_State* L = lua_engine_get_state(g_lua_engine);
            if (L) {
                if (entry->lua_onCall_ref != LUA_NOREF)
                    luaL_unref(L, LUA_REGISTRYINDEX, entry->lua_onCall_ref);
                if (entry->lua_onReturn_ref != LUA_NOREF)
                    luaL_unref(L, LUA_REGISTRYINDEX, entry->lua_onReturn_ref);
            }
        }

        entry->active = false;
        entry->lua_onCall_ref = LUA_NOREF;
        entry->lua_onReturn_ref = LUA_NOREF;

        LOGI("strace: Removed trace for %s", syscall_name);
        return 0;
    }
    return -1;
}

void strace_remove_all(void) {
    int removed = 0;
    for (int i = 0; i < g_strace_count; i++) {
        if (g_strace_hooks[i].active && g_strace_hooks[i].def) {
            strace_remove(g_strace_hooks[i].def->name);
            removed++;
        }
    }
    g_strace_count = 0;
    LOGI("strace: Removed all traces (%d)", removed);
}
