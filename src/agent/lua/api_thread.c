#include <agent/lua_thread.h>
#include <agent/lua_engine.h>
#include <agent/globals.h>

#include <dlfcn.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

__thread uintptr_t g_hook_caller_fp = 0;
__thread uintptr_t g_hook_caller_lr = 0;

static inline pid_t get_thread_id(void) {
#ifdef SYS_gettid
    return (pid_t)syscall(SYS_gettid);
#else
    return getpid();
#endif
}

#define MAX_FRAMES 64

typedef struct {
    uintptr_t fp;
    uintptr_t lr;
} stack_frame_t;

static uintptr_t s_pac_mask = 0;

static void init_pac_mask(void) {
    uintptr_t self = (uintptr_t)&init_pac_mask;
    int highest_bit = 0;
    for (int i = 63; i >= 0; i--) {
        if (self & (1ULL << i)) {
            highest_bit = i;
            break;
        }
    }
    int va_bits;
    if (highest_bit < 39) va_bits = 39;
    else if (highest_bit < 48) va_bits = 48;
    else va_bits = 52;
    s_pac_mask = (1ULL << va_bits) - 1;
    LOGI("PAC strip mask: 0x%lx (VA bits: %d, self: 0x%lx)",
         (unsigned long)s_pac_mask, va_bits, (unsigned long)self);
}

static inline uintptr_t strip_pac(uintptr_t ptr) {
    if (__builtin_expect(s_pac_mask == 0, 0)) init_pac_mask();
    return ptr & s_pac_mask;
}

static inline uintptr_t get_frame_pointer(void) {
    uintptr_t fp;
    __asm__ volatile ("mov %0, x29" : "=r"(fp));
    return fp;
}

static int is_valid_frame(uintptr_t fp) {
    if (fp == 0 || (fp & 0xF) != 0) {
        return 0;
    }
    if (fp < 0x1000ULL) {
        return 0;
    }
    if (fp >= 0xFFFF000000000000ULL) {
        return 0;
    }
    return 1;
}

static int is_valid_pc(uintptr_t pc) {
    if (pc == 0 || pc < 0x1000ULL) {
        return 0;
    }
    return 1;
}

static void push_frame_table(lua_State* L, int index, uintptr_t raw_pc) {
    uintptr_t pc = strip_pac(raw_pc);

    lua_newtable(L);

    lua_pushstring(L, "index");
    lua_pushinteger(L, (lua_Integer)(index + 1));
    lua_settable(L, -3);

    lua_pushstring(L, "pc");
    lua_pushinteger(L, (lua_Integer)pc);
    lua_settable(L, -3);

    Dl_info info;
    if (dladdr((void*)pc, &info)) {
        if (info.dli_sname) {
            lua_pushstring(L, "symbol");
            lua_pushstring(L, info.dli_sname);
            lua_settable(L, -3);
        }

        if (info.dli_fname) {
            lua_pushstring(L, "module");
            const char* filename = strrchr(info.dli_fname, '/');
            lua_pushstring(L, filename ? filename + 1 : info.dli_fname);
            lua_settable(L, -3);

            lua_pushstring(L, "path");
            lua_pushstring(L, info.dli_fname);
            lua_settable(L, -3);
        }

        if (info.dli_fbase) {
            lua_pushstring(L, "base");
            lua_pushinteger(L, (lua_Integer)info.dli_fbase);
            lua_settable(L, -3);

            lua_pushstring(L, "offset");
            lua_pushinteger(L, (lua_Integer)(pc - (uintptr_t)info.dli_fbase));
            lua_settable(L, -3);
        }
    }
}

static int lua_backtrace_tostring(lua_State* L) {
    luaL_Buffer buf;
    luaL_buffinit(L, &buf);

    int len = (int)lua_rawlen(L, 1);
    for (int i = 1; i <= len; i++) {
        lua_rawgeti(L, 1, i);

        lua_getfield(L, -1, "index");
        int index = (int)lua_tointeger(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, -1, "module");
        const char* module = lua_tostring(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, -1, "symbol");
        const char* symbol = lua_tostring(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, -1, "offset");
        lua_Integer offset = lua_tointeger(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, -1, "pc");
        lua_Integer pc = lua_tointeger(L, -1);
        lua_pop(L, 1);

        char line[256];
        const char* mod = module ? module : "???";
        if (symbol) {
            snprintf(line, sizeof(line), "  #%02d  %s  %s", index, mod, symbol);
        } else if (module) {
            snprintf(line, sizeof(line), "  #%02d  %s  +0x%lx", index, mod, (unsigned long)offset);
        } else {
            snprintf(line, sizeof(line), "  #%02d  0x%lx", index, (unsigned long)pc);
        }

        luaL_addstring(&buf, line);
        if (i < len) luaL_addchar(&buf, '\n');

        lua_pop(L, 1);
    }

    luaL_pushresult(&buf);
    return 1;
}

static int lua_thread_backtrace(lua_State* L) {
    uintptr_t frames[MAX_FRAMES];
    size_t frame_count = 0;

    uintptr_t start_fp;
    uintptr_t first_lr = 0;

    if (g_hook_caller_fp != 0) {
        start_fp = g_hook_caller_fp;
        first_lr = g_hook_caller_lr;
    } else if (lua_gettop(L) >= 1 && lua_isinteger(L, 1)) {
        start_fp = (uintptr_t)lua_tointeger(L, 1);
    } else {
        start_fp = get_frame_pointer();
    }

    if (first_lr != 0 && is_valid_pc(first_lr)) {
        frames[frame_count++] = first_lr;
    }

    uintptr_t fp = start_fp;
    while (frame_count < MAX_FRAMES && is_valid_frame(fp)) {
        stack_frame_t* frame = (stack_frame_t*)fp;

        uintptr_t pc = frame->lr;
        if (!is_valid_pc(pc)) break;

        frames[frame_count++] = pc;

        uintptr_t next_fp = strip_pac(frame->fp);
        if (next_fp <= fp) break;

        fp = next_fp;
    }

    lua_newtable(L);
    for (size_t i = 0; i < frame_count; i++) {
        push_frame_table(L, i, frames[i]);
        lua_rawseti(L, -2, i + 1);
    }

    lua_newtable(L);
    lua_pushcfunction(L, lua_backtrace_tostring);
    lua_setfield(L, -2, "__tostring");
    lua_setmetatable(L, -2);

    return 1;
}

static int lua_thread_id(lua_State* L) {
    lua_pushinteger(L, (lua_Integer)get_thread_id());
    return 1;
}

void lua_register_thread(lua_State* L) {
    lua_newtable(L);

    lua_pushcfunction(L, lua_thread_backtrace);
    lua_setfield(L, -2, "backtrace");

    lua_pushcfunction(L, lua_thread_id);
    lua_setfield(L, -2, "id");

    lua_setglobal(L, "Thread");

    LOGI("Thread API registered");
}
