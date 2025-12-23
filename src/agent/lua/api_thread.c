#include <agent/lua_thread.h>
#include <agent/lua_engine.h>
#include <agent/globals.h>

#include <dlfcn.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

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

static inline uintptr_t get_frame_pointer(void) {
    uintptr_t fp;
    __asm__ volatile ("mov %0, x29" : "=r"(fp));
    return fp;
}

static int is_valid_frame(uintptr_t fp) {
    if (fp == 0 || (fp & 0xF) != 0) {
        return 0;
    }

    if (fp < 0x7000000000ULL || fp > 0x8000000000ULL) {
        return 0;
    }

    return 1;
}

static int lua_thread_backtrace(lua_State* L) {
    uintptr_t frames[MAX_FRAMES];
    size_t frame_count = 0;

    uintptr_t fp = get_frame_pointer();

    while (frame_count < MAX_FRAMES && is_valid_frame(fp)) {
        stack_frame_t* frame = (stack_frame_t*)fp;

        uintptr_t pc = frame->lr;
        if (pc == 0) {
            break;
        }

        frames[frame_count++] = pc;

        uintptr_t next_fp = frame->fp;

        if (next_fp <= fp) {
            break;
        }

        fp = next_fp;
    }

    lua_newtable(L);

    for (size_t i = 0; i < frame_count; i++) {
        lua_newtable(L);

        lua_pushstring(L, "index");
        lua_pushinteger(L, (lua_Integer)(i + 1));
        lua_settable(L, -3);

        lua_pushstring(L, "pc");
        lua_pushinteger(L, (lua_Integer)frames[i]);
        lua_settable(L, -3);

        Dl_info info;
        if (dladdr((void*)frames[i], &info)) {
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
                lua_pushinteger(L, (lua_Integer)(frames[i] - (uintptr_t)info.dli_fbase));
                lua_settable(L, -3);
            }
        }

        lua_rawseti(L, -2, i + 1);
    }

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
