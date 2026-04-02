#include <agent/lua_kcov.h>
#include <agent/kcov.h>
#include <agent/globals.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

extern int g_output_client_fd;

static void send_to_cli(const char* msg) {
    if (g_output_client_fd >= 0 && msg) {
        size_t len = strlen(msg);
        write(g_output_client_fd, msg, len);
        write(g_output_client_fd, "\n", 1);
    }
}

/*
 * Lua userdata: each KCov.open() call returns a KCovState.
 * Methods like :enable(), :disable(), :collect() etc. are called on it.
 *
 * Usage:
 *   local cov = KCov.open(65536)   -- 64K entry buffer (optional)
 *   cov:enable()                    -- start coverage
 *   ... make syscalls ...
 *   cov:disable()                   -- stop coverage
 *   local pcs = cov:collect()       -- {0xffffff..., 0xffffff..., ...}
 *   print("hit:", cov:count())
 *   cov:reset()                     -- reset buffer
 *   cov:close()                     -- cleanup
 */

#define KCOV_META "KCov.State"

/* get and validate kcov userdata from stack */
static KCovState* check_kcov(lua_State* L) {
    return (KCovState*)luaL_checkudata(L, 1, KCOV_META);
}

/*
 * KCov.open([buf_size]) -> userdata
 *
 * Open KCOV device and prepare shared buffer.
 * buf_size: how many PC addresses to hold (default: 256K)
 *           each entry is 8 bytes, so 256K = 2MB RAM
 *
 * Errors if kernel CONFIG_KCOV=y is not available.
 */
static int lua_kcov_open(lua_State* L) {
    size_t buf_size = 0;
    if (lua_gettop(L) >= 1) {
        buf_size = (size_t)luaL_checkinteger(L, 1);
    }

    /* create KCovState as userdata - Lua GC handles cleanup */
    KCovState* state = (KCovState*)lua_newuserdata(L, sizeof(KCovState));
    memset(state, 0, sizeof(KCovState));
    state->fd = -1;

    /* bind metatable for methods */
    luaL_getmetatable(L, KCOV_META);
    lua_setmetatable(L, -2);

    if (kcov_open(state, buf_size) != 0) {
        return luaL_error(L, "KCov.open failed (CONFIG_KCOV=y required)");
    }

    char msg[128];
    snprintf(msg, sizeof(msg), "KCov opened: %zu entries (%zu KB buffer)",
             state->buffer_size, (state->buffer_size * 8) / 1024);
    send_to_cli(msg);

    return 1; /* return userdata */
}

/*
 * cov:enable()
 *
 * Start kernel coverage recording for this thread.
 * IMPORTANT: only the thread that calls enable() is traced.
 * For coverage of different threads, each needs its own
 * KCov.open() + enable().
 */
static int lua_kcov_enable(lua_State* L) {
    KCovState* state = check_kcov(L);
    if (kcov_enable(state) != 0) {
        return luaL_error(L, "KCov enable failed");
    }
    return 0;
}

/*
 * cov:disable()
 *
 * Stop coverage recording. Data in the buffer is preserved,
 * you can read it with collect() at any time.
 */
static int lua_kcov_disable(lua_State* L) {
    KCovState* state = check_kcov(L);
    if (kcov_disable(state) != 0) {
        return luaL_error(L, "KCov disable failed");
    }
    return 0;
}

/*
 * cov:collect([max]) -> table
 *
 * Return kernel PC addresses from buffer as a Lua table.
 * max: maximum entries to read (default: 8192)
 *
 * Return: {0xffffffc0103a5e20, 0xffffffc0103a5e48, ...}
 *         each element is a kernel function address
 *
 * You can resolve these via /proc/kallsyms to get function names.
 */
static int lua_kcov_collect(lua_State* L) {
    KCovState* state = check_kcov(L);

    size_t max_count = 8192;
    if (lua_gettop(L) >= 2) {
        max_count = (size_t)luaL_checkinteger(L, 2);
    }

    /* temporary buffer on heap to avoid large stack allocation */
    uint64_t* pcs = (uint64_t*)malloc(max_count * sizeof(uint64_t));
    if (!pcs) {
        return luaL_error(L, "KCov collect: malloc failed");
    }

    size_t count = kcov_collect(state, pcs, max_count);

    /* convert to Lua table */
    lua_createtable(L, (int)count, 0);
    for (size_t i = 0; i < count; i++) {
        lua_pushinteger(L, (lua_Integer)pcs[i]);
        lua_rawseti(L, -2, (int)(i + 1));
    }

    free(pcs);
    return 1;
}

/*
 * cov:count() -> integer
 *
 * Return the number of entries in buffer (without copying).
 * Fast check: "how many kernel functions did this syscall hit?"
 */
static int lua_kcov_count(lua_State* L) {
    KCovState* state = check_kcov(L);
    lua_pushinteger(L, (lua_Integer)kcov_count(state));
    return 1;
}

/*
 * cov:reset()
 *
 * Reset the buffer. Call before starting a new measurement.
 * Use between enable/disable cycles:
 *   cov:reset()
 *   cov:enable()
 *   ... test ...
 *   cov:disable()
 *   local pcs = cov:collect()
 */
static int lua_kcov_reset(lua_State* L) {
    KCovState* state = check_kcov(L);
    kcov_reset(state);
    return 0;
}

/*
 * cov:close()
 *
 * Close KCOV, munmap buffer, close fd.
 * GC also calls this, but early closing is best practice.
 */
static int lua_kcov_close(lua_State* L) {
    KCovState* state = check_kcov(L);
    kcov_close(state);
    return 0;
}

/*
 * cov:edges() -> table
 *
 * Return unique edge hashes (for coverage-guided fuzzing).
 * Generates hashes from consecutive PC pairs: hash(pc[i] ^ pc[i+1])
 * AFL-style edge coverage - same function called from different paths
 * produces different edges.
 *
 * Return: {[edge_hash] = hit_count, ...}
 */
static int lua_kcov_edges(lua_State* L) {
    KCovState* state = check_kcov(L);

    size_t count = kcov_count(state);
    if (count < 2) {
        lua_newtable(L);
        return 1;
    }

    /* read up to 16K entries */
    size_t max = count < 16384 ? count : 16384;
    uint64_t* pcs = (uint64_t*)malloc(max * sizeof(uint64_t));
    if (!pcs) {
        lua_newtable(L);
        return 1;
    }

    size_t actual = kcov_collect(state, pcs, max);

    lua_newtable(L);

    /* generate edge hash from consecutive PC pairs */
    for (size_t i = 0; i + 1 < actual; i++) {
        /* simple XOR + shift hash - fast, good distribution */
        uint64_t edge = (pcs[i] >> 1) ^ pcs[i + 1];
        lua_Integer key = (lua_Integer)(edge & 0xFFFFF); /* 20-bit hash = 1M slots */

        lua_rawgeti(L, -1, (int)key);
        lua_Integer prev = lua_isinteger(L, -1) ? lua_tointeger(L, -1) : 0;
        lua_pop(L, 1);

        lua_pushinteger(L, prev + 1);
        lua_rawseti(L, -2, (int)key);
    }

    free(pcs);
    return 1;
}

/*
 * cov:diff(old_edges) -> integer
 *
 * Compare current edges with a previous edge set.
 * Returns the number of newly discovered edges.
 *
 * Usage in fuzzing loop:
 *   local baseline = cov:edges()
 *   ... mutated syscall ...
 *   local new_count = cov:diff(baseline)
 *   if new_count > 0 then add to corpus end
 */
static int lua_kcov_diff(lua_State* L) {
    KCovState* state = check_kcov(L);
    luaL_checktype(L, 2, LUA_TTABLE); /* old_edges table */

    size_t count = kcov_count(state);
    if (count < 2) {
        lua_pushinteger(L, 0);
        return 1;
    }

    size_t max = count < 16384 ? count : 16384;
    uint64_t* pcs = (uint64_t*)malloc(max * sizeof(uint64_t));
    if (!pcs) {
        lua_pushinteger(L, 0);
        return 1;
    }

    size_t actual = kcov_collect(state, pcs, max);
    int new_edges = 0;

    for (size_t i = 0; i + 1 < actual; i++) {
        uint64_t edge = (pcs[i] >> 1) ^ pcs[i + 1];
        lua_Integer key = (lua_Integer)(edge & 0xFFFFF);

        lua_rawgeti(L, 2, (int)key); /* old_edges[key] */
        if (lua_isnil(L, -1)) {
            new_edges++;
        }
        lua_pop(L, 1);
    }

    free(pcs);
    lua_pushinteger(L, new_edges);
    return 1;
}

/* GC: cleanup KCOV when userdata is collected */
static int lua_kcov_gc(lua_State* L) {
    KCovState* state = (KCovState*)luaL_checkudata(L, 1, KCOV_META);
    kcov_close(state);
    return 0;
}

/* method table */
static const luaL_Reg kcov_methods[] = {
    {"enable",  lua_kcov_enable},
    {"disable", lua_kcov_disable},
    {"collect", lua_kcov_collect},
    {"count",   lua_kcov_count},
    {"reset",   lua_kcov_reset},
    {"close",   lua_kcov_close},
    {"edges",   lua_kcov_edges},
    {"diff",    lua_kcov_diff},
    {NULL, NULL}
};

void register_kcov_api(lua_State* L) {
    /* create metatable for cov:method() calls */
    luaL_newmetatable(L, KCOV_META);

    /* __index = methods table */
    lua_newtable(L);
    luaL_setfuncs(L, kcov_methods, 0);
    lua_setfield(L, -2, "__index");

    /* __gc = automatic cleanup */
    lua_pushcfunction(L, lua_kcov_gc);
    lua_setfield(L, -2, "__gc");

    lua_pop(L, 1); /* pop metatable from stack */

    /* KCov global table */
    lua_newtable(L);
    lua_pushcfunction(L, lua_kcov_open);
    lua_setfield(L, -2, "open");
    lua_setglobal(L, "KCov");
}
