#include <agent/handlers.h>
#include <agent/globals.h>

#include <string.h>
#include <unistd.h>

void handle_eval(int client_fd, const char* lua_code) {
    LOGI("Evaluating Lua: %s", lua_code);

    if (!g_lua_engine) {
        const char* error = "ERROR: Lua engine not initialized\n";
        write(client_fd, error, strlen(error));
        return;
    }

    bool success = lua_engine_load_script(g_lua_engine, lua_code);
    if (success) {
        const char* ok = "OK\n";
        write(client_fd, ok, strlen(ok));
    } else {
        const char* error = "ERROR: Lua execution failed\n";
        write(client_fd, error, strlen(error));
    }
}
