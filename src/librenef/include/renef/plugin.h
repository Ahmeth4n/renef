#pragma once

#include <stddef.h>
#include <stdbool.h>

#ifdef __APPLE__
    #define RENEF_PLUGIN_DIR "~/.config/renef/plugins"
    #define RENEF_PLUGIN_EXT ".dylib"
#elif __linux__
    #define RENEF_PLUGIN_DIR "~/.config/renef/plugins"
    #define RENEF_PLUGIN_EXT ".so"
#elif _WIN32
    #define RENEF_PLUGIN_DIR "%APPDATA%\\renef\\plugins"
    #define RENEF_PLUGIN_EXT ".dll"
#endif

#ifdef __APPLE__
    #define RENEF_SYSTEM_PLUGIN_DIR "/usr/local/lib/renef/plugins"
#elif __linux__
    #define RENEF_SYSTEM_PLUGIN_DIR "/usr/lib/renef/plugins"
#endif

/* Plugin type enum */
typedef enum {
    PLUGIN_LUA,
    PLUGIN_NATIVE,
    PLUGIN_COMMAND
} PluginType;

/* Plugin context - opaque for C plugins, defined in C++ */
#ifdef __cplusplus
    class CommandRegistry;
    class SocketHelper;

    struct renef_ctx {
        CommandRegistry* command_registry;
        SocketHelper* socket_helper;
        int* client_fd;
        int* target_pid;
    };
#else
    /* Opaque struct for C plugins */
    struct renef_ctx;
#endif

typedef struct renef_ctx* renef_ctx_t;

#ifdef __cplusplus
extern "C" {
#endif

    typedef int (*ren_plugin_init_fn)(renef_ctx_t ctx);
    typedef void (*ren_plugin_close_fn)(renef_ctx_t ctx);
    typedef int (*ren_plugin_exec_fn)(renef_ctx_t ctx, char* input);

    typedef struct RENPluginMetadata {
        const char* name;
        const char* author;
        const char* version;
        const char* description;
        const char* command;      /* Command prefix (e.g. "test" -> "test <args>") */
        PluginType type;
    } RENPluginMetadata;

    typedef struct RENPlugin {
        RENPluginMetadata* metadata;
        void* handle;
        bool loaded;
        ren_plugin_init_fn init;
        ren_plugin_close_fn close;
        ren_plugin_exec_fn exec;
    } RENPlugin;


    /* Plugin management functions */
    RENPlugin* plugin_load(const char* path);
    void plugin_unload(RENPlugin* plugin);
    int plugin_list(RENPlugin** out, int max);
    int plugin_autoload(renef_ctx_t ctx);
    int plugin_count();
    RENPlugin* plugin_find(const char* name);

    /* Public interface for plugin developers */
    void  ren_print(renef_ctx_t ctx, char* msg);
    int   ren_exec(const char* cmd);
    char* ren_recv();


#ifdef __cplusplus
}
#endif
