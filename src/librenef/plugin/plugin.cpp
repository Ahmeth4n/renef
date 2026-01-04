#include <renef/plugin.h>
#include <renef/socket_helper.h>
#include <renef/server_connection.h>
#include <renef/cmd.h>
#include <iostream>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <vector>
#include <pwd.h>

class PluginCommandDispatcher : public CommandDispatcher {
    RENPlugin* plugin;
    std::string cmd_name;
    std::string cmd_desc;

public:
    PluginCommandDispatcher(RENPlugin* p) : plugin(p) {
        if (p->metadata) {
            cmd_name = p->metadata->command ? p->metadata->command : p->metadata->name;
            cmd_desc = p->metadata->description ? p->metadata->description : "Plugin command";
        }
    }

    std::string get_name() const override { return cmd_name; }
    std::string get_description() const override { return cmd_desc; }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t) override {
        if (!plugin || !plugin->exec) {
            return CommandResult(false, "Plugin has no exec function");
        }

        std::string cmd(cmd_buffer);
        std::string args;
        size_t space = cmd.find(' ');
        if (space != std::string::npos) {
            args = cmd.substr(space + 1);
        }

        renef_ctx ctx;
        ctx.client_fd = &client_fd;
        ctx.socket_helper = &CommandRegistry::instance().get_socket_helper();
        ctx.command_registry = &CommandRegistry::instance();
        ctx.target_pid = nullptr;

        int ret = plugin->exec(&ctx, args.empty() ? nullptr : const_cast<char*>(args.c_str()));
        return CommandResult(ret == 0, "");
    }
};

static std::vector<RENPlugin*> g_loaded_plugins;

static std::string expand_path(const char* path) {
    std::string result(path);
    if (!result.empty() && result[0] == '~') {
        const char* home = getenv("HOME");
        if (!home) {
            struct passwd* pw = getpwuid(getuid());
            if (pw) home = pw->pw_dir;
        }
        if (home) {
            result = std::string(home) + result.substr(1);
        }
    }
    return result;
}

const char* get_user_plugin_dir(){
    return RENEF_PLUGIN_DIR;
}
const char* get_user_plugin_ext(){
    return RENEF_PLUGIN_EXT;
}

RENPlugin* plugin_load(const char* path){
    RENPlugin* r_plugin = (struct RENPlugin*)malloc(sizeof(struct RENPlugin));
    if (!r_plugin) return nullptr;

    memset(r_plugin, 0, sizeof(struct RENPlugin));

    std::string full_path;

    if (path[0] == '/' || path[0] == '.') {
        full_path = path;
    } else {
        std::string plugin_dir = expand_path(get_user_plugin_dir());
        full_path = plugin_dir + "/" + path;

        std::string ext = get_user_plugin_ext();
        if (full_path.length() < ext.length() ||
            full_path.substr(full_path.length() - ext.length()) != ext) {
            full_path += ext;
        }
    }

    void* plg_file = dlopen(full_path.c_str(), RTLD_NOW);
    if (!plg_file) {
        std::cerr << "[plugin] Failed to load: " << full_path << "\n";
        std::cerr << "[plugin] Error: " << dlerror() << "\n";
        free(r_plugin);
        return nullptr;
    }

    r_plugin->handle = plg_file;
    r_plugin->metadata = (RENPluginMetadata*)dlsym(plg_file, "ren_plugin_info");
    r_plugin->init = (ren_plugin_init_fn)dlsym(plg_file, "ren_plugin_init");
    r_plugin->close = (ren_plugin_close_fn)dlsym(plg_file, "ren_plugin_close");
    r_plugin->exec = (ren_plugin_exec_fn)dlsym(plg_file, "ren_plugin_exec");
    r_plugin->loaded = true;

    g_loaded_plugins.push_back(r_plugin);

    return r_plugin;
}

void plugin_unload(RENPlugin* plugin){
    if (!plugin) return;

    if (plugin->handle) {
        dlclose(plugin->handle);
    }

    for (auto it = g_loaded_plugins.begin(); it != g_loaded_plugins.end(); ++it) {
        if (*it == plugin) {
            g_loaded_plugins.erase(it);
            break;
        }
    }

    free(plugin);
}

int plugin_list(RENPlugin** out, int max){
    int count = 0;
    for (size_t i = 0; i < g_loaded_plugins.size() && count < max; i++) {
        out[count++] = g_loaded_plugins[i];
    }
    return count;
}

int plugin_count(){
    return (int)g_loaded_plugins.size();
}

RENPlugin* plugin_find(const char* name){
    for (auto* plugin : g_loaded_plugins) {
        if (plugin && plugin->metadata) {
            if (plugin->metadata->command && strcmp(plugin->metadata->command, name) == 0) {
                return plugin;
            }
            if (plugin->metadata->name && strcmp(plugin->metadata->name, name) == 0) {
                return plugin;
            }
        }
    }
    return nullptr;
}

int plugin_autoload(renef_ctx_t ctx){
    int loaded = 0;
    std::string plugin_dir = expand_path(get_user_plugin_dir());
    std::string ext = get_user_plugin_ext();

    struct stat st;
    if (stat(plugin_dir.c_str(), &st) != 0) {
        return 0;
    }

    DIR* dir = opendir(plugin_dir.c_str());
    if (!dir) {
        return 0;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string filename = entry->d_name;

        if (filename == "." || filename == "..") continue;

        if (filename.length() < ext.length()) continue;
        if (filename.substr(filename.length() - ext.length()) != ext) continue;

        std::string full_path = plugin_dir + "/" + filename;


        RENPlugin* plugin = plugin_load(full_path.c_str());
        if (plugin) {
            if (plugin->init && ctx) {
                int ret = plugin->init(ctx);
                if (ret != 0) {
                    std::cerr << "[plugin] Init failed for: " << filename << "\n";
                    plugin_unload(plugin);
                    continue;
                }
            }

            if (plugin->metadata && plugin->metadata->name) {
                if (plugin->exec) {
                    const char* cmd = plugin->metadata->command ? plugin->metadata->command : plugin->metadata->name;
                    if (!CommandRegistry::instance().is_command_exist(cmd)) {
                        CommandRegistry::instance().register_command(
                            std::make_unique<PluginCommandDispatcher>(plugin)
                        );
                    }
                }
            }

            loaded++;
        }
    }

    closedir(dir);


    return loaded;
}

void ren_print(renef_ctx_t ctx, char* msg){
    write(*ctx->client_fd, msg, strlen(msg));
}

int ren_exec(const char* cmd){
    ServerConnection& conn = ServerConnection::instance();
    if (!conn.is_connected()) {
        if (!conn.connect()) {
            return -1;
        }
    }

    return conn.send(std::string(cmd) + "\n");
}

char* ren_recv(){
    ServerConnection& conn = ServerConnection::instance();
    std::string data = conn.receive(5000);

    if (data.empty()) {
        return nullptr;
    }

    char* result = strdup(data.c_str());
    return result;
}
