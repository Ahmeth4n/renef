#include <renef/cmd.h>
#include <renef/plugin.h>
#include <unistd.h>
#include <string.h>

class PluginsCommand : public CommandDispatcher{

    std::string get_name() const override {
        return "plugins";
    }

    std::string get_description() const override {
        return "List loaded plugins";
    }

    CommandResult dispatch(int client_fd, const char*, size_t) override {
        int count = plugin_count();
        if (count == 0) {
            const char* msg = "No plugins loaded.\n";
            write(client_fd, msg, strlen(msg));
        } else {
            RENPlugin* plugins[64];
            int n = plugin_list(plugins, 64);

            char header[64];
            snprintf(header, sizeof(header), "Loaded plugins (%d):\n", n);
            write(client_fd, header, strlen(header));

            for (int i = 0; i < n; i++) {
                char line[256];
                if (plugins[i]->metadata && plugins[i]->metadata->name) {
                    snprintf(line, sizeof(line), "  [%d] %s - %s\n",
                        i + 1,
                        plugins[i]->metadata->name,
                        plugins[i]->metadata->description ? plugins[i]->metadata->description : "");
                } else {
                    snprintf(line, sizeof(line), "  [%d] (unnamed plugin)\n", i + 1);
                }
                write(client_fd, line, strlen(line));
            }
        }
        return CommandResult(true, "");
    }
};

std::unique_ptr<CommandDispatcher> create_plugins_command() {
    return std::make_unique<PluginsCommand>();
}