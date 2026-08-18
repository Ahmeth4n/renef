#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <renef/string_utils.h>
#include <cstdio>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <cerrno>
#include <cstring>

class ListAppsCommand : public CommandDispatcher {
public:
    std::string get_name() const override {
        return "la";
    }

    std::string get_description() const override {
        return "List installed applications on your device";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        // List installed apps straight from the on-device package manager.
        // No target PID / injection required — this mirrors `frida-ps -Uai`:
        // it only needs renef_server running, not a spawned or attached app.
        std::string filter = extract_filter(cmd_buffer, cmd_size);  // "~pattern" or ""
        std::string pattern;
        if (filter.size() > 1 && filter[0] == '~') {
            pattern = filter.substr(1);
        }

        FILE* fp = popen("pm list packages 2>/dev/null", "r");
        if (!fp) {
            const char* error_msg = "ERROR: Failed to query package manager\n";
            write(client_fd, error_msg, strlen(error_msg));
            return CommandResult(false, "pm list packages failed");
        }

        char line[512];
        int count = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "package:", 8) != 0) {
                continue;
            }
            char* pkg = line + 8;
            size_t len = strlen(pkg);
            if (len > 0 && pkg[len - 1] == '\n') {
                pkg[--len] = '\0';
            }
            if (!pattern.empty() && strstr(pkg, pattern.c_str()) == nullptr) {
                continue;
            }
            write(client_fd, pkg, len);
            write(client_fd, "\n", 1);
            count++;
        }
        pclose(fp);

        char summary[64];
        int slen = snprintf(summary, sizeof(summary), "\nTotal: %d packages\n", count);
        write(client_fd, summary, slen);

        return CommandResult(true, "List apps successful");
    }
};

std::unique_ptr<CommandDispatcher> create_list_command() {
    return std::make_unique<ListAppsCommand>();
}
