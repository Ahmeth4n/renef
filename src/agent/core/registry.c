#include <agent/cmd_registry.h>
#include <agent/globals.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

struct cmd_entry {
    char name[CMD_MAX_NAME_LEN];
    size_t name_len;
    cmd_handler_t handler;
};

static struct cmd_entry g_commands[CMD_MAX_COMMANDS];
static int g_cmd_count = 0;

void cmd_register(const char* name, cmd_handler_t handler) {
    if (g_cmd_count >= CMD_MAX_COMMANDS) {
        LOGE("Command registry full");
        return;
    }

    strncpy(g_commands[g_cmd_count].name, name, CMD_MAX_NAME_LEN - 1);
    g_commands[g_cmd_count].name[CMD_MAX_NAME_LEN - 1] = '\0';
    g_commands[g_cmd_count].name_len = strlen(name);
    g_commands[g_cmd_count].handler = handler;
    g_cmd_count++;

    LOGI("Registered command: %s", name);
}

int cmd_dispatch(int fd, const char* cmd) {
    for (int i = 0; i < g_cmd_count; i++) {
        size_t len = g_commands[i].name_len;

        if (strncmp(cmd, g_commands[i].name, len) == 0) {
            const char* args = cmd + len;
            while (*args == ' ') args++;
            return g_commands[i].handler(fd, args);
        }
    }
    return 0;
}

void cmd_list(int fd) {
    char buf[4096];
    int offset = 0;

    offset += snprintf(buf + offset, sizeof(buf) - offset, "Available commands (%d):\n", g_cmd_count);

    for (int i = 0; i < g_cmd_count; i++) {
        offset += snprintf(buf + offset, sizeof(buf) - offset, "  %s\n", g_commands[i].name);
    }

    write(fd, buf, offset);
}
