#include <agent/cmd_registry.h>
#include <agent/globals.h>
#include <agent/hook.h>
#include <agent/proc.h>
#include <agent/handlers.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int cmd_ping(int fd, const char* args) {
    (void)args;
    const char* pong = "pong\n";
    write(fd, pong, strlen(pong));
    return 1;
}

static int cmd_list_apps(int fd, const char* args) {
    const char* filter = NULL;
    if (args && args[0] == '~' && args[1] != '\0') {
        filter = args + 1;
    }

    FILE *fp = popen("pm list packages", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "package:", 8) == 0) {
                char* pkg_name = line + 8;
                size_t len = strlen(pkg_name);
                if (len > 0 && pkg_name[len - 1] == '\n') {
                    pkg_name[len - 1] = '\0';
                    len--;
                }
                if (filter == NULL || strstr(pkg_name, filter) != NULL) {
                    write(fd, pkg_name, len);
                    write(fd, "\n", 1);
                }
            }
        }
        pclose(fp);
    }
    return 1;
}

static int cmd_hooks(int fd, const char* args) {
    (void)args;
    char response[1024];
    int len = snprintf(response, sizeof(response), "Active hooks: %d\n", g_hook_count);
    for (int i = 0; i < g_hook_count; i++) {
        if (g_hooks[i].data.trampoline.target_addr != NULL) {
            len += snprintf(response + len, sizeof(response) - len,
                "  [%d] target=%p\n", i, g_hooks[i].data.trampoline.target_addr);
        } else {
            len += snprintf(response + len, sizeof(response) - len,
                "  [%d] (removed)\n", i);
        }
    }
    write(fd, response, len);
    return 1;
}

static int cmd_unhook(int fd, const char* args) {
    if (!args || !*args || strcmp(args, "all") == 0) {
        int count = uninstall_all_hooks();
        char response[128];
        snprintf(response, sizeof(response), "Removed %d hook(s)\n", count);
        write(fd, response, strlen(response));
    } else {
        int hook_id = atoi(args);
        if (uninstall_hook(hook_id) == 0) {
            char response[128];
            snprintf(response, sizeof(response), "Hook %d removed\n", hook_id);
            write(fd, response, strlen(response));
        } else {
            const char* error = "ERROR: Failed to remove hook\n";
            write(fd, error, strlen(error));
        }
    }
    return 1;
}

static int cmd_hook(int fd, const char* args) {
    handle_inspect_binary(fd, args);
    return 1;
}

static int cmd_eval(int fd, const char* args) {
    handle_eval(fd, args);
    return 1;
}

static int cmd_memscan(int fd, const char* args) {
    handle_memscan(fd, args);
    return 1;
}

static int cmd_memdump(int fd, const char* args) {
    handle_memdump(fd, args);
    return 1;
}

static int cmd_sec(int fd, const char* args) {
    char* lib_path = find_library_path(args);
    if (lib_path) {
        dump_elf_sections(fd, lib_path);
        free(lib_path);
    } else {
        char err[256];
        snprintf(err, sizeof(err), "ERROR: Library '%s' not found in process\n", args);
        write(fd, err, strlen(err));
    }
    return 1;
}

static int cmd_help(int fd, const char* args) {
    (void)args;
    cmd_list(fd);
    return 1;
}

void register_builtin_commands(void) {
    cmd_register("ping", cmd_ping);
    cmd_register("la", cmd_list_apps); 
    cmd_register("hooks", cmd_hooks);
    cmd_register("unhook", cmd_unhook);
    cmd_register("hookn", cmd_hook);
    cmd_register("exec", cmd_eval);
    cmd_register("ms", cmd_memscan);
    cmd_register("md", cmd_memdump);
    cmd_register("sec", cmd_sec);
    cmd_register("help", cmd_help);
}
