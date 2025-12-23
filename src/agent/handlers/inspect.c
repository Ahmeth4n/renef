#include <agent/handlers.h>
#include <agent/globals.h>
#include <agent/hook.h>
#include <agent/proc.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

void handle_inspect_binary(int client_fd, const char* args) {
    char lib_name[128];
    uint64_t offset;

    if (sscanf(args, "%127s 0x%llx", lib_name, (unsigned long long*)&offset) != 2 &&
        sscanf(args, "%127s %llu", lib_name, (unsigned long long*)&offset) != 2) {
        const char* error = "ERROR: Usage: inspect_binary <lib_name> <offset>\n";
        write(client_fd, error, strlen(error));
        return;
    }

    LOGI("inspect_binary: lib=%s offset=0x%llx", lib_name, (unsigned long long)offset);

    void* base_addr = find_library_base(lib_name);
    if (!base_addr) {
        const char* error = "ERROR: Library not found in process\n";
        write(client_fd, error, strlen(error));
        return;
    }

    void* target_func = (void*)((uintptr_t)base_addr + offset);
    LOGI("Target function: %p", target_func);

    if (g_hook_count >= MAX_HOOKS) {
        const char* error = "ERROR: Maximum hooks reached\n";
        write(client_fd, error, strlen(error));
        return;
    }

    HookInfo* hook_info = &g_hooks[g_hook_count];

    if (install_trampoline_hook(target_func, (void*)generic_hook_handler, hook_info) != 0) {
        const char* error = "ERROR: Failed to install hook\n";
        write(client_fd, error, strlen(error));
        return;
    }

    g_hook_count++;

    char response[256];
    snprintf(response, sizeof(response),
             "{\"success\":true,\"lib\":\"%s\",\"offset\":\"0x%llx\",\"addr\":\"%p\",\"hook_id\":%d}\n",
             lib_name, (unsigned long long)offset, target_func, g_hook_count - 1);
    write(client_fd, response, strlen(response));

    LOGI("Hook installed (total: %d)", g_hook_count);
}
