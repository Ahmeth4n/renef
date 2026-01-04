// Test plugin for renef
// Build: gcc -shared -fPIC -o test_plugin.so test_plugin.c

#include <renef/plugin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Plugin metadata (required export)
RENPluginMetadata ren_plugin_info = {
    .name = "test_plugin",
    .author = "developer",
    .version = "1.0.0",
    .description = "Test plugin for renef",
    .command = "test",              // Command prefix: "test <args>"
    .type = PLUGIN_COMMAND
};

int ren_plugin_init(renef_ctx_t ctx) {
    (void)ctx;  // ctx may be NULL during autoload
    return 0;
}

int ren_plugin_exec(renef_ctx_t ctx, char* input) {
    if (!ctx) return -1;

    char msg[256];

    // Example: send ping command
    if (input && strcmp(input, "ping") == 0) {
        ren_exec("ping");
        char* response = ren_recv();
        if (response) {
            snprintf(msg, sizeof(msg), "%s", response);
            ren_print(ctx, msg);
            free(response);
        }
    }

    return 0;
}

void ren_plugin_close(renef_ctx_t ctx) {
    (void)ctx;
}
