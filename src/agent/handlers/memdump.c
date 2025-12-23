#include <agent/handlers.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#include <android/log.h>

#define TAG "RENEF_MEMDUMP"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static sigjmp_buf jump_buffer;
static volatile sig_atomic_t fault_occurred = 0;

static void segfault_handler(int sig) {
    fault_occurred = 1;
    siglongjmp(jump_buffer, 1);
}

void handle_memdump(int client_fd, const char* args) {
    unsigned long address = 0;
    size_t size = 0;

    int parsed = sscanf(args, "%lx %zu", &address, &size);
    if (parsed != 2 || size == 0 || size > 4096) {
        const char* error = "ERROR: Invalid arguments. Usage: memdump <address> <size>\n";
        write(client_fd, error, strlen(error));
        return;
    }

    LOGI("Memory dump requested: addr=0x%lx, size=%zu", address, size);

    void* mem_ptr = (void*)address;

    char* buffer = (char*)malloc(size);
    if (!buffer) {
        const char* error = "ERROR: Memory allocation failed\n";
        write(client_fd, error, strlen(error));
        return;
    }

    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = segfault_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGSEGV, &sa, &old_sa);
    fault_occurred = 0;

    if (sigsetjmp(jump_buffer, 1) == 0) {
        memcpy(buffer, mem_ptr, size);
    } else {
        LOGI("Memory access fault at 0x%lx", address);
        sigaction(SIGSEGV, &old_sa, NULL);
        free(buffer);
        const char* error = "ERROR: Invalid memory address or access violation\n";
        write(client_fd, error, strlen(error));
        return;
    }

    sigaction(SIGSEGV, &old_sa, NULL);

    size_t total_sent = 0;
    while (total_sent < size) {
        ssize_t sent = write(client_fd, buffer + total_sent, size - total_sent);
        if (sent <= 0) {
            LOGI("Failed to send data to client: sent=%zd, total_sent=%zu", sent, total_sent);
            free(buffer);
            return;
        }
        total_sent += sent;
    }

    LOGI("Sent %zu bytes to client", total_sent);
    free(buffer);
}
