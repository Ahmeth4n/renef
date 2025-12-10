/**
 * RENEF Agent - Main entry point
 *
 * This file contains only:
 * - Constructor (init)
 * - Command handler thread
 * - Command router
 *
 * All functionality is split into modules:
 * - core/globals.c   - Global state
 * - hook/hook.c      - Hook system
 * - proc/proc.c      - Process utilities
 * - handlers/*.c     - Command handlers
 */

#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <signal.h>

#include "core/globals.h"
#include "core/cmd_registry.h"
#include "hook/hook.h"
#include "proc/proc.h"
#include "handlers/handlers.h"

static JavaVM* g_jvm = NULL;

typedef jint (*JNI_GetCreatedJavaVMs_t)(JavaVM**, jsize, jsize*);

static JNIEnv* get_jni_env(void) {
    if (!g_jvm) {
        void* handle = dlopen("libart.so", RTLD_NOW);
        if (!handle) {
            handle = dlopen("libnativehelper.so", RTLD_NOW);
        }

        if (handle) {
            JNI_GetCreatedJavaVMs_t getVMs = (JNI_GetCreatedJavaVMs_t)dlsym(handle, "JNI_GetCreatedJavaVMs");
            if (getVMs) {
                JavaVM* vms[1];
                jsize count = 0;
                if (getVMs(vms, 1, &count) == JNI_OK && count > 0) {
                    g_jvm = vms[0];
                    LOGI("Got JavaVM via JNI_GetCreatedJavaVMs: %p", g_jvm);
                }
            }
        }

        if (!g_jvm) {
            LOGE("Failed to get JavaVM");
            return NULL;
        }
    }

    JNIEnv* env = NULL;
    jint result = (*g_jvm)->GetEnv(g_jvm, (void**)&env, JNI_VERSION_1_6);

    if (result == JNI_EDETACHED) {
        result = (*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL);
        if (result != JNI_OK) {
            LOGE("Failed to attach thread to JVM: %d", result);
            return NULL;
        }
        LOGI("Thread attached to JVM");
    } else if (result != JNI_OK) {
        LOGE("GetEnv failed: %d", result);
        return NULL;
    }

    return env;
}

static char sock_path[256];
static bool is_agent_established = false;
static char session_key[33] = {0};

static void filter_and_send(int client_fd, const char* data, const char* filter) {
    if (!filter || !*filter) {
        write(client_fd, data, strlen(data));
        return;
    }

    char* data_copy = strdup(data);
    if (!data_copy) return;

    char* line = strtok(data_copy, "\n");
    while (line) {
        if (strstr(line, filter)) {
            write(client_fd, line, strlen(line));
            write(client_fd, "\n", 1);
        }
        line = strtok(NULL, "\n");
    }

    free(data_copy);
}

static char* g_capture_buffer = NULL;
static size_t g_capture_size = 0;
static size_t g_capture_used = 0;
static int g_capture_fd = -1;

static void capture_init(void) {
    g_capture_size = 65536;
    g_capture_buffer = (char*)malloc(g_capture_size);
    g_capture_used = 0;
    if (g_capture_buffer) g_capture_buffer[0] = '\0';
}

static void capture_write(const char* data, size_t len) {
    if (!g_capture_buffer) return;

    while (g_capture_used + len + 1 > g_capture_size) {
        g_capture_size *= 2;
        char* new_buf = (char*)realloc(g_capture_buffer, g_capture_size);
        if (!new_buf) return;
        g_capture_buffer = new_buf;
    }

    memcpy(g_capture_buffer + g_capture_used, data, len);
    g_capture_used += len;
    g_capture_buffer[g_capture_used] = '\0';
}

static void capture_free(void) {
    free(g_capture_buffer);
    g_capture_buffer = NULL;
    g_capture_size = 0;
    g_capture_used = 0;
}

static void route_command(int client_fd, const char* cmd, size_t cmd_len) {
    LOGI("Command: %s", cmd);

    static char main_cmd[65536];
    char filter[256] = {0};

    const char* is_eval_cmd = strstr(cmd, " eval ");
    const char* tilde = NULL;

    if (!is_eval_cmd) {
        tilde = strchr(cmd, '~');
    }

    if (tilde) {
        size_t len = tilde - cmd;
        if (len >= sizeof(main_cmd)) len = sizeof(main_cmd) - 1;
        strncpy(main_cmd, cmd, len);
        main_cmd[len] = '\0';

        strncpy(filter, tilde + 1, sizeof(filter) - 1);
        filter[sizeof(filter) - 1] = '\0';
        LOGI("Filter enabled: '%s'", filter);
    } else {
        strncpy(main_cmd, cmd, sizeof(main_cmd) - 1);
        main_cmd[sizeof(main_cmd) - 1] = '\0';
    }

    int use_capture = (filter[0] != '\0');

    if (use_capture) {
        capture_init();
    }

    if(!is_agent_established){
        if(strncmp(main_cmd,"con ", 4) == 0){
            strncpy(session_key, main_cmd + 4, 32);
            session_key[32] = '\0';
            is_agent_established = true;
            LOGI("Session established");
            return;
        }
        return;
    }

    if(cmd_len < 33 || strncmp(main_cmd, session_key, 32) != 0 || main_cmd[32] != ' '){
        return;
    }

    const char* actual_cmd = main_cmd + 33;
    memmove(main_cmd, actual_cmd, strlen(actual_cmd) + 1);

    if (!cmd_dispatch(client_fd, main_cmd)) {
        const char* error = "{\"success\":false,\"error\":\"Unknown command\"}\n";
        write(client_fd, error, strlen(error));
    }

    if (use_capture && g_capture_buffer) {
        filter_and_send(client_fd, g_capture_buffer, filter);
        capture_free();
    }
}

static void* command_handler(void* arg) {
    LOGI("Starting command handler...");

    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        LOGE("Socket creation failed");
        return NULL;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    addr.sun_path[0] = '\0';
    snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 2, "renef_pl_%d", getpid());

    socklen_t addr_len = sizeof(addr.sun_family) + strlen(addr.sun_path + 1) + 1;

    if (bind(server_fd, (struct sockaddr*)&addr, addr_len) < 0) {
        LOGE("Bind failed: %s", strerror(errno));
        close(server_fd);
        return NULL;
    }

    if (listen(server_fd, 5) < 0) {
        LOGE("Listen failed");
        close(server_fd);
        return NULL;
    }

    LOGI("Listening on: @renef_pl_%d", getpid());

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) continue;

        LOGI("Client connected (fd=%d)", client_fd);
        g_output_client_fd = client_fd;

        while (1) {
            size_t buf_size = 65536;
            size_t buf_used = 0;
            char* cmd = (char*)malloc(buf_size);
            if (!cmd) {
                LOGE("malloc failed");
                break;
            }

            int complete = 0;
            while (!complete) {
                if (buf_used >= buf_size - 1) {
                    buf_size *= 2;
                    if (buf_size > 2 * 1024 * 1024) {
                        LOGE("Command too large");
                        break;
                    }
                    char* new_buf = (char*)realloc(cmd, buf_size);
                    if (!new_buf) {
                        LOGE("realloc failed");
                        break;
                    }
                    cmd = new_buf;
                }

                ssize_t n = read(client_fd, cmd + buf_used, buf_size - buf_used - 1);

                if (n <= 0) {
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        usleep(10000);
                        continue;
                    }
                    LOGI("Client disconnected");
                    free(cmd);
                    cmd = NULL;
                    break;
                }

                buf_used += n;
                cmd[buf_used] = '\0';

                if (buf_used > 0 && cmd[buf_used - 1] == '\n') {
                    complete = 1;
                }
            }

            if (!cmd) break;

            while (buf_used > 0 && (cmd[buf_used-1] == '\n' || cmd[buf_used-1] == '\r' || cmd[buf_used-1] == ' ')) {
                cmd[--buf_used] = '\0';
            }

            if (buf_used == 0) {
                free(cmd);
                continue;
            }

            LOGI("Received command (%zu bytes)", buf_used);

            g_current_jni_env = get_jni_env();
            if (g_current_jni_env) {
                LOGI("JNIEnv available: %p", g_current_jni_env);
            }

            if (strcmp(cmd, "exit") == 0) {
                LOGI("Exit requested");
                free(cmd);
                break;
            }

            route_command(client_fd, cmd, buf_used);
            free(cmd);
        }

        g_output_client_fd = -1;
        close(client_fd);
        LOGI("Connection closed");
    }

    close(server_fd);
    return NULL;
}

__attribute__((constructor))
void init(void) {
    signal(SIGPIPE, SIG_IGN);

    LOGI("========================================");
    LOGI("RENEF Agent Loaded");
    LOGI("========================================");
    LOGI("PID: %d", getpid());
    LOGI("UID: %d", getuid());
    LOGI("========================================");

    register_builtin_commands();
    LOGI("Builtin commands registered");

    g_lua_engine = lua_engine_create();
    if (g_lua_engine) {
        LOGI("Lua engine initialized");
        lua_engine_load_script(g_lua_engine, "console.log('RENEF ready')");
    } else {
        LOGE("Lua engine initialization failed");
    }

    snprintf(sock_path, sizeof(sock_path), "@renef_pl_%d", getpid());

    pthread_t thread;
    if (pthread_create(&thread, NULL, command_handler, NULL) == 0) {
        pthread_detach(thread);
        LOGI("Command handler started: %s", sock_path);
    } else {
        LOGE("Thread creation failed");
    }
}
