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
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <agent/globals.h>
#include <agent/cmd_registry.h>
#include <agent/hook.h>
#include <agent/proc.h>
#include <agent/handlers.h>
#include <sys/system_properties.h>

static JavaVM* g_jvm = NULL;

typedef jint (*JNI_GetCreatedJavaVMs_t)(JavaVM**, jsize, jsize*);

static int get_device_api_level(void) {
    static int cached_api = 0;
    if (cached_api > 0) return cached_api;

    char value[PROP_VALUE_MAX] = {0};
    if (__system_property_get("ro.build.version.sdk", value) > 0) {
        cached_api = atoi(value);
    } else {
        cached_api = 30;
    }
    return cached_api;
}

// ELF symbol lookup - find symbol in loaded library by parsing ELF
static void* elf_lookup_symbol(const char* lib_path, uintptr_t load_addr, const char* symbol_name) {
    int fd = open(lib_path, O_RDONLY);
    if (fd < 0) {
        LOGE("Cannot open %s: %s", lib_path, strerror(errno));
        return NULL;
    }

    // Get file size
    off_t file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    // Map the file
    void* map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (map == MAP_FAILED) {
        LOGE("mmap failed: %s", strerror(errno));
        return NULL;
    }

    void* result = NULL;
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)map;

    // Verify ELF magic
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        LOGE("Not a valid ELF file");
        goto cleanup;
    }

    // Find the first PT_LOAD segment to calculate proper load bias
    Elf64_Phdr* phdr = (Elf64_Phdr*)((uint8_t*)map + ehdr->e_phoff);
    uintptr_t first_load_vaddr = 0;
    int found_load = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            first_load_vaddr = phdr[i].p_vaddr;
            found_load = 1;
            LOGI("First PT_LOAD vaddr: 0x%lx", (unsigned long)first_load_vaddr);
            break;
        }
    }

    if (!found_load) {
        LOGE("No PT_LOAD segment found");
        goto cleanup;
    }

    // Calculate actual load bias
    uintptr_t load_bias = load_addr - first_load_vaddr;
    LOGI("Load bias: 0x%lx (load_addr: 0x%lx - vaddr: 0x%lx)",
         (unsigned long)load_bias, (unsigned long)load_addr, (unsigned long)first_load_vaddr);

    // Find section headers
    Elf64_Shdr* shdr = (Elf64_Shdr*)((uint8_t*)map + ehdr->e_shoff);
    Elf64_Shdr* shstrtab = &shdr[ehdr->e_shstrndx];
    const char* shstrtab_data = (const char*)map + shstrtab->sh_offset;

    // Find .dynsym and .dynstr sections
    Elf64_Shdr* dynsym_shdr = NULL;
    Elf64_Shdr* dynstr_shdr = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char* section_name = shstrtab_data + shdr[i].sh_name;
        if (strcmp(section_name, ".dynsym") == 0) {
            dynsym_shdr = &shdr[i];
        } else if (strcmp(section_name, ".dynstr") == 0) {
            dynstr_shdr = &shdr[i];
        }
    }

    if (!dynsym_shdr || !dynstr_shdr) {
        LOGE("Could not find .dynsym or .dynstr");
        goto cleanup;
    }

    Elf64_Sym* symtab = (Elf64_Sym*)((uint8_t*)map + dynsym_shdr->sh_offset);
    const char* strtab = (const char*)map + dynstr_shdr->sh_offset;
    size_t sym_count = dynsym_shdr->sh_size / sizeof(Elf64_Sym);

    // Search for the symbol
    for (size_t i = 0; i < sym_count; i++) {
        const char* name = strtab + symtab[i].st_name;
        if (strcmp(name, symbol_name) == 0 && symtab[i].st_value != 0) {
            result = (void*)(load_bias + symtab[i].st_value);
            LOGI("ELF lookup: Found %s at %p (bias: 0x%lx, st_value: 0x%lx)",
                 symbol_name, result, (unsigned long)load_bias, (unsigned long)symtab[i].st_value);
            break;
        }
    }

cleanup:
    munmap(map, file_size);
    return result;
}

// Try to find libart.so base from /proc/self/maps and resolve symbol
static JNI_GetCreatedJavaVMs_t find_jvm_func_from_maps(void) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return NULL;

    char line[512];
    uintptr_t libart_base = 0;
    char libart_path[256] = {0};

    // Find the FIRST (lowest address) mapping of libart.so - this is the true base
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libart.so")) {
            unsigned long start;
            char perms[5];
            char path[256] = {0};
            if (sscanf(line, "%lx-%*lx %4s %*x %*s %*d %255s", &start, perms, path) >= 2) {
                // Take the first (lowest) mapping as base
                if (libart_base == 0 || start < libart_base) {
                    libart_base = (uintptr_t)start;
                    if (path[0]) {
                        strncpy(libart_path, path, sizeof(libart_path) - 1);
                    }
                }
            }
        }
    }
    fclose(fp);

    if (!libart_base) {
        LOGI("libart.so not found in /proc/self/maps");
        return NULL;
    }

    LOGI("Found libart.so at 0x%lx: %s", libart_base, libart_path);

    // Method 1: Try dlopen with RTLD_NOLOAD first
    void* handle = dlopen("libart.so", RTLD_NOW | RTLD_NOLOAD);
    if (!handle && libart_path[0]) {
        handle = dlopen(libart_path, RTLD_NOW | RTLD_NOLOAD);
    }

    if (handle) {
        JNI_GetCreatedJavaVMs_t func = (JNI_GetCreatedJavaVMs_t)dlsym(handle, "JNI_GetCreatedJavaVMs");
        if (func) {
            LOGI("Found JNI_GetCreatedJavaVMs via RTLD_NOLOAD: %p", func);
            return func;
        }
    }

    // Method 2: ELF parsing - directly read symbol from file
    if (libart_path[0]) {
        JNI_GetCreatedJavaVMs_t func = (JNI_GetCreatedJavaVMs_t)elf_lookup_symbol(
            libart_path, libart_base, "JNI_GetCreatedJavaVMs");
        if (func) {
            return func;
        }
    }

    return NULL;
}

// Android 11-14 (API 30-34): Try multiple approaches
static JNI_GetCreatedJavaVMs_t get_jvm_func_api30(void) {
    JNI_GetCreatedJavaVMs_t func = NULL;

    // Method 1: RTLD_DEFAULT (might work in some cases)
    func = (JNI_GetCreatedJavaVMs_t)dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
    if (func) {
        LOGI("API 30-34: Found JNI_GetCreatedJavaVMs via RTLD_DEFAULT");
        return func;
    }

    // Method 2: Try RTLD_NOLOAD with libart.so
    void* handle = dlopen("libart.so", RTLD_NOW | RTLD_NOLOAD);
    if (handle) {
        func = (JNI_GetCreatedJavaVMs_t)dlsym(handle, "JNI_GetCreatedJavaVMs");
        if (func) {
            LOGI("API 30-34: Found JNI_GetCreatedJavaVMs via RTLD_NOLOAD libart.so");
            return func;
        }
    }

    // Method 3: Try APEX paths (Android 12+ moved ART to APEX)
    const char* apex_paths[] = {
        "/apex/com.android.art/lib64/libart.so",
        "/apex/com.android.art/lib/libart.so",
        "/apex/com.android.runtime/lib64/libart.so",
        "/apex/com.android.runtime/lib/libart.so",
        NULL
    };

    for (int i = 0; apex_paths[i]; i++) {
        handle = dlopen(apex_paths[i], RTLD_NOW | RTLD_NOLOAD);
        if (handle) {
            func = (JNI_GetCreatedJavaVMs_t)dlsym(handle, "JNI_GetCreatedJavaVMs");
            if (func) {
                LOGI("API 30-34: Found JNI_GetCreatedJavaVMs via %s", apex_paths[i]);
                return func;
            }
        }
    }

    // Method 4: Try libnativehelper.so
    handle = dlopen("libnativehelper.so", RTLD_NOW | RTLD_NOLOAD);
    if (handle) {
        func = (JNI_GetCreatedJavaVMs_t)dlsym(handle, "JNI_GetCreatedJavaVMs");
        if (func) {
            LOGI("API 30-34: Found JNI_GetCreatedJavaVMs via libnativehelper.so");
            return func;
        }
    }

    // Method 5: Parse /proc/self/maps to find libart.so
    func = find_jvm_func_from_maps();
    if (func) {
        return func;
    }

    LOGE("API 30-34: Could not find JNI_GetCreatedJavaVMs");
    return NULL;
}

// Android 15+ (API 35+): dlopen works
static JNI_GetCreatedJavaVMs_t get_jvm_func_api35(void) {
    void* handle = dlopen("libart.so", RTLD_NOW);
    if (!handle) {
        handle = dlopen("libnativehelper.so", RTLD_NOW);
    }
    if (handle) {
        JNI_GetCreatedJavaVMs_t func = (JNI_GetCreatedJavaVMs_t)dlsym(handle, "JNI_GetCreatedJavaVMs");
        if (func) {
            LOGI("API 35+: Found JNI_GetCreatedJavaVMs via dlopen");
        }
        return func;
    }
    return NULL;
}

// Android 10 and below (API <= 29): dlopen works
static JNI_GetCreatedJavaVMs_t get_jvm_func_legacy(void) {
    void* handle = dlopen("libart.so", RTLD_NOW);
    if (!handle) {
        handle = dlopen("libnativehelper.so", RTLD_NOW);
    }
    if (handle) {
        JNI_GetCreatedJavaVMs_t func = (JNI_GetCreatedJavaVMs_t)dlsym(handle, "JNI_GetCreatedJavaVMs");
        if (func) {
            LOGI("API <=29: Found JNI_GetCreatedJavaVMs via dlopen");
        }
        return func;
    }
    return NULL;
}

JNIEnv* get_jni_env(void) {
    if (!g_jvm) {
        int api = get_device_api_level();
        JNI_GetCreatedJavaVMs_t getVMs = NULL;

        if (api >= 35) {
            // Android 15+ (API 35+)
            getVMs = get_jvm_func_api35();
        } else if (api >= 30) {
            // Android 11-14 (API 30-34)
            getVMs = get_jvm_func_api30();
        } else {
            // Android 10 and below (API <= 29)
            getVMs = get_jvm_func_legacy();
        }

        if (getVMs) {
            JavaVM* vms[1];
            jsize count = 0;
            if (getVMs(vms, 1, &count) == JNI_OK && count > 0) {
                g_jvm = vms[0];
                g_java_vm = g_jvm;
                LOGI("Got JavaVM: %p (API %d)", g_jvm, api);
            }
        }

        if (!g_jvm) {
            LOGE("Failed to get JavaVM (API %d)", api);
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

    if (filter[0] != '\0') {
        size_t cmd_len_now = strlen(main_cmd);
        snprintf(main_cmd + cmd_len_now, sizeof(main_cmd) - cmd_len_now, "~%s", filter);
    }

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
