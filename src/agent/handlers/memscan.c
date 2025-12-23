#include <agent/handlers.h>
#include <agent/globals.h>
#include <agent/lua_memory.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static size_t hex_to_bytes(const char* hex, unsigned char* out, size_t max_len) {
    size_t hex_len = strlen(hex);
    size_t byte_len = hex_len / 2;

    if (byte_len > max_len) {
        byte_len = max_len;
    }

    for (size_t i = 0; i < byte_len; i++) {
        sscanf(hex + (i * 2), "%2hhx", &out[i]);
    }

    return byte_len;
}

static void json_escape(const char* src, char* dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dst_size - 2; i++) {
        char c = src[i];
        if (c == '"' || c == '\\') {
            dst[j++] = '\\';
        }
        if (j < dst_size - 1) {
            dst[j++] = c;
        }
    }
    dst[j] = '\0';
}

void handle_memscan(int client_fd, const char* pattern) {
    LOGI("Memory scan for pattern: %s", pattern);

    unsigned char pattern_bytes[256];
    size_t pattern_len = hex_to_bytes(pattern, pattern_bytes, sizeof(pattern_bytes));

    if (pattern_len == 0) {
        const char* error = "{\"success\":false,\"error\":\"Invalid pattern\"}\n";
        write(client_fd, error, strlen(error));
        return;
    }

    LOGI("Pattern bytes: %zu", pattern_len);

    MemorySearchResult result = memory_search(pattern_bytes, pattern_len);

    size_t buf_size = result.count * 1024 + 256;
    char* response = (char*)malloc(buf_size);
    if (!response) {
        const char* error = "{\"success\":false,\"error\":\"Out of memory\"}\n";
        write(client_fd, error, strlen(error));
        free_search_result(&result);
        return;
    }

    int offset = snprintf(response, buf_size, "{\"success\":true,\"count\":%d,\"results\":[", result.count);

    for (int i = 0; i < result.count; i++) {
        char lib_escaped[512];
        char hex_escaped[1024];
        char ascii_escaped[256];

        json_escape(result.items[i].library_name ? result.items[i].library_name : "", lib_escaped, sizeof(lib_escaped));
        json_escape(result.items[i].hex_result ? result.items[i].hex_result : "", hex_escaped, sizeof(hex_escaped));
        json_escape(result.items[i].ascii_result ? result.items[i].ascii_result : "", ascii_escaped, sizeof(ascii_escaped));

        offset += snprintf(response + offset, buf_size - offset,
            "%s{\"library\":\"%s\",\"offset\":%lu,\"address\":%lu,\"hex\":\"%s\",\"ascii\":\"%s\"}",
            (i > 0) ? "," : "",
            lib_escaped,
            (unsigned long)result.items[i].found_offset_addr,
            (unsigned long)result.items[i].absolute_addr,
            hex_escaped,
            ascii_escaped);
    }

    snprintf(response + offset, buf_size - offset, "]}\n");

    write(client_fd, response, strlen(response));

    free(response);
    free_search_result(&result);

    LOGI("Memory scan complete: %d results", result.count);
}
