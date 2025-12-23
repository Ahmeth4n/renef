#ifndef AGENT_HANDLERS_H
#define AGENT_HANDLERS_H

#include <stdint.h>
#include <stdbool.h>

typedef void (*cmd_handler_fn)(int client_fd, const char* args);

void handle_eval(int client_fd, const char* lua_code);
void handle_inspect_binary(int client_fd, const char* args);
void handle_memscan(int client_fd, const char* pattern);
void handle_list_apps(int client_fd, const char* args);
void handle_memdump(int client_fd, const char* args);

void register_builtin_commands(void);

#endif
