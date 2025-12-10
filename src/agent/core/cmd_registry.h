#ifndef CMD_REGISTRY_H
#define CMD_REGISTRY_H

#include <stddef.h>

#define CMD_MAX_COMMANDS 128
#define CMD_MAX_NAME_LEN 64

typedef int (*cmd_handler_t)(int fd, const char* args);

void cmd_register(const char* name, cmd_handler_t handler);
int cmd_dispatch(int fd, const char* cmd);
void cmd_list(int fd);

#endif
