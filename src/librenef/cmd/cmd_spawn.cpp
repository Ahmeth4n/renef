#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <renef/cmd.h>
#include <renef/crypto.h>
#include <renef/socket_helper.h>
#include <renef/string_utils.h>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

#define HIDDEN_PAYLOAD_PATH "/data/local/tmp/libagent.so"
#define TEMP_PAYLOAD_PATH "/data/local/tmp/libagent.so"

struct SpawnParams {
  std::string pkg_name;
  std::string hook_type;
};

static SpawnParams parse_spawn_params(const char *cmd_buffer, size_t cmd_size) {
  SpawnParams params;
  std::string full_cmd(cmd_buffer, cmd_size);

  while (!full_cmd.empty() &&
         (full_cmd.back() == '\n' || full_cmd.back() == '\r' ||
          full_cmd.back() == ' ' || full_cmd.back() == '\0')) {
    full_cmd.pop_back();
  }

  size_t space_pos = full_cmd.find(' ');
  if (space_pos == std::string::npos) {
    return params;
  }

  std::string args = full_cmd.substr(space_pos + 1);

  size_t hook_pos = args.find("--hook=");
  if (hook_pos != std::string::npos) {
    size_t hook_start = hook_pos + 7;
    size_t hook_end = args.find(' ', hook_start);
    if (hook_end == std::string::npos) {
      hook_end = args.length();
    }
    params.hook_type = args.substr(hook_start, hook_end - hook_start);

    std::string before_hook = args.substr(0, hook_pos);
    std::string after_hook =
        (hook_end < args.length()) ? args.substr(hook_end) : "";
    args = before_hook + after_hook;
  }

  size_t start = args.find_first_not_of(" \t");
  size_t end = args.find_last_not_of(" \t");
  if (start != std::string::npos && end != std::string::npos) {
    params.pkg_name = args.substr(start, end - start + 1);
  }

  return params;
}

extern bool inject(int pid, const char *so_path);

class SpawnCommand : public CommandDispatcher {
public:
  std::string get_name() const override { return "spawn"; }

  std::string get_description() const override {
    return "Spawn a new process and inject the payload.";
  }

  CommandResult dispatch(int client_fd, const char *cmd_buffer,
                         size_t cmd_size) override {
    SpawnParams params = parse_spawn_params(cmd_buffer, cmd_size);

    std::cerr << "  Package name: '" << params.pkg_name << "'" << std::endl;
    std::cerr << "  Hook type: '" << params.hook_type << "'" << std::endl;
    std::cerr << "  Raw command: '" << std::string(cmd_buffer, cmd_size) << "'"
              << std::endl;

    std::string session_key = generate_auth_key();
    SocketHelper &sock = CommandRegistry::instance().get_socket_helper();

    if (params.pkg_name.empty()) {
      const char *error_msg = "ERROR: Invalid package name\n";
      write(client_fd, error_msg, strlen(error_msg));
      return CommandResult(false, "Invalid package name");
    }

    char kill_cmd[512];
    snprintf(kill_cmd, sizeof(kill_cmd),
             "pid=$(pidof %s); [ -n \"$pid\" ] && { kill -9 \"$pid\"; echo 1; "
             "} || echo 0",
             params.pkg_name.c_str());
    int kill_result = system(kill_cmd);
    (void)kill_result;

    char launch_cmd[512];
    snprintf(launch_cmd, sizeof(launch_cmd), "monkey -p %s 1",
             params.pkg_name.c_str());
    int ret = system(launch_cmd);
    if (ret != 0) {
      const char *error_msg = "ERROR: Failed to launch app\n";
      write(client_fd, error_msg, strlen(error_msg));
      return CommandResult(false, "Failed to launch app");
    }

    char get_pid_cmd[512];
    snprintf(get_pid_cmd, sizeof(get_pid_cmd), "pidof -s %s",
             params.pkg_name.c_str());

    int pid = 0;
    const int max_retries = 10;
    const int retry_delay_us = 500000;

    for (int i = 0; i < max_retries && pid <= 0; i++) {
      usleep(retry_delay_us);

      FILE *pipe = popen(get_pid_cmd, "r");
      if (pipe) {
        fscanf(pipe, "%d", &pid);
        pclose(pipe);
      }
    }

    if (pid <= 0) {
      const char *error_msg = "ERROR: Failed to get PID (timeout)\n";
      write(client_fd, error_msg, strlen(error_msg));
      return CommandResult(false, "Failed to get PID");
    }

    bool is_injected = inject(pid, HIDDEN_PAYLOAD_PATH);

    char response[64];
    if (is_injected) {
      // Clean up temp payload file
      unlink(TEMP_PAYLOAD_PATH);

      int con_pid = sock.ensure_connection(pid);
      std::string con_cmd = "con " + session_key + "\n";
      ssize_t con_payload =
          sock.send_data(con_cmd.c_str(), con_cmd.length(), false);

      sock.set_session_key(session_key);

      if (!params.hook_type.empty()) {
        std::string hook_cmd =
            "exec _G.__hook_type__ = \"" + params.hook_type + "\"\n";
        sock.send_data(hook_cmd.c_str(), hook_cmd.length(), false);
      }

      snprintf(response, sizeof(response), "OK %d\n", pid);
    } else {
      snprintf(response, sizeof(response), "FAIL\n");
    }
    write(client_fd, response, strlen(response));

    CommandRegistry::instance().set_current_pid(pid);

    return CommandResult(is_injected, is_injected ? "Injection successful"
                                                  : "Injection failed");
  }
};

std::unique_ptr<CommandDispatcher> create_spawn_command() {
  return std::make_unique<SpawnCommand>();
}
