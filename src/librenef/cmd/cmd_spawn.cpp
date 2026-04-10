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
#include <chrono>
#include <signal.h>

#define RENEF_PAYLOAD_PATH "/data/local/tmp/libagent.so"

struct SpawnParams {
  std::string pkg_name;
  bool pause = false;
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
    // Legacy: strip --hook= argument if present (no longer used)
    size_t hook_end = args.find(' ', hook_pos);
    if (hook_end == std::string::npos) hook_end = args.length();
    std::string before_hook = args.substr(0, hook_pos);
    std::string after_hook = (hook_end < args.length()) ? args.substr(hook_end) : "";
    args = before_hook + after_hook;
  }

  auto remove_flag = [&args](const std::string& flag) {
    std::string space_flag = " " + flag;
    size_t pos;
    while ((pos = args.find(space_flag)) != std::string::npos) {
      size_t end = pos + space_flag.length();

      if (end >= args.length() || args[end] == ' ') {
        while (end < args.length() && args[end] == ' ') end++;
        args = args.substr(0, pos) + (end < args.length() ? " " + args.substr(end) : "");
      } else {
        break;
      }
    }
  };
  remove_flag("--verbose");
  remove_flag("-v");

  if (args.find("--pause") != std::string::npos) {
    params.pause = true;
    remove_flag("--pause");
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
    std::cerr << "  Raw command: '" << std::string(cmd_buffer, cmd_size) << "'"
              << std::endl;

    auto spawn_start = std::chrono::steady_clock::now();

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
    auto after_launch = std::chrono::steady_clock::now();
    std::cerr << "  [timing] launch: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(after_launch - spawn_start).count()
              << "ms" << std::endl;
    if (ret != 0) {
      const char *error_msg = "ERROR: Failed to launch app\n";
      write(client_fd, error_msg, strlen(error_msg));
      return CommandResult(false, "Failed to launch app");
    }

    char get_pid_cmd[512];
    snprintf(get_pid_cmd, sizeof(get_pid_cmd), "pidof -s %s",
             params.pkg_name.c_str());

    int pid = 0;
    const int max_retries = 100;
    const int retry_delay_us = 30000; // 30ms

    for (int i = 0; i < max_retries && pid <= 0; i++) {
      FILE *pipe = popen(get_pid_cmd, "r");
      if (pipe) {
        fscanf(pipe, "%d", &pid);
        pclose(pipe);
      }
      if (pid > 0) break;
      usleep(retry_delay_us);
    }

    if (pid <= 0) {
      const char *error_msg = "ERROR: Failed to get PID (timeout)\n";
      write(client_fd, error_msg, strlen(error_msg));
      return CommandResult(false, "Failed to get PID");
    }

    auto after_pid = std::chrono::steady_clock::now();
    std::cerr << "  [timing] pid found: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(after_pid - spawn_start).count()
              << "ms (pid=" << pid << ")" << std::endl;

    bool is_injected = inject(pid, RENEF_PAYLOAD_PATH);

    char response[64];
    if (is_injected) {

      // Close old agent connection BEFORE establishing new one
      // (set_current_pid closes SocketHelper if PID changed)
      CommandRegistry::instance().set_current_pid(pid);

      int con_pid = sock.ensure_connection(pid);
      std::string con_cmd = "con " + session_key + "\n";
      ssize_t con_payload =
          sock.send_data(con_cmd.c_str(), con_cmd.length(), false);

      sock.set_session_key(session_key);

      if (params.pause) {
        // Spawn gate: freeze process AFTER agent is connected.
        // The agent socket is open and buffered by kernel.
        // Next exec command will SIGCONT before polling for response,
        // so the agent reads buffered script data and installs hooks
        // before the main thread reaches onCreate.
        kill(pid, SIGSTOP);
        CommandRegistry::instance().gated_pid = pid;
        std::cerr << "  [spawn-gate] process frozen (pid=" << pid
                  << "), will resume on first exec" << std::endl;
      }

      snprintf(response, sizeof(response), "OK %d\n", pid);
    } else {
      snprintf(response, sizeof(response), "FAIL\n");
    }

    auto spawn_end = std::chrono::steady_clock::now();
    std::cerr << "  [timing] total: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(spawn_end - spawn_start).count()
              << "ms" << std::endl;

    write(client_fd, response, strlen(response));

    return CommandResult(is_injected, is_injected ? "Injection successful"
                                                  : "Injection failed");
  }
};

std::unique_ptr<CommandDispatcher> create_spawn_command() {
  return std::make_unique<SpawnCommand>();
}

