#include <renef/cmd.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <signal.h>

class ResumeCommand : public CommandDispatcher {
public:
  std::string get_name() const override { return "resume"; }

  std::string get_description() const override {
    return "Resume a spawn-gated process.";
  }

  CommandResult dispatch(int client_fd, const char *cmd_buffer,
                         size_t cmd_size) override {
    int gated = CommandRegistry::instance().gated_pid;

    if (gated <= 0) {
      const char *msg = "No gated process.\n";
      write(client_fd, msg, strlen(msg));
      return CommandResult(true, "No gated process");
    }

    kill(gated, SIGCONT);
    CommandRegistry::instance().gated_pid = -1;

    char msg[128];
    snprintf(msg, sizeof(msg), "Resumed pid %d\n", gated);
    write(client_fd, msg, strlen(msg));
    fprintf(stderr, "[spawn-gate] Manual resume (pid=%d)\n", gated);

    return CommandResult(true, "Resumed");
  }
};

std::unique_ptr<CommandDispatcher> create_resume_command() {
  return std::make_unique<ResumeCommand>();
}
