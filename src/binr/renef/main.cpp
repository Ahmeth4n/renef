#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <map>
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <asio.hpp>
#include <renef/cmd.h>
#include <renef/colors.h>
#include <renef/server_connection.h>
#include <renef/crypto.h>
#include <renef/string_utils.h>
#include "transport/uds.h"
#include "transport/tcp.h"
#ifndef RENEF_NO_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <atomic>
#include "tui/memscan_tui.h"
#include <renef/plugin.h>
#ifdef RENEF_HAS_TUI
#include "tui/tui_app.h"
#endif

static std::vector<std::pair<std::string, std::string>> global_commands;
static std::string g_device_id;
static bool g_device_ready = false;
static bool g_local_mode = false;
static bool g_gadget_mode = false;
static int g_gadget_pid = 0;
static std::string g_gadget_key;
static std::unique_ptr<ITransport> g_gadget_transport;
static bool g_verbose_mode = false;
#define DEFAULT_TCP_PORT 1907
#define DEFAULT_UDS_PATH "@com.android.internal.os.RuntimeInit"

static std::map<std::string, std::vector<std::pair<std::string, std::string>>> lua_api = {
    {"Module", {
        {"list()", "List all loaded modules"},
        {"find(\"", "Find module base address"},
        {"exports(\"", "Get exported functions"}
    }},
    {"Memory", {
        {"scan(\"", "Scan memory for pattern"},
        {"patch(", "Patch memory at address"}
    }},
    {"JNI", {
        {"string(", "Wrap as JNI string"},
        {"int(", "Wrap as JNI int"},
        {"long(", "Wrap as JNI long"},
        {"boolean(", "Wrap as JNI boolean"}
    }},
    {"console", {
        {"log(\"", "Print to console"}
    }},
    {"Syscall", {
        {"trace(\"", "Trace specific syscalls"},
        {"traceAll()", "Trace all syscalls"},
        {"untrace(\"", "Stop tracing specific syscall"},
        {"stop()", "Stop all tracing"},
        {"list()", "List available syscalls"},
        {"active()", "Show active traces"}
    }},
    {"", {
        {"Module.", "Module operations (list, find, exports)"},
        {"Memory.", "Memory operations (scan, patch)"},
        {"hook(", "Install hook on function"},
        {"console.", "Console output"},
        {"JNI.", "JNI type wrappers"},
        {"Syscall.", "Syscall tracing (trace, stop, list)"}
    }}
};

static bool g_lua_context = false;

#ifdef RENEF_NO_READLINE
// Line editor with history and escape sequence handling for builds without readline
static std::vector<std::string> simple_history;

static void simple_add_history(const char* line) {
    if (line && line[0] != '\0') {
        simple_history.push_back(line);
    }
}

static char* simple_readline(const char* prompt) {
    std::cout << prompt;
    std::cout.flush();

    struct termios oldt, newt;
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
        // Fallback: if terminal control unavailable, use basic getline
        std::string line;
        if (!std::getline(std::cin, line)) return nullptr;
        char* r = (char*)malloc(line.size() + 1);
        if (r) strcpy(r, line.c_str());
        return r;
    }

    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    newt.c_cc[VMIN] = 1;
    newt.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::string line;
    size_t cursor = 0;
    int hist_idx = (int)simple_history.size();
    std::string saved_line;

    auto redraw = [&]() {
        // Move cursor to start of line, clear it, reprint
        std::cout << "\r" << prompt << line;
        // Clear any leftover characters after line
        std::cout << "\x1b[K";
        // Move cursor to correct position
        size_t total_prompt_len = strlen(prompt) + line.size();
        size_t target = strlen(prompt) + cursor;
        if (target < total_prompt_len) {
            std::cout << "\x1b[" << (total_prompt_len - target) << "D";
        }
        std::cout.flush();
    };

    while (true) {
        char ch;
        ssize_t n = read(STDIN_FILENO, &ch, 1);
        if (n <= 0) {
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            return nullptr;
        }

        if (ch == '\n' || ch == '\r') {
            std::cout << "\n";
            break;
        } else if (ch == 4) { // Ctrl+D
            if (line.empty()) {
                std::cout << "\n";
                tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
                return nullptr;
            }
        } else if (ch == 127 || ch == 8) { // Backspace
            if (cursor > 0) {
                line.erase(cursor - 1, 1);
                cursor--;
                redraw();
            }
        } else if (ch == 3) { // Ctrl+C
            line.clear();
            cursor = 0;
            std::cout << "^C\n" << prompt;
            std::cout.flush();
        } else if (ch == 1) { // Ctrl+A - Home
            cursor = 0;
            redraw();
        } else if (ch == 5) { // Ctrl+E - End
            cursor = line.size();
            redraw();
        } else if (ch == 21) { // Ctrl+U - clear line
            line.clear();
            cursor = 0;
            redraw();
        } else if (ch == 11) { // Ctrl+K - kill to end of line
            line.erase(cursor);
            redraw();
        } else if (ch == 12) { // Ctrl+L - clear screen
            std::cout << "\x1b[2J\x1b[H";
            redraw();
        } else if (ch == '\x1b') { // Escape sequence
            char seq[3];
            ssize_t r1 = read(STDIN_FILENO, &seq[0], 1);
            if (r1 <= 0) continue;

            if (seq[0] == '[') {
                ssize_t r2 = read(STDIN_FILENO, &seq[1], 1);
                if (r2 <= 0) continue;

                switch (seq[1]) {
                    case 'A': // Up arrow - previous history
                        if (hist_idx > 0) {
                            if (hist_idx == (int)simple_history.size())
                                saved_line = line;
                            hist_idx--;
                            line = simple_history[hist_idx];
                            cursor = line.size();
                            redraw();
                        }
                        break;
                    case 'B': // Down arrow - next history
                        if (hist_idx < (int)simple_history.size()) {
                            hist_idx++;
                            if (hist_idx == (int)simple_history.size())
                                line = saved_line;
                            else
                                line = simple_history[hist_idx];
                            cursor = line.size();
                            redraw();
                        }
                        break;
                    case 'C': // Right arrow
                        if (cursor < line.size()) {
                            cursor++;
                            redraw();
                        }
                        break;
                    case 'D': // Left arrow
                        if (cursor > 0) {
                            cursor--;
                            redraw();
                        }
                        break;
                    case 'H': // Home
                        cursor = 0;
                        redraw();
                        break;
                    case 'F': // End
                        cursor = line.size();
                        redraw();
                        break;
                    case '3': { // Delete key (ESC[3~)
                        char tilde;
                        read(STDIN_FILENO, &tilde, 1);
                        if (tilde == '~' && cursor < line.size()) {
                            line.erase(cursor, 1);
                            redraw();
                        }
                        break;
                    }
                    default:
                        // Consume unknown sequences silently
                        if (seq[1] >= '0' && seq[1] <= '9') {
                            char tmp;
                            read(STDIN_FILENO, &tmp, 1); // consume ~
                        }
                        break;
                }
            } else if (seq[0] == 'O') {
                // Application mode arrow keys (ESC O A/B/C/D)
                ssize_t r2 = read(STDIN_FILENO, &seq[1], 1);
                if (r2 <= 0) continue;
                switch (seq[1]) {
                    case 'A': // Up
                        if (hist_idx > 0) {
                            if (hist_idx == (int)simple_history.size())
                                saved_line = line;
                            hist_idx--;
                            line = simple_history[hist_idx];
                            cursor = line.size();
                            redraw();
                        }
                        break;
                    case 'B': // Down
                        if (hist_idx < (int)simple_history.size()) {
                            hist_idx++;
                            if (hist_idx == (int)simple_history.size())
                                line = saved_line;
                            else
                                line = simple_history[hist_idx];
                            cursor = line.size();
                            redraw();
                        }
                        break;
                    case 'C': // Right
                        if (cursor < line.size()) { cursor++; redraw(); }
                        break;
                    case 'D': // Left
                        if (cursor > 0) { cursor--; redraw(); }
                        break;
                    case 'H': // Home
                        cursor = 0; redraw();
                        break;
                    case 'F': // End
                        cursor = line.size(); redraw();
                        break;
                    default:
                        break;
                }
            }
            // Other ESC sequences silently ignored
        } else if (ch == '\t') {
            // Tab: ignore (no completion in simple mode)
        } else if (ch >= 32) { // Printable character
            line.insert(cursor, 1, ch);
            cursor++;
            redraw();
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    char* result = (char*)malloc(line.size() + 1);
    if (result) strcpy(result, line.c_str());
    return result;
}

#define readline simple_readline
#define add_history simple_add_history
#define rl_bind_key(k, f) ((void)0)
#define rl_variable_bind(k, v) ((void)0)
#endif

#ifndef RENEF_NO_READLINE
char* lua_api_generator(const char* text, int state) {
    static size_t list_index;
    static std::string prefix;
    static std::vector<std::pair<std::string, std::string>>* completions;

    if (!state) {
        list_index = 0;
        std::string input(text);

        completions = nullptr;
        for (auto& [key, values] : lua_api) {
            if (!key.empty() && input.rfind(key + ".", 0) == 0) {
                prefix = key + ".";
                completions = &values;
                break;
            }
        }

        if (!completions && !input.empty()) {
            for (auto& [key, values] : lua_api) {
                if (!key.empty() && key.rfind(input, 0) == 0) {
                    prefix = "";
                    completions = &lua_api[""];
                    break;
                }
            }
        }

        if (!completions && g_lua_context && input.empty()) {
            prefix = "";
            completions = &lua_api[""];
        }
    }

    if (!completions) return NULL;

    while (list_index < completions->size()) {
        const auto& [name, desc] = (*completions)[list_index++];
        std::string full_name = prefix + name;
        if (full_name.rfind(text, 0) == 0) {
            return strdup(full_name.c_str());
        }
    }

    return NULL;
}

char* command_generator(const char* text, int state) {
    static size_t list_index, len;
    static std::vector<std::string> local_commands = {"help", "color", "clear", "msi", "q"};

    if (!state) {
        list_index = 0;
        len = strlen(text);
    }

    while (list_index < global_commands.size()) {
        const auto& [name, desc] = global_commands[list_index++];
        if (strncmp(name.c_str(), text, len) == 0) {
            return strdup(name.c_str());
        }
    }

    size_t local_index = list_index - global_commands.size();
    while (local_index < local_commands.size()) {
        const std::string& name = local_commands[local_index];
        list_index++;
        local_index++;
        if (strncmp(name.c_str(), text, len) == 0) {
            return strdup(name.c_str());
        }
    }

    return NULL;
}
#endif // RENEF_NO_READLINE

static std::map<std::string, std::string> local_command_descs = {
    {"msi", "Interactive memory scan with TUI (msi <hex_pattern>)"},
    {"help", "Show available commands"},
    {"color", "Set theme colors (color list, color prompt=RED)"},
    {"clear", "Clear the screen"},
    {"q", "Exit"}
};

#ifndef RENEF_NO_READLINE
extern "C" void display_matches(char** matches, int num_matches, int max_length) {
    if (!matches || num_matches <= 0) {
        return;
    }

    printf("\n");

    for (int i = 1; i <= num_matches; i++) {
        if (!matches[i]) continue;

        std::string desc = "";
        std::string match_str = matches[i];

        for (const auto& [name, d] : global_commands) {
            if (name == match_str) {
                desc = d;
                break;
            }
        }

        if (desc.empty()) {
            auto it = local_command_descs.find(match_str);
            if (it != local_command_descs.end()) {
                desc = it->second;
            }
        }

        if (desc.empty()) {
            for (const auto& [prefix, completions] : lua_api) {
                for (const auto& [name, d] : completions) {
                    std::string full_name = prefix.empty() ? name : (prefix + "." + name);
                    if (full_name == match_str || (prefix + name) == match_str) {
                        desc = d;
                        break;
                    }
                }
                if (!desc.empty()) break;
            }
        }

        if (!desc.empty()) {
            printf("  %-25s - %s\n", matches[i], desc.c_str());
        } else {
            printf("  %s\n", matches[i]);
        }
    }
    printf("\n");

    rl_forced_update_display();
}

int custom_tab_handler(int count, int key) {
    int start = rl_point;
    int end = rl_point;

    std::string full_line(rl_line_buffer, rl_end);
    g_lua_context = (full_line.rfind("exec ", 0) == 0);

    while (start > 0 && rl_line_buffer[start - 1] != ' ') {
        start--;
    }

    while (end < rl_end && rl_line_buffer[end] != ' ') {
        end++;
    }

    int len = rl_point - start;
    char text[256];
    strncpy(text, rl_line_buffer + start, len);
    text[len] = '\0';

    char** matches;
    if (g_lua_context) {
        matches = rl_completion_matches(text, lua_api_generator);
    } else {
        matches = rl_completion_matches(text, command_generator);
    }

    if (matches) {
        int num_matches = 0;
        while (matches[num_matches]) num_matches++;

        if (num_matches >= 1) {
            int actual_matches = (num_matches == 1) ? 1 : num_matches - 1;
            display_matches(matches, actual_matches, 0);
        }

        for (int i = 0; matches[i]; i++) {
            free(matches[i]);
        }
        free(matches);
    }

    return 0;
}

char** command_completion(const char* text, int start, int end) {
    rl_attempted_completion_over = 1;
    return rl_completion_matches(text, command_generator);
}
#endif // RENEF_NO_READLINE

void show_help() {
    printf("\nAvailable commands:\n");
    printf("─────────────────────────────────────────────────\n");

    for (const auto& [name, desc] : global_commands) {
        printf("  %-15s - %s\n", name.c_str(), desc.c_str());
    }

    printf("  %-15s - %s\n", "msi", "Interactive memory scan (msi <hex_pattern>)");
    printf("  %-15s - %s\n", "color", "Set theme colors (color list, color prompt=RED)");
    printf("  %-15s - %s\n", "help", "Show this help");
    printf("  %-15s - %s\n", "q", "Exit");
    printf("─────────────────────────────────────────────────\n\n");
}

bool handle_color_command(const std::string& args) {
    ColorManager& cm = ColorManager::instance();

    if (args.empty() || args == "list") {
        std::cout << "Current theme:\n" << cm.list_theme();
        std::cout << "\nAvailable colors: " << cm.list_colors() << "\n";
        std::cout << "\nUsage: color <theme>=<COLOR>\n";
        std::cout << "Themes: prompt, response\n";
        return true;
    }

    size_t eq_pos = args.find('=');
    if (eq_pos == std::string::npos) {
        std::cerr << "ERROR: Invalid format. Use: color <theme>=<COLOR>\n";
        return true;
    }

    std::string theme = args.substr(0, eq_pos);
    std::string color_name = args.substr(eq_pos + 1);

    std::transform(color_name.begin(), color_name.end(), color_name.begin(), ::toupper);

    if (cm.set_theme_color(theme, color_name)) {
        std::cout << "Set " << theme << " to " << cm.get(color_name) << color_name << RESET << "\n";
    } else {
        std::cerr << "ERROR: Invalid theme or color name.\n";
        std::cerr << "Themes: prompt, response\n";
        std::cerr << "Colors: " << cm.list_colors() << "\n";
    }
    return true;
}


bool check_adb_devices(std::string& device_id) {
    FILE* pipe = popen("adb devices", "r");
    if (!pipe) {
        std::cerr << "ERROR: Failed to execute 'adb devices'\n";
        return false;
    }

    char buffer[256];
    std::vector<std::string> devices;

    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            std::string line(buffer);
            size_t start = line.find_first_not_of(" \t\n\r");
            size_t end = line.find_last_not_of(" \t\n\r");
            if (start != std::string::npos && end != std::string::npos) {
                line = line.substr(start, end - start + 1);
            }

            if (!line.empty() && line.find("device") != std::string::npos) {
                size_t tab_pos = line.find('\t');
                if (tab_pos == std::string::npos) {
                    tab_pos = line.find(' ');
                }
                if (tab_pos != std::string::npos) {
                    std::string dev_id = line.substr(0, tab_pos);
                    devices.push_back(dev_id);
                }
            }
        }
    }
    pclose(pipe);

    if (devices.empty()) {
        return false;
    }

    if (devices.size() == 1) {
        device_id = devices[0];
        std::cout << "[*] Using device: " << device_id << "\n";
        return true;
    }

    if (device_id.empty()) {
        std::cerr << "ERROR: Multiple devices found. Please specify device with -d option:\n";
        for (const auto& dev : devices) {
            std::cerr << "  - " << dev << "\n";
        }
        return false;
    }

    bool found = false;
    for (const auto& dev : devices) {
        if (dev == device_id) {
            found = true;
            break;
        }
    }

    if (!found) {
        std::cerr << "ERROR: Specified device '" << device_id << "' not found.\n";
        std::cerr << "Available devices:\n";
        for (const auto& dev : devices) {
            std::cerr << "  - " << dev << "\n";
        }
        return false;
    }

    std::cout << "[*] Using device: " << device_id << "\n";
    return true;
}

bool setup_adb_forward(const std::string& device_id) {
    std::string forward_cmd = "adb";
    if (!device_id.empty()) {
        forward_cmd += " -s " + device_id;
    }
    forward_cmd += " forward tcp:1907 localabstract:com.android.internal.os.RuntimeInit";

    int ret = system(forward_cmd.c_str());
    if (ret != 0) {
        std::cerr << "WARNING: Failed to setup ADB port forwarding\n";
        std::cerr << "Please run manually: " << forward_cmd << "\n";
        return false;
    }
    return true;
}

std::string read_lua_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::string clean_input(const std::string& input) {
    std::string result;
    result.reserve(input.size());

    size_t i = 0;
    while (i < input.size()) {
        if (input[i] == '\x1b') {
            if (i + 1 < input.size() && input[i + 1] == '[') {
                size_t j = i + 2;
                while (j < input.size()) {
                    char c = input[j];
                    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '~') {
                        j++;
                        break;
                    }
                    j++;
                }
                i = j;
                continue;
            } else if (i + 1 < input.size()) {
                i += 2;
                continue;
            }
        }

        if (input[i] < 0x20 && input[i] != '\t' && input[i] != '\n' && input[i] != '\r') {
            i++;
            continue;
        }

        result += input[i];
        i++;
    }

    return result;
}

struct LoadScriptResult {
    std::vector<std::string> exec_cmds;  // Multiple commands for batch loading
    bool auto_watch;
};

static LoadScriptResult g_last_load_result;

LoadScriptResult preprocess_load_command(const std::string& command) {
    LoadScriptResult result{{}, false};
    std::string clean_cmd = clean_input(command);

    if (clean_cmd.length() > 2 && clean_cmd[0] == 'l' && clean_cmd[1] == ' ') {
        std::string args = clean_cmd.substr(2);

        bool watch_flag = false;

        size_t watch_pos = args.find("-w");
        if (watch_pos == std::string::npos) {
            watch_pos = args.find("--watch");
        }

        if (watch_pos != std::string::npos) {
            watch_flag = true;
            std::string before_flag = args.substr(0, watch_pos);
            size_t flag_len = (args.find("--watch", watch_pos) != std::string::npos) ? 7 : 2;
            size_t flag_end = watch_pos + flag_len;
            std::string after_flag = (flag_end < args.length()) ? args.substr(flag_end) : "";
            args = before_flag + after_flag;
        }

        size_t start = args.find_first_not_of(" \t");
        size_t end = args.find_last_not_of(" \t");
        if (start == std::string::npos) {
            return result;
        }
        args = args.substr(start, end - start + 1);

        std::vector<std::string> file_paths;
        std::istringstream iss(args);
        std::string file_path;
        while (iss >> file_path) {
            file_paths.push_back(file_path);
        }

        if (file_paths.empty()) {
            return result;
        }

        std::cout << "Loading " << file_paths.size() << " script(s)";
        if (watch_flag) {
            std::cout << " (auto-watch enabled)";
        }
        std::cout << ":\n";

        for (const auto& path : file_paths) {
            std::string lua_code = read_lua_file(path);
            if (lua_code.empty()) {
                std::cerr << "  ERROR: Cannot read file: " << path << "\n";
                continue;
            }
            std::cout << "  ✓ " << path << "\n";
            result.exec_cmds.push_back("exec " + lua_code);
        }

        result.auto_watch = watch_flag;
        g_last_load_result = result;
    }

    return result;
}

bool is_streaming_command(const std::string& command) {
    if (command == "watch" || command.rfind("watch ", 0) == 0) return true;
    if (command.rfind("renef-strace", 0) == 0) {
        std::string args = command.length() > 13 ? command.substr(13) : "";
        if (args == "--stop" || args == "--list" || args == "--active" ||
            args == "-h" || args == "--help")
            return false;
        return true;
    }
    return false;
}

bool check_quit_key() {
    struct termios oldt, newt;
    int ch;
    int oldf;

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);

    ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fcntl(STDIN_FILENO, F_SETFL, oldf);

    if (ch == 'q' || ch == 'Q') {
        return true;
    }
    return false;
}

std::string send_command(const std::string& command) {
    if (g_gadget_mode && g_gadget_transport && g_gadget_transport->is_connected()) {
        std::string full_cmd = g_gadget_key + " " + command + "\n";
        g_gadget_transport->send_data(full_cmd.c_str(), full_cmd.length());

        std::string response;
        char buffer[4096];
        auto start = std::chrono::steady_clock::now();
        bool got_data = false;

        while (true) {
            ssize_t n = g_gadget_transport->receive_data(buffer, sizeof(buffer) - 1);
            if (n > 0) {
                buffer[n] = '\0';
                response += buffer;
                got_data = true;
                start = std::chrono::steady_clock::now();
            } else {
                auto elapsed = std::chrono::steady_clock::now() - start;
                if (elapsed > std::chrono::milliseconds(got_data ? 200 : 10000)) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }

        if (!response.empty()) {
            ColorManager& cm = ColorManager::instance();
            std::cout << cm.response_color << response << RESET;
            std::cout.flush();
        }
        return response;
    }

    ServerConnection& conn = ServerConnection::instance();

    if (!conn.is_connected()) {
        bool connected = false;
        if (g_local_mode) {
            // Local mode: connect via UDS directly
            connected = conn.connect(DEFAULT_UDS_PATH, 0);
            if (!connected) {
                std::cerr << "Error: Cannot connect to server via UDS\n";
                std::cerr << "\nMake sure renef_server is running on the device\n";
            }
        } else {
            // Remote mode: connect via TCP (through ADB forward)
            connected = conn.connect("127.0.0.1", DEFAULT_TCP_PORT);
            if (!connected) {
                std::cerr << "Error: Cannot connect to server\n";
                std::cerr << "\nMake sure:\n";
                std::cerr << "1. renef_server is running on Android device\n";
                std::cerr << "2. adb forward is set: adb forward tcp:1907 localabstract:com.android.internal.os.RuntimeInit\n";
            }
        }
        if (!connected) {
            return "";
        }
    }

    // Drain any stale data from previous streaming commands (strace, watch, etc.)
    {
        int fd = conn.get_socket_fd();
        if (fd >= 0) {
            char drain[4096];
            int old_flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, old_flags | O_NONBLOCK);
            while (recv(fd, drain, sizeof(drain), 0) > 0) {}
            fcntl(fd, F_SETFL, old_flags);
        }
    }

    bool streaming = is_streaming_command(command);
    if (streaming) {
        std::cout << "(Press 'q' to exit watch mode)\n";
    }

    if (!conn.send(command + "\n")) {
        std::cerr << "Error: Failed to send command\n";
        return "";
    }

    std::string full_response;
    ColorManager& cm = ColorManager::instance();

    if (streaming) {
        // Streaming mode: loop with short timeout, check for 'q' key
        while (true) {
            if (check_quit_key()) {
                std::cout << "\nExiting watch mode...\n";
                conn.send("q\n");
                conn.receive(500);
                break;
            }

            std::string chunk = conn.receive(100);
            if (!chunk.empty()) {
                std::cout << cm.response_color << chunk << RESET;
                std::cout.flush();
                full_response += chunk;
            }
        }
    } else {
        // Normal mode: single receive with timeout
        full_response = conn.receive(10000);

        if (!full_response.empty()) {
            std::cout << cm.response_color << full_response << RESET;
            std::cout.flush();
        } else {
            std::cout << "(no response)\n";
        }
    }

    return full_response;
}

static std::string send_command_silent(const std::string& command) {
    ServerConnection& conn = ServerConnection::instance();
    if (!conn.is_connected()) return "";

    int fd = conn.get_socket_fd();
    if (fd < 0) return "";

    {
        char drain[4096];
        int old_flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, old_flags | O_NONBLOCK);
        while (recv(fd, drain, sizeof(drain), 0) > 0) {}
        fcntl(fd, F_SETFL, old_flags);
    }

    if (!conn.send(command + "\n")) return "";

    std::string result;
    char buf[4096];
    int old_flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, old_flags | O_NONBLOCK);

    int timeout_count = 0;
    while (timeout_count < 100) { // 10 seconds max
        struct pollfd pfd = {fd, POLLIN, 0};
        int ret = poll(&pfd, 1, 100);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                buf[n] = '\0';
                result += buf;
                if (strstr(buf, "\342\234\223") || strstr(buf, "\342\234\227")) break;
                timeout_count = 0;
            } else if (n == 0) {
                break;
            }
        } else {
            timeout_count++;
        }
    }

    fcntl(fd, F_SETFL, old_flags);

    size_t marker = result.find("\342\234\223");
    if (marker == std::string::npos) marker = result.find("\342\234\227");
    if (marker != std::string::npos) result = result.substr(0, marker);

    return result;
}

// ─── Client-side AI command (multi-provider) ─────────────────────

enum AIProvider { AI_OLLAMA, AI_OPENAI, AI_ANTHROPIC };

static std::string ai_https_post(const std::string& host, int port, bool use_tls,
                                 const std::string& path, const std::string& body,
                                 const std::string& auth_header = "") {
    // For HTTPS (OpenAI/Anthropic) we shell out to curl — simpler than implementing TLS
    if (use_tls) {
        std::string url = "https://" + host + path;
        std::string cmd = "curl -s --max-time 300 -X POST \"" + url + "\" "
            "-H \"Content-Type: application/json\" ";
        if (!auth_header.empty()) cmd += auth_header + " ";
        // Write body to temp file to avoid shell escaping issues
        std::string tmp = "/tmp/.renef_ai_body.json";
        FILE* f = fopen(tmp.c_str(), "w");
        if (f) { fwrite(body.c_str(), 1, body.size(), f); fclose(f); }
        cmd += "-d @" + tmp + " 2>/dev/null";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return "";
        std::string result;
        char buf[4096];
        while (fgets(buf, sizeof(buf), pipe)) result += buf;
        pclose(pipe);
        return result;
    }

    // Plain HTTP (Ollama) — raw socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    struct timeval tv = {300, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return "";
    }

    std::string request =
        "POST " + path + " HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: close\r\n\r\n" + body;

    size_t total_sent = 0;
    while (total_sent < request.size()) {
        ssize_t sent = ::send(sock, request.c_str() + total_sent, request.size() - total_sent, 0);
        if (sent < 0) { close(sock); return ""; }
        total_sent += sent;
    }

    std::string response;
    char buf[4096];
    int retries = 0;
    while (retries < 3) {
        ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n > 0) { buf[n] = '\0'; response += buf; retries = 0; }
        else if (n == 0) break;
        else if (errno == EAGAIN || errno == EWOULDBLOCK) { retries++; continue; }
        else break;
    }
    close(sock);

    size_t body_start = response.find("\r\n\r\n");
    if (body_start != std::string::npos) return response.substr(body_start + 4);
    return response;
}

static std::string ai_json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 64);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    char hex[8]; snprintf(hex, sizeof(hex), "\\u%04x", c); out += hex;
                } else { out += c; }
        }
    }
    return out;
}

static std::string ai_json_extract(const std::string& json, const std::string& field) {
    std::string key = "\"" + field + "\"";
    size_t pos = json.find(key);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + key.size());
    if (pos == std::string::npos) return "";
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\n')) pos++;
    if (pos >= json.size() || json[pos] != '"') return "";
    pos++;
    std::string result;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            pos++;
            switch (json[pos]) {
                case 'n': result += '\n'; break;
                case 't': result += '\t'; break;
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                default: result += json[pos]; break;
            }
        } else { result += json[pos]; }
        pos++;
    }
    return result;
}


static const char* TOOL_DEF_OPENAI = R"([{"type":"function","function":{"name":"renef_exec","description":"Execute Lua code in the target Android process. Use print() for output.","parameters":{"type":"object","properties":{"command":{"type":"string","description":"Lua code. Use print() for output."}},"required":["command"]}}}])";

static const char* TOOL_DEF_ANTHROPIC = R"([{"name":"renef_exec","description":"Execute Lua code in the target Android process. Use print() for output.","input_schema":{"type":"object","properties":{"command":{"type":"string","description":"Lua code. Use print() for output."}},"required":["command"]}}])";

struct AIRequest {
    std::string host;
    int port;
    bool use_tls;
    std::string path;
    std::string auth_header;
};

struct AIResponse {
    std::string content;
    std::string tool_cmd;
    std::string raw;
};

static AIRequest ai_build_request(AIProvider provider) {
    AIRequest req;
    switch (provider) {
        case AI_OPENAI:
            req.host = "api.openai.com"; req.port = 443; req.use_tls = true;
            req.path = "/v1/chat/completions";
            req.auth_header = "-H \"Authorization: Bearer " + std::string(getenv("OPENAI_API_KEY") ?: "") + "\"";
            break;
        case AI_ANTHROPIC:
            req.host = "api.anthropic.com"; req.port = 443; req.use_tls = true;
            req.path = "/v1/messages";
            req.auth_header = "-H \"x-api-key: " + std::string(getenv("ANTHROPIC_API_KEY") ?: "") + "\" "
                "-H \"anthropic-version: 2023-06-01\"";
            break;
        default: { // OLLAMA
            const char* h = getenv("OLLAMA_HOST");
            const char* p = getenv("OLLAMA_PORT");
            req.host = h ? h : "127.0.0.1";
            req.port = p ? atoi(p) : 11434;
            req.use_tls = false;
            req.path = "/api/chat";
            break;
        }
    }
    return req;
}

static std::string ai_build_body(AIProvider provider, const std::string& model,
                                  const std::string& system_prompt,
                                  const std::string& messages_json,
                                  bool use_tools) {
    switch (provider) {
        case AI_OPENAI: {
            std::string body = "{\"model\":\"" + model + "\",\"messages\":" + messages_json;
            if (use_tools) body += ",\"tools\":" + std::string(TOOL_DEF_OPENAI);
            body += "}";
            return body;
        }
        case AI_ANTHROPIC: {
            // Anthropic: system is separate, messages don't include system role
            // Extract user/assistant/tool messages from messages_json (skip system)
            std::string body = "{\"model\":\"" + model + "\","
                "\"max_tokens\":4096,"
                "\"system\":\"" + ai_json_escape(system_prompt) + "\","
                "\"messages\":" + messages_json;
            if (use_tools) body += ",\"tools\":" + std::string(TOOL_DEF_ANTHROPIC);
            body += "}";
            return body;
        }
        default: { // OLLAMA
            std::string body = "{\"model\":\"" + model + "\",\"messages\":" + messages_json + ",\"stream\":false";
            if (use_tools) {
                body += ",\"tools\":[{\"type\":\"function\",\"function\":{\"name\":\"renef_exec\","
                    "\"description\":\"Execute Lua code. Use print() for output.\","
                    "\"parameters\":{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}},"
                    "\"required\":[\"command\"]}}}]";
            }
            body += "}";
            return body;
        }
    }
}

static AIResponse ai_parse_response(AIProvider provider, const std::string& raw) {
    AIResponse resp;
    resp.raw = raw;

    switch (provider) {
        case AI_OPENAI: {
            // OpenAI: {"choices":[{"message":{"content":"...","tool_calls":[{"function":{"arguments":"{\"command\":\"...\"}"}}]}}]}
            resp.content = ai_json_extract(raw, "content");
            if (raw.find("\"tool_calls\"") != std::string::npos) {
                // OpenAI tool_calls arguments is a JSON STRING, not object
                std::string args_str = ai_json_extract(raw, "arguments");
                if (!args_str.empty()) {
                    resp.tool_cmd = ai_json_extract(args_str, "command");
                }
            }
            break;
        }
        case AI_ANTHROPIC: {
            // Anthropic: {"content":[{"type":"text","text":"..."},{"type":"tool_use","input":{"command":"..."}}]}
            if (raw.find("\"tool_use\"") != std::string::npos) {
                size_t tool_pos = raw.find("\"tool_use\"");
                size_t input_pos = raw.find("\"input\"", tool_pos);
                if (input_pos != std::string::npos) {
                    resp.tool_cmd = ai_json_extract(raw.substr(input_pos), "command");
                }
            }
            size_t text_pos = raw.find("\"text\"");
            if (text_pos != std::string::npos) {
                resp.content = ai_json_extract(raw.substr(text_pos - 1), "text");
            }
            break;
        }
        default: { // OLLAMA
            resp.content = ai_json_extract(raw, "content");
            if (raw.find("\"tool_calls\"") != std::string::npos) {
                size_t args_pos = raw.find("\"arguments\"");
                if (args_pos != std::string::npos)
                    resp.tool_cmd = ai_json_extract(raw.substr(args_pos), "command");
            }
            if (resp.tool_cmd.empty() && !resp.content.empty() && resp.content.size() < 300 && resp.content.find("```") == std::string::npos) {
                std::string maybe = ai_json_extract(resp.content, "command");
                if (!maybe.empty()) resp.tool_cmd = maybe;
            }
            break;
        }
    }

    // Check for API errors
    std::string err = ai_json_extract(raw, "error");
    if (err.empty()) err = ai_json_extract(raw, "message"); // Anthropic error format
    if (!err.empty() && resp.content.empty() && resp.tool_cmd.empty()) {
        resp.content = "ERROR: " + err;
    }

    return resp;
}

static std::string resolve_file_refs(const std::string& prompt) {
    std::string result;
    size_t pos = 0;

    while (pos < prompt.size()) {
        size_t at = prompt.find('@', pos);
        if (at == std::string::npos) {
            result += prompt.substr(pos);
            break;
        }

        result += prompt.substr(pos, at - pos);

        size_t path_start = at + 1;
        size_t path_end = path_start;
        while (path_end < prompt.size() && prompt[path_end] != ' ' && prompt[path_end] != '\t') {
            path_end++;
        }

        std::string path = prompt.substr(path_start, path_end - path_start);

        if (!path.empty()) {
            std::ifstream f(path);
            if (f.good()) {
                std::string content((std::istreambuf_iterator<char>(f)), {});
                std::cout << "[AI] Read " << content.size() << " bytes from " << path << "\n";
                result += "\n--- File: " + path + " ---\n" + content + "\n--- End of file ---\n";
            } else {
                std::cerr << "[AI] Cannot read: " << path << "\n";
                result += "@" + path;
            }
        }

        pos = path_end;
    }

    return result;
}

static bool handle_ai_command(const std::string& raw_prompt) {
    std::string prompt = resolve_file_refs(raw_prompt);

    const char* env_provider = getenv("RENEF_AI_PROVIDER");
    AIProvider provider = AI_OLLAMA;
    if (env_provider) {
        std::string p = env_provider;
        if (p == "openai") provider = AI_OPENAI;
        else if (p == "anthropic") provider = AI_ANTHROPIC;
    } else if (getenv("OPENAI_API_KEY")) {
        provider = AI_OPENAI;
    } else if (getenv("ANTHROPIC_API_KEY")) {
        provider = AI_ANTHROPIC;
    }

    const char* env_model = getenv("OLLAMA_MODEL");
    std::string model;
    if (env_model) {
        model = env_model;
    } else {
        switch (provider) {
            case AI_OPENAI:    model = "gpt-4o"; break;
            case AI_ANTHROPIC: model = "claude-sonnet-4-20250514"; break;
            default:           model = "llama3.1"; break;
        }
    }

    const char* provider_names[] = {"Ollama", "OpenAI", "Anthropic"};
    std::cout << "[AI] Provider: " << provider_names[provider] << " (" << model << ")\n";

    std::string system_prompt;
    const char* prompt_paths[] = {"RENEF_AI_PROMPT.md", "/data/local/tmp/renef_prompt.md", nullptr};
    const char* env_prompt_path = getenv("RENEF_AI_PROMPT");
    if (env_prompt_path) {
        std::ifstream f(env_prompt_path);
        if (f.good()) system_prompt.assign(std::istreambuf_iterator<char>(f), {});
    }
    if (system_prompt.empty()) {
        for (int i = 0; prompt_paths[i]; i++) {
            std::ifstream f(prompt_paths[i]);
            if (f.good()) { system_prompt.assign(std::istreambuf_iterator<char>(f), {}); break; }
        }
    }
    if (system_prompt.empty()) {
        system_prompt = "You are a Renef scripting assistant for Android instrumentation using Lua. Do NOT use Frida syntax.";
    }

    bool has_target = (CommandRegistry::instance().get_current_pid() > 0);

    if (has_target) {
        system_prompt += "\n\nYou have a renef_exec tool to run Lua code on the target. "
            "Use it to gather info (always use print() for output). "
            "Analyze the target first, then generate the final script.";
    }

    std::string messages;
    if (provider == AI_ANTHROPIC) {
        messages = "[{\"role\":\"user\",\"content\":\"" + ai_json_escape(prompt) + "\"}]";
    } else {
        messages = "[{\"role\":\"system\",\"content\":\"" + ai_json_escape(system_prompt) + "\"},"
                   "{\"role\":\"user\",\"content\":\"" + ai_json_escape(prompt) + "\"}]";
    }

    std::cout << "[AI] Thinking...\n";

    AIRequest req = ai_build_request(provider);
    std::string final_text;
    const int max_rounds = 10;

    for (int round = 0; round < max_rounds; round++) {
        std::string body = ai_build_body(provider, model, system_prompt, messages, has_target);
        std::string raw = ai_https_post(req.host, req.port, req.use_tls, req.path, body, req.auth_header);

        if (raw.empty()) {
            std::cerr << "ERROR: Cannot connect to " << provider_names[provider] << " at " << req.host << "\n";
            if (provider == AI_OLLAMA) std::cerr << "Make sure Ollama is running: ollama serve\n";
            return true;
        }

        AIResponse resp = ai_parse_response(provider, raw);

        if (resp.content.find("ERROR:") == 0 && resp.tool_cmd.empty()) {
            std::cerr << resp.content << "\n";
            return true;
        }

        if (has_target && !resp.tool_cmd.empty()) {
            std::cout << "[AI] exec: " << resp.tool_cmd << "\n";

            std::string result = send_command_silent("exec " + resp.tool_cmd);
            if (result.size() > 4000) result = result.substr(0, 4000) + "\n...(truncated)";

            std::string preview = result.substr(0, 200);
            if (result.size() > 200) preview += "...";
            std::cout << "[AI] result: " << preview << "\n";

            messages.pop_back(); // remove ]

            if (provider == AI_ANTHROPIC) {
                // Anthropic: assistant with tool_use block, then user with tool_result
                messages += ",{\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"tc_1\",\"name\":\"renef_exec\","
                    "\"input\":{\"command\":\"" + ai_json_escape(resp.tool_cmd) + "\"}}]},"
                    "{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"tool_use_id\":\"tc_1\","
                    "\"content\":\"" + ai_json_escape(result) + "\"}]}]";
            } else {
                // OpenAI / Ollama: assistant message + tool message
                messages += ",{\"role\":\"assistant\",\"content\":\"" + ai_json_escape(resp.content) + "\"},"
                    "{\"role\":\"tool\",\"content\":\"" + ai_json_escape(result) + "\"}]";
            }

            continue;
        }

        final_text = resp.content;
        break;
    }

    if (final_text.empty()) {
        std::cerr << "ERROR: No response from AI\n";
        return true;
    }

    std::cout << "\n─── AI Response ───\n" << final_text << "\n";

    size_t code_start = final_text.find("```lua");
    if (code_start == std::string::npos) code_start = final_text.find("```");
    if (code_start != std::string::npos) {
        code_start = final_text.find('\n', code_start);
        if (code_start != std::string::npos) {
            code_start++;
            size_t code_end = final_text.find("```", code_start);
            if (code_end != std::string::npos) {
                std::string code = final_text.substr(code_start, code_end - code_start);
                std::cout << "\n─── Extracted Script ───\n" << code;
                std::cout << "\n───\nTo load: exec <paste script>\nOr save to file and: l <path>\n";
            }
        }
    }

    return true;
}

int main(int argc, char *argv[]) {
    std::string device_id;
    std::string script_file;
    std::string attach_pid;
    std::string spawn_app;
    bool view_mode = false;
    bool watch_mode = false;
    bool pause_mode = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if ((arg == "-d" || arg == "--device") && i + 1 < argc) {
            device_id = argv[++i];
        }
        else if ((arg == "-l" || arg == "--load") && i + 1 < argc) {
            script_file = argv[++i];
        }
        else if ((arg == "-a" || arg == "--attach") && i + 1 < argc) {
            attach_pid = argv[++i];
        }
        else if ((arg == "-s" || arg == "--spawn") && i + 1 < argc) {
            spawn_app = argv[++i];
        }
        else if ((arg == "-g" || arg == "--gadget") && i + 1 < argc) {
            g_gadget_pid = std::stoi(argv[++i]);
            g_gadget_mode = true;
        }
        else if ((arg == "-m" || arg == "--mode") && i + 1 < argc) {
            std::string mode_val = argv[++i];
            if (mode_val == "v" || mode_val == "view") {
                view_mode = true;
            }
        }
        else if (arg.rfind("-m=", 0) == 0 || arg.rfind("--mode=", 0) == 0) {
            std::string mode_val = arg.substr(arg.find('=') + 1);
            if (mode_val == "v" || mode_val == "view") {
                view_mode = true;
            }
        }
        else if (arg == "-w" || arg == "--watch") {
            watch_mode = true;
        }
        else if (arg == "-p" || arg == "--pause") {
            pause_mode = true;
        }
        else if (arg == "-v" || arg == "--verbose") {
            g_verbose_mode = true;
        }
        else if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [options]\n";
            std::cout << "Options:\n";
            std::cout << "  -d, --device <id>        Device ID (optional)\n";
            std::cout << "  -l, --load <script>      Load and execute Lua script\n";
            std::cout << "  -a, --attach <pid>       Attach to process by PID\n";
            std::cout << "  -s, --spawn <app>        Spawn application\n";
            std::cout << "  -g, --gadget <pid>       Gadget mode: connect directly to injected agent (no server)\n";
            std::cout << "  --hook <type>            Hook type: trampoline (default) or pltgot\n";
            std::cout << "  --local                  Local mode: connect via UDS (for Termux/on-device)\n";
            std::cout << "  -m, --mode <mode>        Interface mode: v/view (TUI) [default: CLI]\n";
            std::cout << "  -w, --watch              Auto-watch hook output after loading script\n";
            std::cout << "  -p, --pause              Freeze app after spawn until script is loaded (spawn gate)\n";
            std::cout << "  -v, --verbose            Enable verbose mode (show agent debug logs)\n";
            std::cout << "  -h, --help               Show this help\n";
            std::cout << "\nExamples:\n";
            std::cout << "  " << argv[0] << " -s com.example.app -l script.lua -w\n";
            std::cout << "  " << argv[0] << " -s com.example.app --hook pltgot\n";
            std::cout << "  " << argv[0] << " -a 1234 --hook=pltgot -l hook.lua\n";
            std::cout << "  " << argv[0] << " --local -s com.example.app    # On-device usage\n";
            std::cout << "  " << argv[0] << " -g 12345 -l hook.lua          # Gadget mode (rootless)\n";
            std::cout << "  " << argv[0] << " -m v -s com.example.app       # TUI mode\n";
            return 0;
        }else if(arg == "--local"){
            // Local mode: connect directly via UDS, skip ADB
            std::cout << "[*] Local mode enabled (direct UDS connection)\n";
            g_local_mode = true;
        }
    }

    // Gadget mode: connect directly to agent (no server needed)
    if (g_gadget_mode) {
        std::cout << "[*] Gadget mode: connecting to agent (PID: " << g_gadget_pid << ")...\n";

        int fd = -1;

        if (g_local_mode) {
            // Local mode (Termux): connect via UDS directly to agent
            std::cout << "[*] Using UDS (local mode)\n";
            auto uds = std::make_unique<UDSTransport>("", true);
            fd = uds->connect_to_server(std::to_string(g_gadget_pid));
            g_gadget_transport = std::move(uds);
        } else {
            // Remote mode (PC): connect via TCP (requires: adb forward tcp:1907 localabstract:renef_pl_<pid>)
            std::cout << "[*] Using TCP (run: adb forward tcp:" << DEFAULT_TCP_PORT
                      << " localabstract:renef_pl_" << g_gadget_pid << ")\n";
            auto tcp = std::make_unique<TCPTransport>(DEFAULT_TCP_PORT, "127.0.0.1");
            fd = tcp->connect_to_server("127.0.0.1");
            g_gadget_transport = std::move(tcp);
        }

        if (fd < 0) {
            std::cerr << "ERROR: Failed to connect to agent\n";
            if (g_local_mode) {
                std::cerr << "Make sure the app with libagent.so is running (PID: " << g_gadget_pid << ")\n";
            } else {
                std::cerr << "Make sure:\n";
                std::cerr << "  1. The app with embedded libagent.so is running\n";
                std::cerr << "  2. ADB forward is set: adb forward tcp:" << DEFAULT_TCP_PORT
                          << " localabstract:renef_pl_" << g_gadget_pid << "\n";
            }
            return 1;
        }

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        g_gadget_key = generate_auth_key();

        std::string con_cmd = "con " + g_gadget_key + "\n";
        g_gadget_transport->send_data(con_cmd.c_str(), con_cmd.length());

        std::cout << "[*] Session established with agent\n";
        g_device_ready = true;
    }
    // Skip ADB setup in local mode
    else if (!g_local_mode) {
        bool device_connected = check_adb_devices(device_id);
        g_device_id = device_id;

        if (!g_device_id.empty()) {
            setenv("RENEF_DEVICE_ID", g_device_id.c_str(), 1);
        }

        if (device_connected) {
            std::cout << "[*] Setting up ADB port forwarding...\n";
            if (!setup_adb_forward(g_device_id)) {
                std::cerr << "WARNING: Failed to setup port forwarding.\n";
            }
            g_device_ready = true;
        } else {
            std::cout << "[*] No device connected. Some commands will not work until a device is connected.\n";
        }
    } else {
        // Local mode: device is always ready (we're on the device)
        g_device_ready = true;
    }

    std::cout << "\nRENEF Interactive Shell\n";
    std::cout << "Type 'help' for commands, 'q' to exit.\n\n";

    auto& registry = CommandRegistry::instance();
    registry.setup_all_commands();

    // Auto-load plugins from ~/.config/renef/plugins
    plugin_autoload(nullptr);

    // Register plugins command (client-only)
    extern std::unique_ptr<CommandDispatcher> create_plugins_command();
    registry.register_command(create_plugins_command());

    global_commands = registry.get_all_commands_with_descriptions();

    bool auto_started = g_gadget_mode;  // Gadget mode: agent already running
    if (!attach_pid.empty() || !spawn_app.empty()) {
        // Ensure device is connected for CLI spawn/attach
        if (!g_device_ready) {
            std::string new_device_id = g_device_id;
            if (check_adb_devices(new_device_id)) {
                g_device_id = new_device_id;
                if (!g_device_id.empty()) {
                    setenv("RENEF_DEVICE_ID", g_device_id.c_str(), 1);
                }
                std::cout << "[*] Setting up ADB port forwarding...\n";
                if (setup_adb_forward(g_device_id)) {
                    g_device_ready = true;
                }
            } else {
                std::cerr << "ERROR: No ADB device connected. Cannot spawn/attach.\n";
                return 1;
            }
        }

        std::string start_cmd;

        if (!spawn_app.empty()) {
            start_cmd = "spawn " + spawn_app;
            if (pause_mode) start_cmd += " --pause";
            std::cout << "[*] Spawning " << spawn_app << (pause_mode ? " (paused)" : "") << "...\n";
        } else {
            start_cmd = "attach " + attach_pid;
            std::cout << "[*] Attaching to PID " << attach_pid << "...\n";
        }

        std::string response = send_command(start_cmd);

        if (response.rfind("OK", 0) == 0) {
            int pid = 0;

            if (!spawn_app.empty()) {
                size_t space_pos = response.find(' ');
                if (space_pos != std::string::npos) {
                    try {
                        pid = std::stoi(response.substr(space_pos + 1));
                    } catch (...) {}
                }
            } else {
                try {
                    pid = std::stoi(attach_pid);
                } catch (...) {}
            }

            if (pid > 0) {
                registry.set_current_pid(pid);
                auto_started = true;
                std::cout << "[*] Process ready (PID: " << pid << ")\n";

                // Enable verbose mode if requested
                if (g_verbose_mode) {
                    std::cout << "[*] Enabling verbose mode...\n";
                    send_command("verbose on");
                }
            }
        } else {
            std::cerr << "[ERROR] Failed to start process\n";
        }
    }

    if (auto_started && !script_file.empty()) {
        std::cout << "[*] Loading script: " << script_file << "...\n";

        std::string lua_code = read_lua_file(script_file);
        if (lua_code.empty()) {
            std::cerr << "[ERROR] Cannot read file: " << script_file << "\n";
        } else {
            std::string eval_cmd = "exec " + lua_code;
            std::string response = send_command(eval_cmd);

            if (!response.empty()) {
            }
            std::cout << "[*] Script loaded\n";

            if (watch_mode) {
                std::cout << "\n[Auto-watch enabled - Press 'q' to exit]\n";
                send_command("watch");
            }
        }
    }

    if (auto_started) {
        if (pause_mode && script_file.empty()) {
            std::cout << "\n[*] Process is paused. Type 'resume' to continue or 'l <script>' to load a script.\n";
        }
        std::cout << "\n[*] Interactive shell ready\n";
        std::cout << "[*] You can run commands or enter Lua code\n\n";
    }

#ifdef RENEF_HAS_TUI
    if (view_mode) {
        TuiApp app;
        if (auto_started) {
            ConnectionInfo info;
            info.connected = true;
            info.target_pid = registry.get_current_pid();
            info.target_process = spawn_app.empty() ? attach_pid : spawn_app;
            info.device_id = g_device_id;
            info.mode = g_local_mode ? "UDS" : (g_gadget_mode ? "Gadget" : "TCP");
            app.set_initial_state(info);
        }
        return app.run();
    }
#endif

    rl_bind_key('\t', custom_tab_handler);

    rl_variable_bind("enable-bracketed-paste", "off");

    while (true) {
        ColorManager& cm = ColorManager::instance();
        std::string prompt;

        #ifdef RENEF_NO_READLINE
        #define RL_PROMPT_START ""
        #define RL_PROMPT_END ""
        #else
        #define RL_PROMPT_START "\001"
        #define RL_PROMPT_END "\002"
        #endif

        if (!attach_pid.empty()){
            if (cm.prompt_color != RESET) {
                prompt = RL_PROMPT_START + cm.prompt_color + RL_PROMPT_END + "renef (" + attach_pid + ")> " + RL_PROMPT_START RESET RL_PROMPT_END;
            } else {
                prompt = "renef " RL_PROMPT_START + std::string(cm.get("YELLOW")) + RL_PROMPT_END + "(" + attach_pid + ")" + RL_PROMPT_START RESET RL_PROMPT_END + "> ";
            }
        }else if(!spawn_app.empty()){
            if (cm.prompt_color != RESET) {
                prompt = RL_PROMPT_START + cm.prompt_color + RL_PROMPT_END + "renef (" + spawn_app + ")> " + RL_PROMPT_START RESET RL_PROMPT_END;
            } else {
                prompt = "renef " RL_PROMPT_START + std::string(cm.get("YELLOW")) + RL_PROMPT_END + "(" + spawn_app + ")" + RL_PROMPT_START RESET RL_PROMPT_END + "> ";
            }
        }else{
            prompt = RL_PROMPT_START + cm.prompt_color + RL_PROMPT_END + "renef> " + RL_PROMPT_START RESET RL_PROMPT_END;
        }
        char* input = readline(prompt.c_str());
        std::cout << RESET;

        if (!input) {
            std::cout << "\nExiting...\n";
            break;
        }

        std::string command = clean_input(std::string(input));

        if (command.empty()) {
            free(input);
            continue;
        }

        add_history(input);

        if (command == "q") {
            free(input);
            std::cout << "Exiting...\n";
            break;
        }

        if (command == "help") {
            show_help();
            free(input);
            continue;
        }

        if (command == "clear") {
            std::cout << "\033[2J\033[H" << std::flush;
            free(input);
            continue;
        }

        if (command.rfind("msi ", 0) == 0) {
            std::string pattern = command.substr(4);
            size_t start = pattern.find_first_not_of(" \t");
            if (start == std::string::npos) {
                std::cerr << "Usage: msi <hex_pattern>\n";
                free(input);
                continue;
            }
            pattern = pattern.substr(start);

            std::string ms_cmd = "msj " + pattern;

            std::string json_response;
            try {
                asio::io_context io_context;
                asio::ip::tcp::socket socket(io_context);
                asio::ip::tcp::endpoint endpoint(
                    asio::ip::make_address("127.0.0.1"),
                    DEFAULT_TCP_PORT
                );
                socket.connect(endpoint);

                std::string cmd_with_newline = ms_cmd + "\n";
                asio::write(socket, asio::buffer(cmd_with_newline));

                char response[4096];
                socket.non_blocking(true);

                auto start_time = std::chrono::steady_clock::now();
                const auto initial_timeout = std::chrono::seconds(10);
                const auto data_timeout = std::chrono::milliseconds(200);
                bool data_received = false;

                while (true) {
                    asio::error_code error;
                    size_t len = socket.read_some(asio::buffer(response), error);

                    if (len > 0) {
                        json_response += std::string(response, len);
                        data_received = true;
                        start_time = std::chrono::steady_clock::now();
                    }

                    if (error == asio::error::eof) break;

                    if (error == asio::error::would_block) {
                        auto elapsed = std::chrono::steady_clock::now() - start_time;
                        auto timeout = data_received ? data_timeout : initial_timeout;
                        if (elapsed > timeout) break;
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        continue;
                    }

                    if (error) break;
                }

                socket.close();
            } catch (std::exception& e) {
                std::cerr << "Error: " << e.what() << "\n";
                free(input);
                continue;
            }

            auto results = parse_memscan_json(json_response);

            if (results.empty()) {
                std::cout << "No matches found.\n";
                free(input);
                continue;
            }

            auto selection = show_memscan_tui(results);

            if (selection.action != MemScanAction::NONE) {
                std::ostringstream addr_ss;
                addr_ss << "0x" << std::hex << selection.result.address;

                switch (selection.action) {
                    case MemScanAction::DUMP: {
                        std::cout << "Dumping memory at " << addr_ss.str() << "...\n";
                        std::string dump_cmd = "md " + addr_ss.str() + " 256";
                        send_command(dump_cmd);
                        break;
                    }
                    case MemScanAction::PATCH: {
                        std::cout << "Patch address: " << addr_ss.str() << "\n";
                        char* patch_input = readline("Enter hex bytes (e.g. 90909090): ");
                        if (patch_input && strlen(patch_input) > 0) {
                            std::string hex_value(patch_input);
                            std::string lua_bytes;
                            for (size_t i = 0; i + 1 < hex_value.length(); i += 2) {
                                lua_bytes += "\\x" + hex_value.substr(i, 2);
                            }
                            std::string patch_cmd = "exec Memory.patch(" + addr_ss.str() + ", \"" + lua_bytes + "\")";
                            std::cout << "Patching...\n";
                            send_command(patch_cmd);
                        }
                        free(patch_input);
                        break;
                    }
                    case MemScanAction::WATCH: {
                        std::cout << "Watching " << addr_ss.str() << "...\n";
                        std::string watch_cmd = "watch " + addr_ss.str();
                        send_command(watch_cmd);
                        break;
                    }
                    case MemScanAction::COPY_ADDRESS: {
                        std::cout << "Address: " << addr_ss.str() << "\n";
                        break;
                    }
                    default:
                        break;
                }
            }

            free(input);
            continue;
        }

        if (command == "color" || command.rfind("color ", 0) == 0) {
            std::string args = command.length() > 6 ? command.substr(6) : "";
            size_t start = args.find_first_not_of(" \t");
            if (start != std::string::npos) {
                args = args.substr(start);
            } else {
                args = "";
            }
            handle_color_command(args);
            free(input);
            continue;
        }

        // Handle AI command on client side (Ollama is on PC, not device)
        if (command.rfind("ai ", 0) == 0 || command == "ai") {
            std::string ai_prompt = command.size() > 3 ? command.substr(3) : "";
            handle_ai_command(ai_prompt);
            free(input);
            continue;
        }

        auto load_result = preprocess_load_command(command);
        if (!load_result.exec_cmds.empty()) {
            for (const auto& exec_cmd : load_result.exec_cmds) {
                send_command(exec_cmd);
            }

            if (load_result.auto_watch) {
                std::cout << "\n[Auto-watch enabled - Press Ctrl+C to exit]\n";
                send_command("watch");
            }

            free(input);
            continue;
        }

        std::string processed_cmd = clean_input(command);
        if (processed_cmd.empty()) {
            free(input);
            continue;
        }

        std::string cmd_name = processed_cmd;
        size_t space_pos = cmd_name.find(' ');
        size_t tilde_pos = cmd_name.find('~');
        size_t split_pos = std::string::npos;

        if (space_pos != std::string::npos && tilde_pos != std::string::npos) {
            split_pos = std::min(space_pos, tilde_pos);
        } else if (space_pos != std::string::npos) {
            split_pos = space_pos;
        } else if (tilde_pos != std::string::npos) {
            split_pos = tilde_pos;
        }

        if (split_pos != std::string::npos) {
            cmd_name = cmd_name.substr(0, split_pos);
        }

        bool is_known_command = false;

        for (const auto& [name, desc] : global_commands) {
            if (cmd_name == name) {
                is_known_command = true;
                break;
            }
        }

        if (cmd_name == "help" || cmd_name == "q" || cmd_name == "color" || cmd_name == "clear" || cmd_name == "msi") {
            is_known_command = true;
        }

        if (!is_known_command && processed_cmd.rfind("exec ", 0) != 0) {
            processed_cmd = "exec " + command;
        }

        // Check if command is handled by a plugin (not built-in server commands)
        RENPlugin* plugin = plugin_find(cmd_name.c_str());
        if (plugin && plugin->exec) {
            static int stdout_fd = STDOUT_FILENO;

            renef_ctx ctx;
            ctx.client_fd = &stdout_fd;
            ctx.socket_helper = nullptr;
            ctx.command_registry = nullptr;
            ctx.target_pid = nullptr;

            // Get args after command name
            std::string args;
            size_t space = command.find(' ');
            if (space != std::string::npos) {
                args = command.substr(space + 1);
            }

            plugin->exec(&ctx, args.empty() ? nullptr : const_cast<char*>(args.c_str()));
            free(input);
            continue;
        }

        bool is_spawn_or_attach = (command.rfind("spawn ", 0) == 0 || command.rfind("attach ", 0) == 0);

        if (is_spawn_or_attach && !g_device_ready) {
            std::string new_device_id = g_device_id;
            if (check_adb_devices(new_device_id)) {
                g_device_id = new_device_id;
                if (!g_device_id.empty()) {
                    setenv("RENEF_DEVICE_ID", g_device_id.c_str(), 1);
                }
                std::cout << "[*] Setting up ADB port forwarding...\n";
                if (setup_adb_forward(g_device_id)) {
                    g_device_ready = true;
                }
            } else {
                std::cerr << "ERROR: No ADB device connected. Please connect a device first.\n";
                free(input);
                continue;
            }
        }

        std::string response = send_command(processed_cmd);

        if (is_spawn_or_attach && response.rfind("OK", 0) == 0) {
            int pid = 0;
            bool enable_verbose = g_verbose_mode || (command.find("--verbose") != std::string::npos) || (command.find("-v") != std::string::npos);

            if (command.rfind("spawn ", 0) == 0) {
                size_t space_pos = response.find(' ');
                if (space_pos != std::string::npos) {
                    try {
                        pid = std::stoi(response.substr(space_pos + 1));
                    } catch (...) {}
                }
                std::string args = command.substr(6);
                size_t arg_start = args.find_first_not_of(" \t");
                if (arg_start != std::string::npos) {
                    size_t arg_end = args.find_first_of(" \t", arg_start);
                    spawn_app = args.substr(arg_start, arg_end - arg_start);
                    attach_pid.clear();
                }
            }
            else if (command.rfind("attach ", 0) == 0) {
                try {
                    pid = std::stoi(command.substr(7));
                    attach_pid = std::to_string(pid);
                    spawn_app.clear();
                } catch (...) {}
            }

            if (pid > 0) {
                registry.set_current_pid(pid);

                if (enable_verbose) {
                    send_command("verbose on");
                }
            }
        }
        free(input);
    }

    return 0;
}
