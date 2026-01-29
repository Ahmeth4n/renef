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
#ifndef RENEF_NO_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include <atomic>
#include "tui/memscan_tui.h"
#include <renef/plugin.h>

static std::vector<std::pair<std::string, std::string>> global_commands;
static std::string g_device_id;
static bool g_device_ready = false;
static bool g_local_mode = false;
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
    {"", {
        {"Module.", "Module operations (list, find, exports)"},
        {"Memory.", "Memory operations (scan, patch)"},
        {"hook(", "Install hook on function"},
        {"console.", "Console output"},
        {"JNI.", "JNI type wrappers"}
    }}
};

static bool g_lua_context = false;

#ifdef RENEF_NO_READLINE
// Simple readline replacement for builds without readline library
static char* simple_readline(const char* prompt) {
    std::cout << prompt;
    std::cout.flush();
    std::string line;
    if (!std::getline(std::cin, line)) {
        return nullptr;
    }
    char* result = (char*)malloc(line.size() + 1);
    if (result) {
        strcpy(result, line.c_str());
    }
    return result;
}
#define readline simple_readline
#define add_history(x) ((void)0)
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
    return command == "watch" || command.rfind("watch ", 0) == 0;
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

int main(int argc, char *argv[]) {
    std::string device_id;
    std::string script_file;
    std::string attach_pid;
    std::string spawn_app;
    std::string hook_type;

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
        else if (arg == "--hook" && i + 1 < argc) {
            hook_type = argv[++i];
        }
        else if (arg.rfind("--hook=", 0) == 0) {
            hook_type = arg.substr(7);
        }
        else if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [options]\n";
            std::cout << "Options:\n";
            std::cout << "  -d, --device <id>        Device ID (optional)\n";
            std::cout << "  -l, --load <script>      Load and execute Lua script\n";
            std::cout << "  -a, --attach <pid>       Attach to process by PID\n";
            std::cout << "  -s, --spawn <app>        Spawn application\n";
            std::cout << "  --hook <type>            Hook type: trampoline (default) or pltgot\n";
            std::cout << "  --local                  Local mode: connect via UDS (for Termux/on-device)\n";
            std::cout << "  -h, --help               Show this help\n";
            std::cout << "\nExamples:\n";
            std::cout << "  " << argv[0] << " -s com.example.app -l script.lua\n";
            std::cout << "  " << argv[0] << " -s com.example.app --hook pltgot\n";
            std::cout << "  " << argv[0] << " -a 1234 --hook=pltgot -l hook.lua\n";
            std::cout << "  " << argv[0] << " --local -s com.example.app    # On-device usage\n";
            return 0;
        }else if(arg == "--local"){
            // Local mode: connect directly via UDS, skip ADB
            std::cout << "[*] Local mode enabled (direct UDS connection)\n";
            g_local_mode = true;
        }
    }

    // Skip ADB setup in local mode
    if (!g_local_mode) {
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

    bool auto_started = false;
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
            if (!hook_type.empty()) {
                start_cmd += " --hook=" + hook_type;
                std::cout << "[*] Spawning " << spawn_app << " (hook: " << hook_type << ")...\n";
            } else {
                std::cout << "[*] Spawning " << spawn_app << "...\n";
            }
        } else {
            start_cmd = "attach " + attach_pid;
            if (!hook_type.empty()) {
                start_cmd += " --hook=" + hook_type;
                std::cout << "[*] Attaching to PID " << attach_pid << " (hook: " << hook_type << ")...\n";
            } else {
                std::cout << "[*] Attaching to PID " << attach_pid << "...\n";
            }
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
        }
    }

    if (auto_started) {
        std::cout << "\n[*] Interactive shell ready\n";
        std::cout << "[*] You can run commands or enter Lua code\n\n";
    }

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
            }
        }
        free(input);
    }

    return 0;
}
