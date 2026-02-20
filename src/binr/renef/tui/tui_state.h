#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <functional>
#include "memscan_tui.h"

namespace ftxui {
class ScreenInteractive;
}

struct ConnectionInfo {
    bool connected = false;
    std::string mode;
    std::string device_id;
    std::string target_process;
    int target_pid = -1;
};

struct HookEntry {
    int id = 0;
    std::string library;
    std::string function_name;
    std::string address;
    std::string type;
};

struct ModuleEntry {
    std::string name;
    std::string base_address;
    std::string size;
    std::string path;
};

class TuiState {
public:
    static constexpr size_t MAX_CONSOLE_LINES = 5000;
    static constexpr size_t MAX_LOG_LINES = 10000;

    void set_screen(ftxui::ScreenInteractive* screen);
    void request_refresh();

    // Connection
    ConnectionInfo get_connection_info() const;
    void set_connection_info(const ConnectionInfo& info);

    // Console
    void append_console_output(const std::string& text);
    std::vector<std::string> get_console_lines() const;
    void clear_console();

    // Hooks
    void set_hooks(std::vector<HookEntry> hooks);
    std::vector<HookEntry> get_hooks() const;

    // Memory scan
    void set_scan_results(std::vector<MemScanResult> results);
    std::vector<MemScanResult> get_scan_results() const;

    // Hex dump
    void set_hex_dump(const std::string& dump);
    std::string get_hex_dump() const;

    // Modules
    void set_modules(std::vector<ModuleEntry> modules);
    std::vector<ModuleEntry> get_modules() const;

    // Logs
    void append_log(const std::string& line);
    std::vector<std::string> get_log_lines() const;
    void clear_logs();

    // Command busy state
    void set_busy(bool busy);
    bool is_busy() const;

    // TUI theme colors (prompt = accent, response = output text)
    void set_accent(const std::string& color_name);
    std::string get_accent() const;
    void set_response_color(const std::string& color_name);
    std::string get_response_color() const;

    // View switch request (-1 = no request, 0/1/2 = switch to that view)
    void request_view(int view);
    int consume_requested_view();

    // Watch control (for console → watch tab communication)
    enum class WatchAction { NONE, START, STOP, CLEAR };
    void request_watch_action(WatchAction action);
    WatchAction consume_watch_action();

    // Watch streaming state (blocks console commands during watch)
    void set_watching(bool watching);
    bool is_watching() const;

private:
    mutable std::mutex mutex_;
    ftxui::ScreenInteractive* screen_ = nullptr;

    ConnectionInfo connection_info_;
    std::vector<std::string> console_lines_;
    std::vector<HookEntry> hooks_;
    std::vector<MemScanResult> scan_results_;
    std::string hex_dump_;
    std::vector<ModuleEntry> modules_;
    std::vector<std::string> log_lines_;
    bool busy_ = false;
    std::string accent_ = "cyan";
    std::string response_color_ = "white";
    int requested_view_ = -1;
    WatchAction watch_action_ = WatchAction::NONE;
    bool watching_ = false;
};
