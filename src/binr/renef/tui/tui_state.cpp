#include "tui_state.h"
#include <ftxui/component/screen_interactive.hpp>
#include <sstream>

void TuiState::set_screen(ftxui::ScreenInteractive* screen) {
    std::lock_guard<std::mutex> lock(mutex_);
    screen_ = screen;
}

void TuiState::request_refresh() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (screen_) {
        screen_->Post(ftxui::Event::Custom);
    }
}

ConnectionInfo TuiState::get_connection_info() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connection_info_;
}

void TuiState::set_connection_info(const ConnectionInfo& info) {
    std::lock_guard<std::mutex> lock(mutex_);
    connection_info_ = info;
}

void TuiState::append_console_output(const std::string& text) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        console_lines_.push_back(line);
    }
    while (console_lines_.size() > MAX_CONSOLE_LINES) {
        console_lines_.erase(console_lines_.begin());
    }
}

std::vector<std::string> TuiState::get_console_lines() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return console_lines_;
}

void TuiState::clear_console() {
    std::lock_guard<std::mutex> lock(mutex_);
    console_lines_.clear();
}

void TuiState::set_hooks(std::vector<HookEntry> hooks) {
    std::lock_guard<std::mutex> lock(mutex_);
    hooks_ = std::move(hooks);
}

std::vector<HookEntry> TuiState::get_hooks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return hooks_;
}

void TuiState::set_scan_results(std::vector<MemScanResult> results) {
    std::lock_guard<std::mutex> lock(mutex_);
    scan_results_ = std::move(results);
}

std::vector<MemScanResult> TuiState::get_scan_results() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return scan_results_;
}

void TuiState::set_hex_dump(const std::string& dump) {
    std::lock_guard<std::mutex> lock(mutex_);
    hex_dump_ = dump;
}

std::string TuiState::get_hex_dump() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return hex_dump_;
}

void TuiState::set_modules(std::vector<ModuleEntry> modules) {
    std::lock_guard<std::mutex> lock(mutex_);
    modules_ = std::move(modules);
}

std::vector<ModuleEntry> TuiState::get_modules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return modules_;
}

void TuiState::append_log(const std::string& line) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::istringstream stream(line);
    std::string l;
    while (std::getline(stream, l)) {
        log_lines_.push_back(l);
    }
    while (log_lines_.size() > MAX_LOG_LINES) {
        log_lines_.erase(log_lines_.begin());
    }
}

std::vector<std::string> TuiState::get_log_lines() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return log_lines_;
}

void TuiState::clear_logs() {
    std::lock_guard<std::mutex> lock(mutex_);
    log_lines_.clear();
}

void TuiState::set_busy(bool busy) {
    std::lock_guard<std::mutex> lock(mutex_);
    busy_ = busy;
}

bool TuiState::is_busy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return busy_;
}

void TuiState::set_accent(const std::string& color_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    accent_ = color_name;
}

std::string TuiState::get_accent() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return accent_;
}

void TuiState::set_response_color(const std::string& color_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    response_color_ = color_name;
}

std::string TuiState::get_response_color() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return response_color_;
}

void TuiState::request_view(int view) {
    std::lock_guard<std::mutex> lock(mutex_);
    requested_view_ = view;
}

int TuiState::consume_requested_view() {
    std::lock_guard<std::mutex> lock(mutex_);
    int v = requested_view_;
    requested_view_ = -1;
    return v;
}

void TuiState::request_watch_action(WatchAction action) {
    std::lock_guard<std::mutex> lock(mutex_);
    watch_action_ = action;
}

TuiState::WatchAction TuiState::consume_watch_action() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto a = watch_action_;
    watch_action_ = WatchAction::NONE;
    return a;
}

void TuiState::set_watching(bool watching) {
    std::lock_guard<std::mutex> lock(mutex_);
    watching_ = watching;
}

bool TuiState::is_watching() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return watching_;
}
