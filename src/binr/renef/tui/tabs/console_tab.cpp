#include "console_tab.h"
#include "../command_adapter.h"
#include "../memscan_tui.h"
#include <renef/cmd.h>
#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>
#include <algorithm>
#include <fstream>
#include <sstream>

using namespace ftxui;

static Color color_from_name(const std::string& name) {
    if (name == "green")   return Color::Green;
    if (name == "yellow")  return Color::Yellow;
    if (name == "red")     return Color::Red;
    if (name == "blue")    return Color::Blue;
    if (name == "magenta") return Color::Magenta;
    if (name == "white")   return Color::White;
    if (name == "cyan")    return Color::Cyan;
    return Color::GrayLight; // for "reset" or unknown
}

static const std::vector<std::string> tui_color_names = {
    "cyan", "green", "yellow", "red", "blue", "magenta", "white", "reset"
};

class ConsoleTabImpl : public ComponentBase {
public:
    explicit ConsoleTabImpl(std::shared_ptr<TuiState> state)
        : state_(std::move(state)) {
        InputOption opt;
        opt.multiline = false;
        input_ = Input(&input_content_, "", opt);
        Add(input_);

        // Build command list for autocomplete
        auto cmds = CommandRegistry::instance().get_all_commands_with_descriptions();
        for (const auto& [name, desc] : cmds) {
            all_commands_.push_back({name, desc});
        }
        // Local TUI commands
        all_commands_.push_back({"help", "Show available commands"});
        all_commands_.push_back({"color", "Set theme colors (color list, color prompt=RED)"});
        all_commands_.push_back({"clear", "Clear console"});
        all_commands_.push_back({"q", "Quit hint"});

        // Sort for consistent display
        std::sort(all_commands_.begin(), all_commands_.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });
    }

    Element Render() override {
        auto lines = state_->get_console_lines();
        auto ac = color_from_name(state_->get_accent());
        auto rc = color_from_name(state_->get_response_color());

        Elements output_elements;
        for (auto& line : lines) {
            Element el;
            if (line.rfind("> ", 0) == 0) {
                el = hbox({
                    text(" \u276F ") | color(ac),
                    text(line.substr(2)) | bold | color(Color::White),
                });
            } else if (line.rfind("ERROR", 0) == 0 || line.rfind("error", 0) == 0) {
                el = text(" " + line) | color(Color::Red);
            } else if (line.find("[hook") != std::string::npos ||
                       line.find("onEnter") != std::string::npos ||
                       line.find("onLeave") != std::string::npos) {
                el = text(" " + line) | color(ac);
            } else if (line.empty()) {
                el = text("");
            } else {
                el = text(" " + line) | color(rc);
            }
            output_elements.push_back(el);
        }

        if (output_elements.empty()) {
            output_elements.push_back(text("") | dim);
        }

        auto output_box = vbox(std::move(output_elements))
            | focusPositionRelative(0, 1)
            | vscroll_indicator
            | yframe
            | flex;

        // Prompt
        std::string prompt_name;
        auto info = state_->get_connection_info();
        if (!info.target_process.empty()) {
            prompt_name = info.target_process;
        } else {
            prompt_name = "renef";
        }

        // Suggestions
        auto suggestions = get_suggestions();
        Element suggest_el = text("");
        if (!suggestions.empty() && !input_content_.empty()) {
            Elements suggest_items;
            for (size_t i = 0; i < suggestions.size() && i < 5; i++) {
                auto& s = suggestions[i];
                auto name_el = text(" " + s.first) | bold | color(Color::White);
                auto desc_el = text(" " + s.second) | color(Color::GrayDark);

                if ((int)i == suggest_index_) {
                    suggest_items.push_back(
                        hbox({name_el, desc_el}) | bgcolor(Color::Palette256(238)));
                } else {
                    suggest_items.push_back(hbox({name_el, desc_el}));
                }
            }
            suggest_el = vbox(std::move(suggest_items));
        }

        Element input_line;
        if (state_->is_busy()) {
            input_line = hbox({
                text(" " + prompt_name + " \u276F ") | color(ac),
                text("...") | dim | blink,
            });
        } else {
            input_line = hbox({
                text(" " + prompt_name + " \u276F ") | color(ac),
                input_->Render() | flex,
            });
        }

        return vbox({
            output_box | flex,
            suggest_el,
            separator() | color(Color::GrayDark),
            input_line,
        }) | flex;
    }

    bool OnEvent(Event event) override {
        // Tab: accept suggestion if suggestions visible, otherwise pass through
        if (event == Event::Tab) {
            auto suggestions = get_suggestions();
            if (!suggestions.empty() && !input_content_.empty()) {
                int idx = std::max(0, suggest_index_);
                if (idx < (int)suggestions.size()) {
                    input_content_ = suggestions[idx].first + " ";
                    suggest_index_ = -1;
                }
                return true;
            }
            return false; // let tui_app handle Tab for view cycling
        }

        if (event == Event::Return && !input_content_.empty() && !state_->is_busy()) {
            if (state_->is_watching() && input_content_ != "watch stop") {
                state_->append_console_output("Watch active - type 'watch stop' first");
                state_->request_refresh();
                return true;
            }
            suggest_index_ = -1;
            submit_command();
            return true;
        }

        // Arrow up/down: navigate suggestions or history
        if (event == Event::ArrowUp) {
            auto suggestions = get_suggestions();
            if (!suggestions.empty() && !input_content_.empty()) {
                suggest_index_--;
                if (suggest_index_ < 0) suggest_index_ = (int)std::min(suggestions.size(), (size_t)5) - 1;
                return true;
            }
            navigate_history(-1);
            return true;
        }
        if (event == Event::ArrowDown) {
            auto suggestions = get_suggestions();
            if (!suggestions.empty() && !input_content_.empty()) {
                suggest_index_++;
                if (suggest_index_ >= (int)std::min(suggestions.size(), (size_t)5)) suggest_index_ = 0;
                return true;
            }
            navigate_history(1);
            return true;
        }

        // Escape: close suggestions
        if (event == Event::Escape) {
            if (suggest_index_ >= 0) {
                suggest_index_ = -1;
                return true;
            }
        }

        // Reset suggestion index on any other input
        bool result = input_->OnEvent(event);
        if (result) suggest_index_ = -1;
        return result;
    }

    bool Focusable() const override { return true; }

private:
    std::vector<std::pair<std::string, std::string>> get_suggestions() const {
        if (input_content_.empty()) return {};

        // Only suggest for the first word (command name)
        if (input_content_.find(' ') != std::string::npos) return {};

        std::string lower = input_content_;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        std::vector<std::pair<std::string, std::string>> matches;
        for (const auto& [name, desc] : all_commands_) {
            if (name.rfind(lower, 0) == 0 && name != lower) {
                matches.push_back({name, desc});
            }
        }
        return matches;
    }

    void submit_command() {
        std::string cmd = input_content_;
        input_content_.clear();
        history_.push_back(cmd);
        history_index_ = (int)history_.size();

        state_->append_console_output("> " + cmd);
        state_->request_refresh();

        // Local commands
        if (cmd == "clear") {
            state_->clear_console();
            state_->request_refresh();
            return;
        }

        if (cmd == "help") {
            handle_help();
            return;
        }

        if (cmd == "color" || cmd.rfind("color ", 0) == 0) {
            std::string args = cmd.length() > 6 ? cmd.substr(6) : "";
            size_t start = args.find_first_not_of(" \t");
            args = (start != std::string::npos) ? args.substr(start) : "";
            handle_color(args);
            return;
        }

        if (cmd == "q") {
            state_->append_console_output("Use Ctrl+C to exit TUI.");
            state_->request_refresh();
            return;
        }

        // l: load script(s) locally and send as exec
        if (cmd.length() > 2 && cmd[0] == 'l' && cmd[1] == ' ') {
            std::string args = cmd.substr(2);
            bool watch_flag = false;

            // Parse -w / --watch flag
            size_t wpos = args.find("--watch");
            if (wpos == std::string::npos) wpos = args.find("-w");
            if (wpos != std::string::npos) {
                watch_flag = true;
                size_t flen = (args.find("--watch", wpos) != std::string::npos) ? 7 : 2;
                std::string before = args.substr(0, wpos);
                std::string after = (wpos + flen < args.length()) ? args.substr(wpos + flen) : "";
                args = before + after;
            }

            // Trim
            size_t start = args.find_first_not_of(" \t");
            size_t end = args.find_last_not_of(" \t");
            if (start == std::string::npos) {
                state_->append_console_output("ERROR: No file specified");
                state_->request_refresh();
                return;
            }
            args = args.substr(start, end - start + 1);

            // Parse file paths
            std::vector<std::string> file_paths;
            std::istringstream iss(args);
            std::string fpath;
            while (iss >> fpath) {
                file_paths.push_back(fpath);
            }

            // Read each file locally and build exec commands
            std::vector<std::string> exec_cmds;
            for (const auto& path : file_paths) {
                std::ifstream file(path);
                if (!file.is_open()) {
                    state_->append_console_output("ERROR: Cannot read file: " + path);
                    continue;
                }
                std::stringstream buf;
                buf << file.rdbuf();
                std::string lua_code = buf.str();
                if (lua_code.empty()) {
                    state_->append_console_output("ERROR: Empty file: " + path);
                    continue;
                }
                exec_cmds.push_back("exec " + lua_code);
                state_->append_console_output("  loaded " + path);
            }

            if (exec_cmds.empty()) {
                state_->request_refresh();
                return;
            }

            bool do_watch = watch_flag;
            CommandAdapter::execute_async(exec_cmds[0], state_,
                [this, exec_cmds, do_watch](const std::string& result) {
                    if (!result.empty()) {
                        state_->append_console_output(result);
                    }
                    // Send remaining files sequentially
                    for (size_t i = 1; i < exec_cmds.size(); i++) {
                        std::string r = CommandAdapter::execute_server(exec_cmds[i]);
                        if (!r.empty()) {
                            state_->append_console_output(r);
                        }
                    }
                    if (do_watch) {
                        state_->request_watch_action(TuiState::WatchAction::START);
                        state_->request_view(2);
                        state_->append_console_output("Auto-watch enabled");
                    }
                });
            return;
        }

        // ms/msj: memory search → results go to Memory tab
        if (cmd.rfind("ms ", 0) == 0 || cmd.rfind("msj ", 0) == 0) {
            std::string pattern = cmd.substr(cmd.find(' ') + 1);
            // Always use msj for JSON-parseable output
            CommandAdapter::execute_async("msj " + pattern, state_,
                [this](const std::string& result) {
                    auto parsed = parse_memscan_json(result);
                    int count = (int)parsed.size();
                    state_->set_scan_results(std::move(parsed));
                    state_->append_console_output(
                        std::to_string(count) + " result(s) found");
                    state_->request_view(1); // auto-switch to Memory
                });
            return;
        }

        // md: memory dump → hex dump goes to Memory tab
        if (cmd.rfind("md ", 0) == 0) {
            CommandAdapter::execute_async(cmd, state_,
                [this](const std::string& result) {
                    if (!result.empty()) {
                        state_->set_hex_dump(result);
                        state_->append_console_output("Hex dump loaded - Tab to Memory view");
                    }
                });
            return;
        }

        // watch: control watch tab
        if (cmd == "watch" || cmd == "watch start") {
            state_->request_watch_action(TuiState::WatchAction::START);
            state_->request_view(2);
            state_->append_console_output("Watch started");
            state_->request_refresh();
            return;
        }
        if (cmd == "watch stop") {
            state_->request_watch_action(TuiState::WatchAction::STOP);
            state_->append_console_output("Watch stopped");
            state_->request_refresh();
            return;
        }
        if (cmd == "watch clear") {
            state_->request_watch_action(TuiState::WatchAction::CLEAR);
            state_->append_console_output("Watch logs cleared");
            state_->request_refresh();
            return;
        }

        // Handle spawn/attach: parse PID, update connection state, set registry
        bool is_spawn = (cmd.rfind("spawn ", 0) == 0);
        bool is_attach = (cmd.rfind("attach ", 0) == 0);
        std::string spawn_or_attach_cmd = cmd;

        CommandAdapter::execute_async(cmd, state_,
            [this, is_spawn, is_attach, spawn_or_attach_cmd](const std::string& result) {
                if (!result.empty()) {
                    state_->append_console_output(result);
                }

                if ((is_spawn || is_attach) && result.rfind("OK", 0) == 0) {
                    int pid = 0;
                    std::string target_name;

                    if (is_spawn) {
                        // Parse "OK <pid>"
                        size_t space_pos = result.find(' ');
                        if (space_pos != std::string::npos) {
                            try { pid = std::stoi(result.substr(space_pos + 1)); } catch (...) {}
                        }
                        // Extract package name
                        std::string args = spawn_or_attach_cmd.substr(6);
                        size_t start = args.find_first_not_of(" \t");
                        if (start != std::string::npos) {
                            size_t end = args.find_first_of(" \t", start);
                            target_name = args.substr(start, end - start);
                        }
                    } else {
                        // attach <pid>
                        try { pid = std::stoi(spawn_or_attach_cmd.substr(7)); } catch (...) {}
                        target_name = std::to_string(pid);
                    }

                    if (pid > 0) {
                        CommandRegistry::instance().set_current_pid(pid);

                        ConnectionInfo info;
                        info.connected = true;
                        info.target_pid = pid;
                        info.target_process = target_name;
                        info.mode = "TCP";
                        state_->set_connection_info(info);
                    }
                }
            });
    }

    void handle_help() {
        state_->append_console_output("");
        state_->append_console_output("Commands:");

        for (const auto& [name, desc] : all_commands_) {
            std::string padded = name;
            if (padded.size() < 15) padded.resize(15, ' ');
            state_->append_console_output("  " + padded + desc);
        }

        state_->append_console_output("");
        state_->append_console_output("Navigation:");
        state_->append_console_output("  Tab             Cycle views (Overview / Memory / Watch)");
        state_->append_console_output("  Shift+Tab       Cycle views backwards");
        state_->append_console_output("  Ctrl+Q          Quit");
        state_->append_console_output("");
        state_->request_refresh();
    }

    void handle_color(const std::string& args) {
        if (args.empty() || args == "list") {
            std::string prompt_c = state_->get_accent();
            std::string response_c = state_->get_response_color();

            state_->append_console_output("");
            state_->append_console_output("Current theme:");
            state_->append_console_output("  prompt:   " + prompt_c);
            state_->append_console_output("  response: " + response_c);
            state_->append_console_output("");

            std::string available;
            for (const auto& c : tui_color_names) {
                if (!available.empty()) available += ", ";
                available += c;
            }
            state_->append_console_output("Available colors: " + available);
            state_->append_console_output("Themes: prompt, response");
            state_->append_console_output("");
            state_->append_console_output("Usage: color <theme>=<COLOR>");
            state_->append_console_output("");
            state_->request_refresh();
            return;
        }

        // Parse theme=COLOR
        size_t eq = args.find('=');
        if (eq == std::string::npos) {
            state_->append_console_output("ERROR: Invalid format. Use: color <theme>=<COLOR>");
            state_->append_console_output("Themes: prompt, response");
            state_->request_refresh();
            return;
        }

        std::string theme = args.substr(0, eq);
        std::string color_name = args.substr(eq + 1);

        // Normalize
        std::transform(theme.begin(), theme.end(), theme.begin(), ::tolower);
        std::transform(color_name.begin(), color_name.end(), color_name.begin(), ::tolower);

        // Validate color
        bool valid_color = false;
        for (const auto& c : tui_color_names) {
            if (c == color_name) { valid_color = true; break; }
        }
        if (!valid_color) {
            std::string available;
            for (const auto& c : tui_color_names) {
                if (!available.empty()) available += ", ";
                available += c;
            }
            state_->append_console_output("ERROR: Invalid color '" + color_name + "'");
            state_->append_console_output("Colors: " + available);
            state_->request_refresh();
            return;
        }

        if (theme == "prompt") {
            state_->set_accent(color_name);
            state_->append_console_output("Set prompt to " + color_name);
        } else if (theme == "response") {
            state_->set_response_color(color_name);
            state_->append_console_output("Set response to " + color_name);
        } else {
            state_->append_console_output("ERROR: Invalid theme '" + theme + "'");
            state_->append_console_output("Themes: prompt, response");
        }
        state_->request_refresh();
    }

    void navigate_history(int direction) {
        if (history_.empty()) return;
        history_index_ += direction;
        if (history_index_ < 0) history_index_ = 0;
        if (history_index_ >= (int)history_.size()) {
            history_index_ = (int)history_.size();
            input_content_.clear();
            return;
        }
        input_content_ = history_[history_index_];
    }

    std::shared_ptr<TuiState> state_;
    Component input_;
    std::string input_content_;
    std::vector<std::string> history_;
    int history_index_ = 0;
    std::vector<std::pair<std::string, std::string>> all_commands_;
    int suggest_index_ = -1;
};

Component CreateConsoleTab(std::shared_ptr<TuiState> state) {
    return Make<ConsoleTabImpl>(std::move(state));
}
