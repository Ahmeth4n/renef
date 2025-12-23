#include "memscan_tui.h"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <cstring>
#include <json.hpp>

using json = nlohmann::json;

std::vector<MemScanResult> parse_memscan_json(const std::string& json_response) {
    std::vector<MemScanResult> results;

    try {
        json j = json::parse(json_response);

        if (!j.value("success", false)) {
            return results;
        }

        for (const auto& item : j["results"]) {
            MemScanResult r;
            r.library = item.value("library", "");
            r.offset = item.value("offset", 0L);
            r.address = item.value("address", 0UL);
            r.hex = item.value("hex", "");
            r.ascii = item.value("ascii", "");
            results.push_back(r);
        }
    } catch (...) {
    }

    return results;
}

class SimpleTerm {
public:
    struct termios orig_termios;
    bool raw_mode = false;

    void enable_raw_mode() {
        if (raw_mode) return;
        tcgetattr(STDIN_FILENO, &orig_termios);
        struct termios raw = orig_termios;
        raw.c_lflag &= ~(ICANON | ECHO | ISIG);
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        raw_mode = true;
    }

    void disable_raw_mode() {
        if (!raw_mode) return;
        tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
        raw_mode = false;
    }

    int read_key() {
        char c;
        if (read(STDIN_FILENO, &c, 1) != 1) return -1;

        if (c == 27) {
            char seq[3];
            if (read(STDIN_FILENO, &seq[0], 1) != 1) return 27;
            if (read(STDIN_FILENO, &seq[1], 1) != 1) return 27;

            if (seq[0] == '[') {
                switch (seq[1]) {
                    case 'A': return 1000;
                    case 'B': return 1001;
                    case 'C': return 1002;
                    case 'D': return 1003;
                }
            }
            return 27;
        }
        return c;
    }

    void clear() { write(STDOUT_FILENO, "\033[2J\033[H", 7); }
    void hide_cursor() { write(STDOUT_FILENO, "\033[?25l", 6); }
    void show_cursor() { write(STDOUT_FILENO, "\033[?25h", 6); }
};

MemScanSelection show_memscan_tui(const std::vector<MemScanResult>& results) {
    MemScanSelection selection;
    selection.selected_index = -1;
    selection.action = MemScanAction::NONE;

    if (results.empty()) {
        return selection;
    }

    SimpleTerm term;
    term.enable_raw_mode();
    term.hide_cursor();

    int selected = 0;
    bool show_actions = false;
    int action_selected = 0;
    bool running = true;

    const char* action_names[] = {"Dump", "Patch", "Watch", "Copy Address", "Cancel"};
    const int action_count = 5;

    std::vector<std::string> entries;
    for (size_t i = 0; i < results.size(); i++) {
        std::ostringstream ss;
        ss << "[" << (i + 1) << "] ";
        if (!results[i].library.empty()) {
            ss << results[i].library << " + 0x" << std::hex << results[i].offset;
        } else {
            ss << "0x" << std::hex << results[i].address;
        }
        entries.push_back(ss.str());
    }

    std::string output_buffer;
    output_buffer.reserve(8192);

    auto flush_output = [&]() {
        write(STDOUT_FILENO, output_buffer.c_str(), output_buffer.size());
        output_buffer.clear();
    };

    auto append = [&](const char* s) {
        output_buffer.append(s);
    };

    auto append_str = [&](const std::string& s) {
        output_buffer.append(s);
    };

    auto render = [&]() {
        output_buffer.clear();
        append("\033[2J\033[H");

        const auto& r = results[selected];

        append("\033[1m Memory Scan Results (");
        append_str(std::to_string(results.size()));
        append(" matches) \033[0m\n");
        append("─────────────────────────────────────────────────────────────\n");

        int start = std::max(0, selected - 5);
        int end = std::min((int)entries.size(), start + 10);
        if (end - start < 10 && start > 0) {
            start = std::max(0, end - 10);
        }

        for (int i = start; i < end; i++) {
            if (i == selected) {
                append("\033[7m");
                append_str(entries[i]);
                append("\033[0m\n");
            } else {
                append_str(entries[i]);
                append("\n");
            }
        }

        append("─────────────────────────────────────────────────────────────\n");

        std::ostringstream detail;
        detail << "Address: 0x" << std::hex << r.address << std::dec << "\n";
        detail << "Library: " << (r.library.empty() ? "(anonymous)" : r.library) << "\n";
        detail << "Offset:  0x" << std::hex << r.offset << std::dec << "\n";
        detail << "Hex:     " << r.hex << "\n";
        detail << "ASCII:   " << r.ascii << "\n";
        append_str(detail.str());

        append("─────────────────────────────────────────────────────────────\n");

        if (show_actions) {
            append("\033[1mSelect Action:\033[0m\n");
            for (int i = 0; i < action_count; i++) {
                if (i == action_selected) {
                    append("\033[7m > ");
                    append(action_names[i]);
                    append(" \033[0m\n");
                } else {
                    append("   ");
                    append(action_names[i]);
                    append("\n");
                }
            }
        } else {
            append("\033[2m[↑↓] Navigate  [Enter] Actions  [d]ump  [p]atch  [w]atch  [q] Quit\033[0m\n");
        }

        flush_output();
    };

    while (running) {
        render();
        int key = term.read_key();

        if (show_actions) {
            switch (key) {
                case 1000:
                case 'k':
                    action_selected = std::max(0, action_selected - 1);
                    break;
                case 1001:
                case 'j':
                    action_selected = std::min(action_count - 1, action_selected + 1);
                    break;
                case '\n':
                case '\r':
                    if (action_selected == 4) {
                        show_actions = false;
                    } else {
                        selection.selected_index = selected;
                        selection.result = results[selected];
                        switch (action_selected) {
                            case 0: selection.action = MemScanAction::DUMP; break;
                            case 1: selection.action = MemScanAction::PATCH; break;
                            case 2: selection.action = MemScanAction::WATCH; break;
                            case 3: selection.action = MemScanAction::COPY_ADDRESS; break;
                        }
                        running = false;
                    }
                    break;
                case 27:
                    show_actions = false;
                    break;
            }
        } else {
            switch (key) {
                case 1000:
                case 'k':
                    selected = std::max(0, selected - 1);
                    break;
                case 1001:
                case 'j':
                    selected = std::min((int)results.size() - 1, selected + 1);
                    break;
                case '\n':
                case '\r':
                    show_actions = true;
                    action_selected = 0;
                    break;
                case 'q':
                case 27:
                    running = false;
                    break;
                case 'd':
                    selection.selected_index = selected;
                    selection.result = results[selected];
                    selection.action = MemScanAction::DUMP;
                    running = false;
                    break;
                case 'p':
                    selection.selected_index = selected;
                    selection.result = results[selected];
                    selection.action = MemScanAction::PATCH;
                    running = false;
                    break;
                case 'w':
                    selection.selected_index = selected;
                    selection.result = results[selected];
                    selection.action = MemScanAction::WATCH;
                    running = false;
                    break;
            }
        }
    }

    term.show_cursor();
    term.disable_raw_mode();
    term.clear();

    return selection;
}
