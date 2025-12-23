#ifndef MEMSCAN_TUI_H
#define MEMSCAN_TUI_H

#include <string>
#include <vector>
#include <functional>

struct MemScanResult {
    std::string library;
    long offset;
    unsigned long address;
    std::string hex;
    std::string ascii;
};

enum class MemScanAction {
    NONE,
    DUMP,
    PATCH,
    WATCH,
    COPY_ADDRESS
};

struct MemScanSelection {
    int selected_index;
    MemScanAction action;
    MemScanResult result;
};

MemScanSelection show_memscan_tui(const std::vector<MemScanResult>& results);

std::vector<MemScanResult> parse_memscan_json(const std::string& json_response);

#endif
