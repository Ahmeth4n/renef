#include <renef/string_utils.h>
#include <string>
#include <cstdlib>
#include <sstream>
#include <vector>

std::vector<std::string> split(const std::string &s, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(s);
    std::string item;

    while (std::getline(ss, item, delimiter)) {
        if (!item.empty()) {
            tokens.push_back(item);
        }
    }
    return tokens;
}

std::string hex_encode(const std::string& input) {
    static const char hx[] = "0123456789abcdef";
    std::string out;
    out.reserve(input.size() * 2);
    for (unsigned char c : input) {
        out.push_back(hx[c >> 4]);
        out.push_back(hx[c & 0x0f]);
    }
    return out;
}
