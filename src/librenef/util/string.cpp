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
