#pragma once

#include <string>
#include <map>

#define RESET   "\033[0m"
#define BLACK   "\033[30m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define BOLDBLACK   "\033[1m\033[30m"
#define BOLDRED     "\033[1m\033[31m"
#define BOLDGREEN   "\033[1m\033[32m"
#define BOLDYELLOW  "\033[1m\033[33m"
#define BOLDBLUE    "\033[1m\033[34m"
#define BOLDMAGENTA "\033[1m\033[35m"
#define BOLDCYAN    "\033[1m\033[36m"
#define BOLDWHITE   "\033[1m\033[37m"

class ColorManager {
public:
    static ColorManager& instance() {
        static ColorManager mgr;
        return mgr;
    }

    const char* get(const std::string& name) const {
        auto it = color_map.find(name);
        if (it != color_map.end()) {
            return it->second;
        }
        return RESET;
    }

    std::string prompt_color = RESET;
    std::string response_color = RESET;

    bool set_theme_color(const std::string& theme, const std::string& color_name) {
        const char* code = get(color_name);
        if (code == RESET && color_name != "RESET") {
            return false;
        }

        if (theme == "prompt") prompt_color = code;
        else if (theme == "response") response_color = code;
        else return false;

        return true;
    }

    std::string list_colors() const {
        std::string result;
        for (const auto& pair : color_map) {
            result += pair.second + pair.first + RESET + " ";
        }
        return result;
    }

    std::string list_theme() const {
        std::string result;
        result += "prompt:   " + prompt_color + "sample" + RESET + "\n";
        result += "response: " + response_color + "sample" + RESET + "\n";
        return result;
    }

private:
    ColorManager() {
        color_map = {
            {"BLACK", BLACK}, {"RED", RED}, {"GREEN", GREEN},
            {"YELLOW", YELLOW}, {"BLUE", BLUE}, {"MAGENTA", MAGENTA},
            {"CYAN", CYAN}, {"WHITE", WHITE},
            {"BOLDBLACK", BOLDBLACK}, {"BOLDRED", BOLDRED},
            {"BOLDGREEN", BOLDGREEN}, {"BOLDYELLOW", BOLDYELLOW},
            {"BOLDBLUE", BOLDBLUE}, {"BOLDMAGENTA", BOLDMAGENTA},
            {"BOLDCYAN", BOLDCYAN}, {"BOLDWHITE", BOLDWHITE},
            {"RESET", RESET}
        };
    }

    std::map<std::string, const char*> color_map;
};
