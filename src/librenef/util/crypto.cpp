#include <renef/crypto.h>
#include <random>
#include <chrono>

static const char CHARSET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
static const size_t CHARSET_SIZE = sizeof(CHARSET) - 1;

std::string generate_auth_key() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, CHARSET_SIZE - 1);

    std::string key;
    key.reserve(AUTH_KEY_LENGTH);

    for (int i = 0; i < AUTH_KEY_LENGTH; i++) {
        key += CHARSET[dist(gen)];
    }

    return key;
}
