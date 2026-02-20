#include "logs_tab.h"
#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>
#include <renef/cmd.h>
#include <renef/server_connection.h>
#include <thread>
#include <atomic>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <cstring>

using namespace ftxui;

class LogsTabImpl : public ComponentBase {
public:
    explicit LogsTabImpl(std::shared_ptr<TuiState> state)
        : state_(std::move(state)) {}

    ~LogsTabImpl() {
        watching_.store(false);
    }

    Element Render() override {
        // Check for watch actions from console
        auto action = state_->consume_watch_action();
        if (action == TuiState::WatchAction::START && !watching_.load()) {
            start_watching();
        } else if (action == TuiState::WatchAction::STOP) {
            watching_.store(false);
        } else if (action == TuiState::WatchAction::CLEAR) {
            state_->clear_logs();
        }

        auto lines = state_->get_log_lines();
        bool is_live = watching_.load();

        // Header line
        auto header = hbox({
            is_live
                ? (text(" \u25CF LIVE") | bold | color(Color::Green))
                : (text(" \u25CB STOPPED") | color(Color::GrayDark)),
            filler(),
            text(std::to_string(lines.size()) + " lines ") | color(Color::GrayDark),
        });

        // Log content
        Elements log_elements;
        if (lines.empty()) {
            log_elements.push_back(
                text("  s:start/stop  c:clear  a:scroll  Esc:console") | color(Color::GrayDark));
        }

        for (auto& line : lines) {
            Element el;
            if (line.find("[hook") != std::string::npos ||
                line.find("onEnter") != std::string::npos ||
                line.find("onLeave") != std::string::npos) {
                el = text(" " + line) | color(Color::Cyan);
            } else if (line.find("ERROR") != std::string::npos ||
                       line.find("error") != std::string::npos) {
                el = text(" " + line) | color(Color::Red);
            } else if (line.find("[Watch]") != std::string::npos) {
                el = text(" " + line) | color(Color::Yellow);
            } else {
                el = text(" " + line) | color(Color::GrayLight);
            }
            log_elements.push_back(el);
        }

        auto log_box = vbox(std::move(log_elements));
        if (auto_scroll_) {
            log_box = log_box | focusPositionRelative(0, 1);
        }
        log_box = log_box | vscroll_indicator | yframe | flex;

        // Controls line
        auto controls = hbox({
            text(" s") | bold | color(Color::White),
            text(is_live ? ":stop" : ":start") | color(Color::GrayDark),
            text("  c") | bold | color(Color::White),
            text(":clear") | color(Color::GrayDark),
            text("  a") | bold | color(Color::White),
            text(":scroll") | color(Color::GrayDark),
            text(auto_scroll_ ? "[on]" : "[off]")
                | color(auto_scroll_ ? Color::Green : Color::GrayDark),
        });

        return vbox({
            header,
            separator() | color(Color::GrayDark),
            log_box | flex,
            controls,
        }) | flex;
    }

    bool OnEvent(Event event) override {
        if (event == Event::Character('s')) {
            if (watching_.load()) {
                watching_.store(false);
            } else {
                start_watching();
            }
            return true;
        }
        if (event == Event::Character('c')) {
            state_->clear_logs();
            state_->request_refresh();
            return true;
        }
        if (event == Event::Character('a')) {
            auto_scroll_ = !auto_scroll_;
            return true;
        }
        // Escape not handled → bubbles up for focus toggle
        return false;
    }

    bool Focusable() const override { return true; }

private:
    void start_watching() {
        if (watching_.load()) return;
        watching_.store(true);
        state_->set_watching(true);
        state_->request_refresh();

        std::thread([this]() {
            auto& conn = ServerConnection::instance();
            if (!conn.is_connected()) {
                state_->append_log("[Watch] not connected to server");
                watching_.store(false);
                state_->set_watching(false);
                state_->request_refresh();
                return;
            }

            // Send watch command on the main connection
            if (!conn.send("watch\n")) {
                state_->append_log("[Watch] failed to send watch command");
                watching_.store(false);
                state_->set_watching(false);
                state_->request_refresh();
                return;
            }

            // Stream from the main connection's socket
            int sock = conn.get_socket_fd();
            char buffer[4096];

            while (watching_.load()) {
                struct pollfd pfd = {sock, POLLIN, 0};
                int ret = poll(&pfd, 1, 500);
                if (ret > 0 && (pfd.revents & POLLIN)) {
                    ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
                    if (n > 0) {
                        buffer[n] = '\0';
                        state_->append_log(std::string(buffer, n));
                        state_->request_refresh();
                    } else if (n == 0) {
                        state_->append_log("[Watch] connection closed");
                        state_->request_refresh();
                        break;
                    }
                }
            }

            // Exit watch mode on server
            conn.send("q\n");
            // Flush remaining data
            struct pollfd pfd = {sock, POLLIN, 0};
            if (poll(&pfd, 1, 200) > 0) {
                char flush[4096];
                recv(sock, flush, sizeof(flush), MSG_DONTWAIT);
            }

            watching_.store(false);
            state_->set_watching(false);
            state_->request_refresh();
        }).detach();
    }

    std::shared_ptr<TuiState> state_;
    std::atomic<bool> watching_{false};
    bool auto_scroll_ = true;
};

Component CreateLogsTab(std::shared_ptr<TuiState> state) {
    return Make<LogsTabImpl>(std::move(state));
}
