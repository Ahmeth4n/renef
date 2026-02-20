#include "tui_app.h"
#include "tui_status_bar.h"
#include "tabs/console_tab.h"
#include "tabs/hooks_tab.h"
#include "tabs/modules_tab.h"
#include "tabs/memory_tab.h"
#include "tabs/logs_tab.h"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

using namespace ftxui;

static Color accent_from_name(const std::string& name) {
    if (name == "green")   return Color::Green;
    if (name == "yellow")  return Color::Yellow;
    if (name == "red")     return Color::Red;
    if (name == "blue")    return Color::Blue;
    if (name == "magenta") return Color::Magenta;
    if (name == "white")   return Color::White;
    return Color::Cyan; // default
}

TuiApp::TuiApp()
    : state_(std::make_shared<TuiState>()) {}

void TuiApp::set_initial_state(const ConnectionInfo& info) {
    state_->set_connection_info(info);
}

int TuiApp::run() {
    auto screen = ScreenInteractive::Fullscreen();
    state_->set_screen(&screen);

    int active_view = 0;   // 0=overview, 1=memory, 2=watch
    bool panel_active = false; // true = top panel has focus, Esc toggles

    // Components
    auto hooks_panel = CreateHooksTab(state_);
    auto modules_panel = CreateModulesTab(state_);
    auto memory_panel = CreateMemoryTab(state_);
    auto logs_panel = CreateLogsTab(state_);
    auto console_panel = CreateConsoleTab(state_);

    // Console always receives keyboard events
    auto app_renderer = Renderer(console_panel, [&] {
        // Check for view switch request (from console ms/md commands)
        int req = state_->consume_requested_view();
        if (req >= 0 && req <= 2) active_view = req;

        auto accent = accent_from_name(state_->get_accent());
        auto dim_c = Color::GrayDark;

        // ── Live data for tabs ──
        auto hooks_vec = state_->get_hooks();
        auto modules_vec = state_->get_modules();
        auto scan_vec = state_->get_scan_results();
        auto log_vec = state_->get_log_lines();
        int n_hooks = (int)hooks_vec.size();
        int n_mods = (int)modules_vec.size();
        int n_scan = (int)scan_vec.size();
        int n_logs = (int)log_vec.size();

        // ── View tabs with live status ──
        auto active_bg = bgcolor(Color::Palette256(238));
        auto active_fg = bold | color(Color::White);
        auto inactive_fg = color(dim_c);

        // Tab 0: Overview — hooks + modules counts
        Element tab0;
        if (active_view == 0) {
            tab0 = hbox({
                text(" \u25CF") | color(Color::Green),  // ●
                text(" " + std::to_string(n_hooks) + " hooks") | active_fg,
                text(" \u2502 ") | color(dim_c),  // │
                text(std::to_string(n_mods) + " modules ") | active_fg,
            }) | active_bg;
        } else {
            tab0 = hbox({
                text(" \u25CF") | color(n_hooks > 0 ? Color::Green : Color::GrayDark),
                text(" " + std::to_string(n_hooks)) | inactive_fg,
                text("/") | inactive_fg,
                text(std::to_string(n_mods) + " ") | inactive_fg,
            });
        }

        // Tab 1: Memory — scan result count (ms/md)
        Element tab1;
        if (active_view == 1) {
            tab1 = hbox({
                text(" \u25CE") | color(accent),  // ◎
                text(" Memory") | active_fg,
                n_scan > 0
                    ? (text(" (" + std::to_string(n_scan) + ")") | color(Color::Yellow))
                    : text(""),
                text(" "),
            }) | active_bg;
        } else {
            tab1 = hbox({
                text(" \u25CE") | inactive_fg,
                text(" Mem") | inactive_fg,
                n_scan > 0
                    ? (text(":" + std::to_string(n_scan)) | color(Color::Yellow))
                    : text(""),
                text(" "),
            });
        }

        // Tab 2: Watch — live hook output count
        Element tab2;
        if (active_view == 2) {
            tab2 = hbox({
                text(" \u2261") | color(accent),  // ≡
                text(" Watch") | active_fg,
                n_logs > 0
                    ? (text(" (" + std::to_string(n_logs) + ")") | color(Color::Yellow))
                    : text(""),
                text(" "),
            }) | active_bg;
        } else {
            tab2 = hbox({
                text(" \u2261") | inactive_fg,
                text(" Watch") | inactive_fg,
                n_logs > 0
                    ? (text(":" + std::to_string(n_logs)) | color(Color::Yellow))
                    : text(""),
                text(" "),
            });
        }

        auto view_tabs = hbox({
            text(" "),
            tab0,
            text("  "),
            tab1,
            text("  "),
            tab2,
            filler(),
            text(" Tab") | bold | color(Color::GrayLight),
            text(":\u25C0\u25B6 ") | color(dim_c),  // ◀▶
        });

        // ── Top content based on active view ──
        Element top_content;

        if (active_view == 0) {
            auto hooks_hdr = hbox({
                text(" Hooks") | bold | color(accent),
                filler(),
                text(std::to_string(n_hooks) + " ") | color(dim_c),
            });
            auto modules_hdr = hbox({
                text(" Modules") | bold | color(accent),
                filler(),
                text(std::to_string(n_mods) + " ") | color(dim_c),
            });

            top_content = hbox({
                vbox({
                    hooks_hdr,
                    separator(),
                    hooks_panel->Render() | flex,
                }) | flex,
                separator(),
                vbox({
                    modules_hdr,
                    separator(),
                    modules_panel->Render() | flex,
                }) | flex,
            });
        } else if (active_view == 1) {
            top_content = memory_panel->Render();
        } else {
            top_content = logs_panel->Render();
        }

        auto top_area = vbox({
            view_tabs,
            separator(),
            top_content | flex,
        }) | size(HEIGHT, EQUAL, 11);

        // ── Console ──
        auto console_section = console_panel->Render() | flex;

        // ── Unified layout ──
        auto main_content = vbox({
            top_area,
            separator(),
            console_section | flex,
        }) | border | color(dim_c) | flex;

        // ── Status bar ──
        auto status = render_status_bar(state_, 0);

        // ── Help bar ──
        Elements help_items;
        help_items.push_back(text(" Esc") | bold | color(Color::White));
        if (panel_active) {
            help_items.push_back(text(" \u2192 console") | color(dim_c));
        } else if (active_view != 0) {
            help_items.push_back(text(" \u2192 panel") | color(dim_c));
        } else {
            help_items.push_back(text("") | color(dim_c));
        }
        help_items.push_back(text("  Tab") | bold | color(Color::White));
        help_items.push_back(text(" view") | color(dim_c));
        help_items.push_back(text("  ^C") | bold | color(Color::White));
        help_items.push_back(text(" quit") | color(dim_c));
        help_items.push_back(filler());
        if (panel_active) {
            help_items.push_back(text("\u25B2 PANEL") | bold | color(accent));
        } else {
            help_items.push_back(text("\u25BC console") | color(dim_c));
        }
        help_items.push_back(text(" "));

        auto help = hbox(std::move(help_items)) | bgcolor(Color::Palette256(235));

        return vbox({
            status,
            main_content | flex,
            help,
        });
    });

    // Event handler — Esc toggles focus between console and top panel
    auto app = CatchEvent(app_renderer, [&](Event event) -> bool {
        // Tab: cycle views
        if (event == Event::Tab) {
            active_view = (active_view + 1) % 3;
            // Auto-activate panel when switching to memory/watch
            panel_active = (active_view != 0);
            return true;
        }
        if (event == Event::TabReverse) {
            active_view = (active_view + 2) % 3;
            panel_active = (active_view != 0);
            return true;
        }

        // Ctrl+C: quit
        if (event == Event::Special("\x03")) {
            screen.Exit();
            return true;
        }

        // Panel is active: route events to panel
        if (panel_active && (active_view == 1 || active_view == 2)) {
            // Escape: let panel clean up internally, then ALWAYS return to console
            if (event == Event::Escape) {
                if (active_view == 1) memory_panel->OnEvent(event);
                if (active_view == 2) logs_panel->OnEvent(event);
                panel_active = false;
                return true;
            }
            // Other events: route to panel
            if (active_view == 1 && memory_panel->OnEvent(event)) return true;
            if (active_view == 2 && logs_panel->OnEvent(event)) return true;
            // Panel didn't handle → fall through to console
            return false;
        }

        // Console is active: Esc switches to panel (if on memory/watch)
        if (!panel_active && (active_view == 1 || active_view == 2)) {
            if (event == Event::Escape) {
                panel_active = true;
                return true;
            }
        }

        // Everything else → console input
        return false;
    });

    state_->append_console_output("renef v0.3.3");
    state_->append_console_output("Type 'help' for commands.");
    state_->append_console_output("");

    screen.Loop(app);

    state_->set_screen(nullptr);
    return 0;
}
