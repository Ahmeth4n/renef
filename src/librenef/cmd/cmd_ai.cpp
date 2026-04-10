#include <renef/cmd.h>
#include <renef/socket_helper.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

static const char* OLLAMA_HOST_DEFAULT = "127.0.0.1";
static int OLLAMA_PORT_DEFAULT = 11434;
static const int MAX_TOOL_ROUNDS = 10;

// ─── Minimal HTTP POST ───────────────────────────────────────────

static std::string http_post(const std::string& host, int port,
                             const std::string& path,
                             const std::string& body) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    // 60s timeout for LLM responses
    struct timeval tv = {60, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return "";
    }

    std::string request =
        "POST " + path + " HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: close\r\n\r\n" + body;

    send(sock, request.c_str(), request.size(), 0);

    std::string response;
    char buf[4096];
    ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = '\0';
        response += buf;
    }
    close(sock);

    size_t body_start = response.find("\r\n\r\n");
    if (body_start != std::string::npos)
        return response.substr(body_start + 4);
    return response;
}

// ─── JSON helpers ────────────────────────────────────────────────

static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 64);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    char hex[8];
                    snprintf(hex, sizeof(hex), "\\u%04x", c);
                    out += hex;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

static std::string json_extract_string(const std::string& json, const std::string& field) {
    std::string key = "\"" + field + "\"";
    size_t pos = json.find(key);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos + key.size());
    if (pos == std::string::npos) return "";
    pos++;
    while (pos < json.size() && json[pos] == ' ') pos++;
    if (pos >= json.size() || json[pos] != '"') return "";

    pos++;
    std::string result;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            pos++;
            switch (json[pos]) {
                case 'n': result += '\n'; break;
                case 't': result += '\t'; break;
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                default: result += json[pos]; break;
            }
        } else {
            result += json[pos];
        }
        pos++;
    }
    return result;
}

// ─── Extract code block ─────────────────────────────────────────

static std::string extract_lua_code(const std::string& response) {
    size_t start = response.find("```lua");
    if (start == std::string::npos) start = response.find("```");
    if (start != std::string::npos) {
        start = response.find('\n', start);
        if (start != std::string::npos) {
            start++;
            size_t end = response.find("```", start);
            if (end != std::string::npos)
                return response.substr(start, end - start);
        }
    }
    return "";
}

// ─── System prompt loader ────────────────────────────────────────

static const char* PROMPT_PATHS[] = {
    "/data/local/tmp/renef_prompt.md",
    "RENEF_AI_PROMPT.md",
    nullptr
};

static std::string read_file_str(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return "";
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return ""; }
    std::string content(sz, '\0');
    fread(&content[0], 1, sz, f);
    fclose(f);
    return content;
}

static std::string load_system_prompt() {
    const char* env = getenv("RENEF_AI_PROMPT");
    if (env) {
        std::string c = read_file_str(env);
        if (!c.empty()) { fprintf(stderr, "[ai] Prompt: %s\n", env); return c; }
    }
    for (int i = 0; PROMPT_PATHS[i]; i++) {
        std::string c = read_file_str(PROMPT_PATHS[i]);
        if (!c.empty()) { fprintf(stderr, "[ai] Prompt: %s\n", PROMPT_PATHS[i]); return c; }
    }
    return "You are a Renef scripting assistant for Android instrumentation using Lua. Do NOT use Frida syntax.";
}

// ─── Execute renef command on agent ──────────────────────────────

static std::string exec_on_agent(SocketHelper& sock, int pid, const std::string& lua_code) {
    int fd = sock.ensure_connection(pid);
    if (fd < 0) return "ERROR: Not connected to agent";

    std::string cmd = "exec " + lua_code + "\n";
    sock.send_data(cmd.c_str(), cmd.length());

    std::string output;
    char buf[4096];
    int old_flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, old_flags | O_NONBLOCK);

    int timeout = 0;
    while (timeout < 30) {
        struct pollfd pfd = {fd, POLLIN, 0};
        int ret = poll(&pfd, 1, 100);
        if (ret > 0) {
            ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                buf[n] = '\0';
                output += buf;
                if (strstr(buf, "\342\234\223") || strstr(buf, "\342\234\227")) break;
            }
            timeout = 0;
        } else {
            timeout++;
        }
    }

    fcntl(fd, F_SETFL, old_flags);
    sock.drain_buffer();

    size_t marker = output.find("\342\234\223");
    if (marker == std::string::npos) marker = output.find("\342\234\227");
    if (marker != std::string::npos) output = output.substr(0, marker);

    if (output.size() > 4000) {
        output = output.substr(0, 4000) + "\n... (truncated)\n";
    }

    return output.empty() ? "(no output)" : output;
}

// ─── Tool call detection & parsing ───────────────────────────────

struct ToolCall {
    std::string name;
    std::string arguments;
};

static bool has_tool_calls(const std::string& json) {
    return json.find("\"tool_calls\"") != std::string::npos;
}

static std::vector<ToolCall> parse_tool_calls(const std::string& json) {
    std::vector<ToolCall> calls;

    size_t pos = json.find("\"tool_calls\"");
    if (pos == std::string::npos) return calls;

    size_t search = pos;
    while (true) {
        size_t fn_pos = json.find("\"function\"", search);
        if (fn_pos == std::string::npos) break;

        ToolCall tc;

        size_t name_pos = json.find("\"name\"", fn_pos);
        if (name_pos != std::string::npos) {
            tc.name = json_extract_string(json.substr(name_pos - 1), "name");
        }

        size_t args_pos = json.find("\"arguments\"", fn_pos);
        if (args_pos != std::string::npos) {
            size_t brace = json.find('{', args_pos);
            if (brace != std::string::npos) {
                int depth = 1;
                size_t end = brace + 1;
                while (end < json.size() && depth > 0) {
                    if (json[end] == '{') depth++;
                    else if (json[end] == '}') depth--;
                    end++;
                }
                tc.arguments = json.substr(brace, end - brace);
            }
        }

        if (!tc.name.empty()) calls.push_back(tc);
        search = fn_pos + 10;
    }

    return calls;
}

// ─── Ollama Chat API ─────────────────────────────────────────────

static const char* TOOLS_JSON = R"([
  {
    "type": "function",
    "function": {
      "name": "renef_exec",
      "description": "Execute Lua code in the target Android process via Renef agent. Use this to gather information: list modules, find exports, read memory, check Java classes. The code runs in Renef's Lua engine with full API access.",
      "parameters": {
        "type": "object",
        "properties": {
          "command": {
            "type": "string",
            "description": "Lua code to execute. Use print() to see output. Examples: 'Module.list()', 'for _,e in ipairs(Module.exports(\"libc.so\")) do print(e.name) end', 'print(Memory.readStr(0x1234))'"
          }
        },
        "required": ["command"]
      }
    }
  }
])";

struct ChatMessage {
    std::string role;
    std::string content;
    std::string raw_json; 
};

static std::string build_messages_json(const std::vector<ChatMessage>& messages) {
    std::string json = "[";
    for (size_t i = 0; i < messages.size(); i++) {
        if (i > 0) json += ",";
        const auto& m = messages[i];

        if (!m.raw_json.empty()) {
            json += m.raw_json;
        } else {
            json += "{\"role\":\"" + m.role + "\",\"content\":\"" + json_escape(m.content) + "\"}";
        }
    }
    json += "]";
    return json;
}

// ─── AI Command ──────────────────────────────────────────────────

class AiCommand : public CommandDispatcher {
public:
    std::string get_name() const override { return "ai"; }

    std::string get_description() const override {
        return "Generate Lua scripts using Ollama AI (with tool calling). Usage: ai <prompt>";
    }

    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override {
        if (cmd_size <= 3) {
            const char* usage =
                "Usage: ai <prompt>\n"
                "  ai bypass ssl pinning\n"
                "  ai hook all file open calls and log paths\n"
                "  ai bypass root detection\n"
                "  ai trace crypto functions in libcrypto.so\n"
                "\nThe AI can execute renef commands to gather info about the target.\n"
                "\nConfig (env vars):\n"
                "  OLLAMA_HOST      (default: 127.0.0.1)\n"
                "  OLLAMA_PORT      (default: 11434)\n"
                "  OLLAMA_MODEL     (default: llama3)\n"
                "  RENEF_AI_PROMPT  path to custom prompt file\n";
            write(client_fd, usage, strlen(usage));
            return CommandResult(true, "");
        }

        const char* env_host = getenv("OLLAMA_HOST");
        const char* env_port = getenv("OLLAMA_PORT");
        std::string host = env_host ? env_host : OLLAMA_HOST_DEFAULT;
        int port = env_port ? atoi(env_port) : OLLAMA_PORT_DEFAULT;

        std::string model = "llama3";
        const char* env_model = getenv("OLLAMA_MODEL");
        if (env_model) model = env_model;

        std::string prompt(cmd_buffer + 3, cmd_size - 3);
        while (!prompt.empty() && (prompt.front() == ' ' || prompt.front() == '\t')) prompt.erase(0, 1);
        while (!prompt.empty() && (prompt.back() == '\n' || prompt.back() == '\r' || prompt.back() == ' ')) prompt.pop_back();

        if (prompt.empty()) {
            const char* msg = "ERROR: Empty prompt\n";
            write(client_fd, msg, strlen(msg));
            return CommandResult(false, "Empty prompt");
        }

        int pid = CommandRegistry::instance().get_current_pid();
        SocketHelper& sock = CommandRegistry::instance().get_socket_helper();

        std::string system_prompt = load_system_prompt();

        if (pid > 0) {
            system_prompt += "\n\nYou have access to a renef_exec tool that runs Lua code on the target process. "
                "Use it to gather information before generating your script. For example:\n"
                "- renef_exec('Module.list()') to see loaded libraries\n"
                "- renef_exec('for _,e in ipairs(Module.exports(\"libc.so\")) do print(e.name .. \" \" .. string.format(\"0x%x\", e.offset)) end') to list exports\n"
                "- renef_exec('print(OS.getpid())') to get process info\n"
                "First gather relevant information about the target, then generate the final script.";
        }

        std::vector<ChatMessage> messages;
        messages.push_back({"system", system_prompt, ""});
        messages.push_back({"user", prompt, ""});

        const char* thinking = "[AI] Thinking...\n";
        write(client_fd, thinking, strlen(thinking));

        // ─── Agentic loop ────────────────────────────────────
        std::string final_text;
        bool has_tools = (pid > 0); // Only enable tools if connected to a target

        for (int round = 0; round < MAX_TOOL_ROUNDS; round++) {

            std::string body = "{\"model\":\"" + model + "\","
                "\"messages\":" + build_messages_json(messages) + ","
                "\"stream\":false";

            if (has_tools) {
                body += ",\"tools\":" + std::string(TOOLS_JSON);
            }
            body += "}";

            std::string response = http_post(host, port, "/api/chat", body);

            if (response.empty()) {
                std::string err = "ERROR: Cannot connect to Ollama at " + host + ":" + std::to_string(port) + "\n";
                write(client_fd, err.c_str(), err.size());
                const char* hint = "Make sure Ollama is running: ollama serve\n";
                write(client_fd, hint, strlen(hint));
                return CommandResult(false, "Ollama connection failed");
            }

            std::string content = json_extract_string(response, "content");

            if (has_tools && has_tool_calls(response)) {
                auto tool_calls = parse_tool_calls(response);

                if (!tool_calls.empty()) {
                    size_t msg_pos = response.find("\"message\"");
                    std::string raw_msg;
                    if (msg_pos != std::string::npos) {
                        size_t brace = response.find('{', msg_pos);
                        if (brace != std::string::npos) {
                            int depth = 1;
                            size_t end = brace + 1;
                            while (end < response.size() && depth > 0) {
                                if (response[end] == '{') depth++;
                                else if (response[end] == '}') depth--;
                                end++;
                            }
                            raw_msg = response.substr(brace, end - brace);
                        }
                    }
                    messages.push_back({"assistant", content, raw_msg});

                    for (const auto& tc : tool_calls) {
                        std::string cmd = json_extract_string(tc.arguments, "command");
                        if (cmd.empty()) continue;

                        std::string tool_msg = "[AI] exec: " + cmd + "\n";
                        write(client_fd, tool_msg.c_str(), tool_msg.size());

                        std::string result = exec_on_agent(sock, pid, cmd);

                        std::string result_preview = result.substr(0, 200);
                        if (result.size() > 200) result_preview += "...";
                        std::string show = "[AI] result: " + result_preview + "\n";
                        write(client_fd, show.c_str(), show.size());

                        messages.push_back({"tool", result, ""});
                    }

                    continue;
                }
            }

            final_text = content;
            break;
        }

        if (final_text.empty()) {
            const char* err = "ERROR: No response from AI after tool calling rounds\n";
            write(client_fd, err, strlen(err));
            return CommandResult(false, "Empty AI response");
        }

        const char* header = "\n─── AI Response ───\n";
        write(client_fd, header, strlen(header));
        write(client_fd, final_text.c_str(), final_text.size());

        std::string code = extract_lua_code(final_text);
        if (!code.empty()) {
            const char* sep = "\n─── Extracted Script ───\n";
            write(client_fd, sep, strlen(sep));
            write(client_fd, code.c_str(), code.size());
            const char* hint = "\n───\nTo load: exec <paste script>\nOr save to file and: l <path>\n";
            write(client_fd, hint, strlen(hint));
        }

        write(client_fd, "\n", 1);
        return CommandResult(true, "AI response delivered");
    }
};

std::unique_ptr<CommandDispatcher> create_ai_command() {
    return std::make_unique<AiCommand>();
}
