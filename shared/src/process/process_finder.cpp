#include "shared/process/process_finder.hpp"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unistd.h>

namespace raider {

namespace {

std::optional<int> parse_pid_dir(const std::filesystem::path& p) {
    const std::string name = p.filename().string();
    if (name.empty() || !std::isdigit(static_cast<unsigned char>(name[0])))
        return std::nullopt;
    int pid = 0;
    for (char c : name) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return std::nullopt;
        pid = pid * 10 + (c - '0');
    }
    return pid;
}

std::string read_text(const std::filesystem::path& p) {
    std::ifstream f(p);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    std::string s = ss.str();
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
        s.pop_back();
    return s;
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

} // namespace

std::optional<int> find_pid_by_name(std::string_view name) {
    std::string target = to_lower(std::string(name));
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;
        auto pid = parse_pid_dir(entry.path());
        if (!pid) continue;
        if (to_lower(read_text(entry.path() / "comm")) == target)
            return pid;
    }
    return std::nullopt;
}

std::optional<int> find_pid_by_cmdline(std::string_view substring) {
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;
        auto pid = parse_pid_dir(entry.path());
        if (!pid) continue;
        std::string cmdline = read_text(entry.path() / "cmdline");
        for (char& c : cmdline) if (c == '\0') c = ' ';
        if (cmdline.find(substring) != std::string::npos)
            return pid;
    }
    return std::nullopt;
}

std::optional<ProcessInfo> get_process_info(int pid) {
    if (pid <= 0) return std::nullopt;
    std::filesystem::path base = std::filesystem::path("/proc") / std::to_string(pid);
    if (!std::filesystem::is_directory(base)) return std::nullopt;

    ProcessInfo info;
    info.pid     = pid;
    info.comm    = read_text(base / "comm");
    info.cmdline = read_text(base / "cmdline");
    for (char& c : info.cmdline) if (c == '\0') c = ' ';

    char buf[4096];
    ssize_t n = ::readlink((base / "exe").c_str(), buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = '\0'; info.exe_path.assign(buf, n); }

    return info;
}

std::vector<ProcessInfo> list_processes() {
    std::vector<ProcessInfo> out;
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;
        auto pid = parse_pid_dir(entry.path());
        if (!pid) continue;
        ProcessInfo info;
        info.pid     = *pid;
        info.comm    = read_text(entry.path() / "comm");
        info.cmdline = read_text(entry.path() / "cmdline");
        for (char& c : info.cmdline) if (c == '\0') c = ' ';
        out.push_back(std::move(info));
    }
    return out;
}

// Scan /proc/PID/task/*/comm for a thread named "GameThread".
// This identifies the game's main process even when the top-level comm is truncated.
static std::optional<int> find_pid_game_thread() {
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;
        auto pid = parse_pid_dir(entry.path());
        if (!pid) continue;
        std::filesystem::path task_dir = entry.path() / "task";
        if (!std::filesystem::is_directory(task_dir)) continue;
        std::error_code ec;
        for (const auto& t : std::filesystem::directory_iterator(task_dir, ec)) {
            if (read_text(t.path() / "comm") == "GameThread")
                return pid;
        }
    }
    return std::nullopt;
}

std::optional<int> find_arc_pid() {
    if (auto p = find_pid_by_name("ARC-Win64-Shipping"))    return p;
    if (auto p = find_pid_by_cmdline("ARC-Win64-Shipping")) return p;
    if (auto p = find_pid_game_thread())                    return p;
    return std::nullopt;
}

} // namespace raider
