#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace raider {

struct ProcessInfo {
    int         pid{};
    std::string comm;
    std::string cmdline;
    std::string exe_path;
};

// Find a process whose /proc/PID/comm matches name (case-insensitive).
std::optional<int> find_pid_by_name(std::string_view name);

// Find a process whose /proc/PID/cmdline contains substring.
std::optional<int> find_pid_by_cmdline(std::string_view substring);

// Read full info for a known PID.
std::optional<ProcessInfo> get_process_info(int pid);

// List all visible processes.
std::vector<ProcessInfo> list_processes();

// ARC Raiders-specific: tries comm match, then cmdline match, then
// scanning for a thread named "GameThread" inside any wine process.
std::optional<int> find_arc_pid();

} // namespace raider
