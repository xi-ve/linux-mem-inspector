#include "inspector/config.hpp"
#include "inspector/inspector.hpp"
#include "inspector/inspector_mcp.hpp"
#include "shared/process/process_finder.hpp"

#include <iostream>
#include <memory>
#include <string>
#include <thread>

static std::string str_tolower(std::string s) {
  for (char& c : s) if (c >= 'A' && c <= 'Z') c += 32;
  return s;
}

static int resolve_pid(int argc, char* argv[], const raider::InspectorConfig& cfg) {
  if (argc >= 2) {
    try {
      return std::stoi(argv[1]);
    } catch (...) {}
  }
  if (!cfg.auto_connect_exe.empty()) {
    std::string key = str_tolower(cfg.auto_connect_exe);
    auto procs = raider::list_processes();
    for (const auto& p : procs) {
      if (str_tolower(p.comm) == key) return p.pid;
      std::string base = p.exe_path;
      size_t slash = p.exe_path.rfind('/');
      if (slash != std::string::npos) base = p.exe_path.substr(slash + 1);
      if (str_tolower(base) == key || str_tolower(p.exe_path).find(key) != std::string::npos)
        return p.pid;
    }
  }
  return 0;
}

int main(int argc, char* argv[]) {
  raider::InspectorConfig cfg = raider::config_load();
  int pid = resolve_pid(argc, argv, cfg);
  if (pid > 0 && argc < 2 && !cfg.auto_connect_exe.empty())
    std::cerr << "[inspector] Auto-connect to " << cfg.auto_connect_exe << " (PID " << pid << ")\n";

  int mcp_port = (cfg.mcp_enabled && cfg.mcp_port > 0) ? cfg.mcp_port : 0;

  raider::Inspector inspector(pid);

  std::unique_ptr<raider::InspectorMCP> mcp;
  std::thread mcp_thread;
  if (mcp_port > 0) {
    mcp = std::make_unique<raider::InspectorMCP>(inspector, mcp_port);
    mcp_thread = std::thread([&]() { mcp->run(); });
  }

  inspector.run();

  if (mcp) {
    mcp->stop();
    if (mcp_thread.joinable()) mcp_thread.join();
  }

  return 0;
}
