#include "inspector/config.hpp"

#include <cstdlib>
#include <fstream>
#include <string>

#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

namespace raider {

static std::string get_config_dir() {
  const char* xdg = std::getenv("XDG_CONFIG_HOME");
  if (xdg && xdg[0]) return std::string(xdg);
  const char* home = std::getenv("HOME");
  if (home && home[0]) return std::string(home) + "/.config";
  struct passwd* pw = getpwuid(getuid());
  if (pw && pw->pw_dir) return std::string(pw->pw_dir) + "/.config";
  return "/tmp";
}

std::string config_path() {
  return get_config_dir() + "/inspector/config";
}

static int parse_int(const std::string& s, int def) {
  try {
    return std::stoi(s);
  } catch (...) {
    return def;
  }
}

static bool parse_bool(const std::string& s) {
  if (s.empty()) return false;
  if (s == "1" || s == "true" || s == "yes") return true;
  if (s == "0" || s == "false" || s == "no") return false;
  return parse_int(s, 0) != 0;
}

InspectorConfig config_load() {
  InspectorConfig c;
  std::ifstream f(config_path());
  if (!f) return c;
  std::string line;
  while (std::getline(f, line)) {
    size_t p = line.find('#');
    if (p != std::string::npos) line.resize(p);
    while (!line.empty() && (line.back() == ' ' || line.back() == '\r')) line.pop_back();
    size_t eq = line.find('=');
    if (eq == std::string::npos) continue;
    std::string key = line.substr(0, eq);
    std::string val = line.substr(eq + 1);
    while (!key.empty() && key.back() == ' ') key.pop_back();
    while (!val.empty() && val.front() == ' ') val.erase(0, 1);
    if (key == "mcp_enabled") c.mcp_enabled = parse_bool(val);
    else if (key == "mcp_port") c.mcp_port = parse_int(val, 8082);
    else if (key == "auto_connect_exe") c.auto_connect_exe = val;
  }
  return c;
}

void config_save(const InspectorConfig& c) {
  std::string dir = get_config_dir() + "/inspector";
  mkdir(get_config_dir().c_str(), 0755);
  mkdir(dir.c_str(), 0755);
  std::ofstream f(dir + "/config");
  if (!f) return;
  f << "mcp_enabled=" << (c.mcp_enabled ? "1" : "0") << "\n";
  f << "mcp_port=" << c.mcp_port << "\n";
  f << "auto_connect_exe=" << c.auto_connect_exe << "\n";
}

}
