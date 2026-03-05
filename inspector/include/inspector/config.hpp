#pragma once

#include <string>

namespace raider {

struct InspectorConfig {
  bool mcp_enabled{false};
  int mcp_port{8082};
  std::string auto_connect_exe;
};

InspectorConfig config_load();
void config_save(const InspectorConfig& c);
std::string config_path();

}
