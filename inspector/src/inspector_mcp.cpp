#include "inspector/inspector_mcp.hpp"
#include "inspector/inspector.hpp"

#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace raider;

// ── Minimal JSON parsing (no external library) ──────────────────────────────

static std::string json_escape_mcp(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
          out += buf;
        } else {
          out += c;
        }
    }
  }
  return out;
}

static std::string find_json_string(const std::string& json, const char* key) {
  std::string needle = std::string("\"") + key + "\"";
  auto pos = json.find(needle);
  if (pos == std::string::npos) return {};
  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) return {};

  pos = json.find_first_not_of(" \t\n\r", pos + 1);
  if (pos == std::string::npos) return {};

  if (json[pos] == '"') {
    std::string result;
    ++pos;
    while (pos < json.size() && json[pos] != '"') {
      if (json[pos] == '\\' && pos + 1 < json.size()) {
        ++pos;
        switch (json[pos]) {
          case '"': result += '"'; break;
          case '\\': result += '\\'; break;
          case 'n': result += '\n'; break;
          case 'r': result += '\r'; break;
          case 't': result += '\t'; break;
          default: result += json[pos]; break;
        }
      } else {
        result += json[pos];
      }
      ++pos;
    }
    return result;
  }

  auto end = json.find_first_of(",}] \t\n\r", pos);
  if (end == std::string::npos) end = json.size();
  return json.substr(pos, end - pos);
}

static int64_t find_json_int(const std::string& json, const char* key, int64_t def = 0) {
  std::string val = find_json_string(json, key);
  if (val.empty()) return def;
  if (val.size() > 2 && val[0] == '0' && (val[1] == 'x' || val[1] == 'X'))
    return static_cast<int64_t>(std::stoull(val, nullptr, 16));
  if (val.front() == '"') {
    val = val.substr(1);
    if (!val.empty() && val.back() == '"') val.pop_back();
    if (val.size() > 2 && val[0] == '0' && (val[1] == 'x' || val[1] == 'X'))
      return static_cast<int64_t>(std::stoull(val, nullptr, 16));
  }
  try { return std::stoll(val); } catch (...) { return def; }
}

static std::string find_json_object(const std::string& json, const char* key) {
  std::string needle = std::string("\"") + key + "\"";
  auto pos = json.find(needle);
  if (pos == std::string::npos) return "{}";
  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) return "{}";
  pos = json.find_first_not_of(" \t\n\r", pos + 1);
  if (pos == std::string::npos || json[pos] != '{') return "{}";

  int depth = 0;
  size_t start = pos;
  bool in_string = false;
  for (size_t i = pos; i < json.size(); ++i) {
    char c = json[i];
    if (in_string) {
      if (c == '\\') { ++i; continue; }
      if (c == '"') in_string = false;
      continue;
    }
    if (c == '"') { in_string = true; continue; }
    if (c == '{') ++depth;
    else if (c == '}') { --depth; if (depth == 0) return json.substr(start, i - start + 1); }
  }
  return "{}";
}

static std::string find_json_array(const std::string& json, const char* key) {
  std::string needle = std::string("\"") + key + "\"";
  auto pos = json.find(needle);
  if (pos == std::string::npos) return "[]";
  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) return "[]";
  pos = json.find_first_not_of(" \t\n\r", pos + 1);
  if (pos == std::string::npos || json[pos] != '[') return "[]";

  int depth = 0;
  size_t start = pos;
  bool in_string = false;
  for (size_t i = pos; i < json.size(); ++i) {
    char c = json[i];
    if (in_string) {
      if (c == '\\') { ++i; continue; }
      if (c == '"') in_string = false;
      continue;
    }
    if (c == '"') { in_string = true; continue; }
    if (c == '[') ++depth;
    else if (c == ']') { --depth; if (depth == 0) return json.substr(start, i - start + 1); }
  }
  return "[]";
}

static std::vector<uint32_t> parse_int_array(const std::string& arr) {
  std::vector<uint32_t> result;
  size_t pos = 0;
  while (pos < arr.size()) {
    pos = arr.find_first_of("0123456789", pos);
    if (pos == std::string::npos) break;
    auto end = arr.find_first_not_of("0123456789xXabcdefABCDEF", pos);
    if (end == std::string::npos) end = arr.size();
    std::string tok = arr.substr(pos, end - pos);
    try {
      if (tok.size() > 2 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X'))
        result.push_back(static_cast<uint32_t>(std::stoul(tok, nullptr, 16)));
      else
        result.push_back(static_cast<uint32_t>(std::stoul(tok)));
    } catch (...) {}
    pos = end;
  }
  return result;
}

// ── InspectorMCP ─────────────────────────────────────────────────────────────

InspectorMCP::InspectorMCP(Inspector& inspector, int port)
    : inspector_(inspector), port_(port) {}

void InspectorMCP::stop() {
  running_.store(false);
  if (listen_fd_ >= 0) {
    shutdown(listen_fd_, SHUT_RDWR);
    close(listen_fd_);
    listen_fd_ = -1;
  }
}

std::string InspectorMCP::make_result(const std::string& id, const std::string& result_json) {
  return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":" + result_json + "}";
}

std::string InspectorMCP::make_error(const std::string& id, int code, const std::string& msg) {
  return "{\"jsonrpc\":\"2.0\",\"id\":" + id +
         ",\"error\":{\"code\":" + std::to_string(code) +
         ",\"message\":\"" + json_escape_mcp(msg) + "\"}}";
}

void InspectorMCP::send_response(int client_fd, const std::string& json) {
  std::string msg;
  msg.reserve(json.size() + 1);
  for (char c : json) {
    if (c != '\n' && c != '\r') msg += c;
  }
  msg += '\n';

  size_t sent = 0;
  while (sent < msg.size()) {
    ssize_t n = write(client_fd, msg.data() + sent, msg.size() - sent);
    if (n <= 0) break;
    sent += n;
  }
}

// ── MCP tool definitions ─────────────────────────────────────────────────────

static const char* kToolDefs = R"JSON([
  {"name":"read_memory","description":"Read raw bytes from process memory. Returns hex dump and typed interpretations (int, float, pointer).",
   "inputSchema":{"type":"object","properties":{"addr":{"type":"string","description":"Address to read (hex string like 0x...)"},"size":{"type":"integer","description":"Number of bytes to read (default 64)","default":64}},"required":["addr"]}},
  {"name":"read_string","description":"Read a null-terminated UTF-8 string from process memory.",
   "inputSchema":{"type":"object","properties":{"addr":{"type":"string","description":"Address to read from"},"max_len":{"type":"integer","description":"Max bytes to read (default 256)","default":256}},"required":["addr"]}},
  {"name":"open_view","description":"Open a new memory inspector view at an address. Returns view_id for subsequent operations.",
   "inputSchema":{"type":"object","properties":{"addr":{"type":"string","description":"Base address"},"label":{"type":"string","description":"View label"},"size":{"type":"integer","description":"View size in bytes (default 0x200)","default":512}},"required":["addr"]}},
  {"name":"close_view","description":"Close an inspector view by ID.",
   "inputSchema":{"type":"object","properties":{"view_id":{"type":"integer","description":"View ID to close"}},"required":["view_id"]}},
  {"name":"list_views","description":"List all open inspector views.",
   "inputSchema":{"type":"object","properties":{}}},
  {"name":"get_view","description":"Get full node tree of an inspector view with live memory values.",
   "inputSchema":{"type":"object","properties":{"view_id":{"type":"integer","description":"View ID"}},"required":["view_id"]}},
  {"name":"set_node_type","description":"Change the display type of a node at a given offset in a view.",
   "inputSchema":{"type":"object","properties":{"view_id":{"type":"integer"},"offset":{"type":"integer","description":"Node offset"},"type":{"type":"string","description":"Node type: Hex8/Hex16/Hex32/Hex64/Int8/Int16/Int32/Int64/UInt8/UInt16/UInt32/UInt64/Float/Double/Bool/Pointer/UTF8Text/UTF16Text/Vec3"}},"required":["view_id","offset","type"]}},
  {"name":"set_node_name","description":"Rename a node at a given offset in a view.",
   "inputSchema":{"type":"object","properties":{"view_id":{"type":"integer"},"offset":{"type":"integer"},"name":{"type":"string"}},"required":["view_id","offset","name"]}},
  {"name":"set_node_comment","description":"Set a comment on a node at a given offset in a view.",
   "inputSchema":{"type":"object","properties":{"view_id":{"type":"integer"},"offset":{"type":"integer"},"comment":{"type":"string"}},"required":["view_id","offset","comment"]}},
  {"name":"apply_sdk_class","description":"Apply an SDK class layout to a view, replacing all nodes with typed SDK properties.",
   "inputSchema":{"type":"object","properties":{"view_id":{"type":"integer"},"class_name":{"type":"string","description":"SDK class name"}},"required":["view_id","class_name"]}},
  {"name":"expand_pointer","description":"Toggle expand/collapse of a Pointer node, reading the target memory.",
   "inputSchema":{"type":"object","properties":{"view_id":{"type":"integer"},"offset":{"type":"integer"}},"required":["view_id","offset"]}},
  {"name":"list_sdk_classes","description":"List available SDK class names, optionally filtered.",
   "inputSchema":{"type":"object","properties":{"filter":{"type":"string","description":"Optional substring filter"}}}},
  {"name":"get_sdk_class","description":"Get full SDK class definition with all properties (including inherited).",
   "inputSchema":{"type":"object","properties":{"name":{"type":"string","description":"Class name"}},"required":["name"]}},
  {"name":"follow_pointer_chain","description":"Follow a chain of pointer dereferences from a base address through a list of offsets. Returns the final address and value.",
   "inputSchema":{"type":"object","properties":{"base":{"type":"string","description":"Starting address"},"offsets":{"type":"array","items":{"type":"integer"},"description":"List of offsets to dereference through"}},"required":["base","offsets"]}},
  {"name":"read_struct","description":"Read memory at an address and interpret it using an SDK class layout. Returns all fields with hex and typed values.",
   "inputSchema":{"type":"object","properties":{"addr":{"type":"string","description":"Memory address"},"class_name":{"type":"string","description":"SDK class name to use as layout"}},"required":["addr","class_name"]}},
  {"name":"scan_pattern","description":"Scan executable regions of the target process for a byte pattern. Pattern uses hex bytes with ?? wildcards (e.g. '48 8B 05 ?? ?? ?? ??'). Returns match addresses, RVAs, and surrounding bytes for context.",
   "inputSchema":{"type":"object","properties":{"pattern":{"type":"string","description":"Hex bytes with ?? wildcards, e.g. '48 8B 05 ?? ?? ?? ??'"},"context":{"type":"integer","description":"Bytes of context to show before/after match (default 24)","default":24},"max_results":{"type":"integer","description":"Max number of matches to return (default 20)","default":20}},"required":["pattern"]}},
  {"name":"attach","description":"Attach the inspector to a process by PID. Does not save to config; use Process -> Attach in the UI with Auto-connect to persist. Returns ok and pid on success.",
   "inputSchema":{"type":"object","properties":{"pid":{"type":"integer","description":"Process ID to attach to"}},"required":["pid"]}}
])JSON";

// ── Tool call dispatch ───────────────────────────────────────────────────────

std::string InspectorMCP::dispatch_tool(const std::string& name, const std::string& args) {
  if (name == "read_memory") {
    uintptr_t addr = static_cast<uintptr_t>(find_json_int(args, "addr"));
    size_t size = static_cast<size_t>(find_json_int(args, "size", 64));
    if (addr == 0) return "{\"error\":\"addr required\"}";

    auto result = inspector_.mcp_read_memory(addr, size);
    std::ostringstream os;
    os << "{\"addr\":\"0x" << std::hex << result.addr << std::dec << "\",\"size\":" << result.data.size() << ",\"hex\":\"";
    for (auto b : result.data) { char h[4]; snprintf(h, sizeof(h), "%02X", b); os << h; }
    os << "\"";
    if (result.data.size() >= 4) {
      float fv; std::memcpy(&fv, result.data.data(), 4);
      uint32_t u32; std::memcpy(&u32, result.data.data(), 4);
      int32_t i32; std::memcpy(&i32, result.data.data(), 4);
      os << ",\"as_float\":" << (std::isfinite(fv) ? std::to_string(fv) : "null")
         << ",\"as_u32\":" << u32 << ",\"as_i32\":" << i32;
    }
    if (result.data.size() >= 8) {
      double dv; std::memcpy(&dv, result.data.data(), 8);
      uint64_t u64; std::memcpy(&u64, result.data.data(), 8);
      os << ",\"as_double\":" << (std::isfinite(dv) ? std::to_string(dv) : "null")
         << ",\"as_u64\":" << u64
         << ",\"as_ptr\":\"0x" << std::hex << u64 << std::dec << "\"";
    }
    os << "}";
    return os.str();

  } else if (name == "read_string") {
    uintptr_t addr = static_cast<uintptr_t>(find_json_int(args, "addr"));
    size_t max_len = static_cast<size_t>(find_json_int(args, "max_len", 256));
    auto s = inspector_.mcp_read_string(addr, max_len);
    return "{\"value\":\"" + json_escape_mcp(s) + "\"}";

  } else if (name == "open_view") {
    uintptr_t addr = static_cast<uintptr_t>(find_json_int(args, "addr"));
    std::string label = find_json_string(args, "label");
    uint32_t size = static_cast<uint32_t>(find_json_int(args, "size", 0x200));
    int vid = inspector_.mcp_open_view(addr, label, size);
    return "{\"view_id\":" + std::to_string(vid) + "}";

  } else if (name == "close_view") {
    int vid = static_cast<int>(find_json_int(args, "view_id"));
    inspector_.mcp_close_view(vid);
    return "{\"ok\":true}";

  } else if (name == "list_views") {
    auto views = inspector_.mcp_list_views();
    std::ostringstream os;
    os << "{\"views\":[";
    for (size_t i = 0; i < views.size(); ++i) {
      if (i > 0) os << ",";
      os << "{\"id\":" << views[i].first << ",\"name\":\"" << json_escape_mcp(views[i].second) << "\"}";
    }
    os << "]}";
    return os.str();

  } else if (name == "get_view") {
    int vid = static_cast<int>(find_json_int(args, "view_id"));
    return inspector_.mcp_get_view_info(vid);

  } else if (name == "set_node_type") {
    int vid = static_cast<int>(find_json_int(args, "view_id"));
    uint32_t offset = static_cast<uint32_t>(find_json_int(args, "offset"));
    std::string type = find_json_string(args, "type");
    inspector_.mcp_set_node_type(vid, offset, type);
    return "{\"ok\":true}";

  } else if (name == "set_node_name") {
    int vid = static_cast<int>(find_json_int(args, "view_id"));
    uint32_t offset = static_cast<uint32_t>(find_json_int(args, "offset"));
    std::string n = find_json_string(args, "name");
    inspector_.mcp_set_node_name(vid, offset, n);
    return "{\"ok\":true}";

  } else if (name == "set_node_comment") {
    int vid = static_cast<int>(find_json_int(args, "view_id"));
    uint32_t offset = static_cast<uint32_t>(find_json_int(args, "offset"));
    std::string comment = find_json_string(args, "comment");
    inspector_.mcp_set_node_comment(vid, offset, comment);
    return "{\"ok\":true}";

  } else if (name == "apply_sdk_class") {
    int vid = static_cast<int>(find_json_int(args, "view_id"));
    std::string class_name = find_json_string(args, "class_name");
    inspector_.mcp_apply_sdk_class(vid, class_name);
    return "{\"ok\":true}";

  } else if (name == "expand_pointer") {
    int vid = static_cast<int>(find_json_int(args, "view_id"));
    uint32_t offset = static_cast<uint32_t>(find_json_int(args, "offset"));
    inspector_.mcp_expand_pointer(vid, offset);
    return "{\"ok\":true}";

  } else if (name == "list_sdk_classes") {
    std::string filter = find_json_string(args, "filter");
    auto classes = inspector_.mcp_list_sdk_classes(filter);
    std::ostringstream os;
    os << "{\"count\":" << classes.size() << ",\"classes\":[";
    for (size_t i = 0; i < classes.size(); ++i) {
      if (i > 0) os << ",";
      os << "\"" << json_escape_mcp(classes[i]) << "\"";
    }
    os << "]}";
    return os.str();

  } else if (name == "get_sdk_class") {
    std::string n = find_json_string(args, "name");
    return inspector_.mcp_get_sdk_class(n);

  } else if (name == "follow_pointer_chain") {
    uintptr_t base = static_cast<uintptr_t>(find_json_int(args, "base"));
    std::string offsets_arr = find_json_array(args, "offsets");
    auto offsets = parse_int_array(offsets_arr);
    return inspector_.mcp_follow_pointer_chain(base, offsets);

  } else if (name == "read_struct") {
    uintptr_t addr = static_cast<uintptr_t>(find_json_int(args, "addr"));
    std::string class_name = find_json_string(args, "class_name");
    return inspector_.mcp_read_struct(addr, class_name);

  } else if (name == "scan_pattern") {
    std::string pat = find_json_string(args, "pattern");
    int context = static_cast<int>(find_json_int(args, "context", 24));
    int max_res = static_cast<int>(find_json_int(args, "max_results", 20));
    if (pat.empty()) return "{\"error\":\"pattern required\"}";
    return inspector_.mcp_scan_pattern(pat, context, max_res);

  } else if (name == "attach") {
    int pid = static_cast<int>(find_json_int(args, "pid"));
    if (pid <= 0) return "{\"ok\":false,\"error\":\"pid required (positive integer)\"}";
    if (inspector_.attach(pid))
      return "{\"ok\":true,\"pid\":" + std::to_string(pid) + "}";
    return "{\"ok\":false,\"error\":\"failed to attach to pid " + std::to_string(pid) + "\"}";
  }

  return "{\"error\":\"Unknown tool: " + json_escape_mcp(name) + "\"}";
}

// ── MCP protocol handler ─────────────────────────────────────────────────────

void InspectorMCP::handle_request(int client_fd, const std::string& line) {
  std::string id = find_json_string(line, "id");
  std::string method = find_json_string(line, "method");
  std::string params = find_json_object(line, "params");

  std::string id_json;
  if (id.empty()) {
    id_json = "null";
  } else {
    bool is_num = true;
    for (char c : id) {
      if (!isdigit(c) && c != '-') { is_num = false; break; }
    }
    id_json = is_num ? id : ("\"" + json_escape_mcp(id) + "\"");
  }

  if (method == "notifications/initialized" || method == "notifications/cancelled") {
    return;
  }

  if (method.empty()) {
    send_response(client_fd, make_error(id_json, -32600, "Invalid request: no method"));
    return;
  }

  if (method == "initialize") {
    std::string resp = make_result(id_json,
      "{\"protocolVersion\":\"2024-11-05\","
      "\"capabilities\":{\"tools\":{},\"resources\":{},\"prompts\":{}},"
      "\"serverInfo\":{\"name\":\"inspector\",\"version\":\"1.0.0\"}}");
    send_response(client_fd, resp);

  } else if (method == "tools/list") {
    std::string resp = make_result(id_json, std::string("{\"tools\":") + kToolDefs + "}");
    send_response(client_fd, resp);

  } else if (method == "resources/list") {
    send_response(client_fd, make_result(id_json, "{\"resources\":[]}"));

  } else if (method == "resources/templates/list") {
    send_response(client_fd, make_result(id_json, "{\"resourceTemplates\":[]}"));

  } else if (method == "prompts/list") {
    send_response(client_fd, make_result(id_json, "{\"prompts\":[]}"));

  } else if (method == "completion/complete") {
    send_response(client_fd, make_result(id_json, "{\"completion\":{\"values\":[]}}"));

  } else if (method == "tools/call") {
    std::string tool_name = find_json_string(params, "name");
    std::string arguments = find_json_object(params, "arguments");

    std::string tool_result;
    try {
      tool_result = dispatch_tool(tool_name, arguments);
    } catch (const std::exception& e) {
      tool_result = "{\"error\":\"" + json_escape_mcp(std::string("Exception: ") + e.what()) + "\"}";
      std::cerr << "[mcp] Tool '" << tool_name << "' threw: " << e.what() << "\n";
    } catch (...) {
      tool_result = "{\"error\":\"Unknown exception in tool dispatch\"}";
      std::cerr << "[mcp] Tool '" << tool_name << "' threw unknown exception\n";
    }

    std::string resp = make_result(id_json,
      "{\"content\":[{\"type\":\"text\",\"text\":\"" +
      json_escape_mcp(tool_result) + "\"}]}");
    send_response(client_fd, resp);

  } else if (method == "ping") {
    send_response(client_fd, make_result(id_json, "{}"));

  } else {
    std::cerr << "[mcp] Unknown method: " << method << "\n";
    send_response(client_fd, make_result(id_json, "{}"));
  }
}

void InspectorMCP::handle_client(int client_fd) {
  std::cerr << "[mcp] Client connected (fd=" << client_fd << ")\n";

  int flag = 1;
  setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
  setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));

  std::string buf;
  char chunk[4096];
  while (running_.load()) {
    struct pollfd pfd;
    pfd.fd = client_fd;
    pfd.events = POLLIN;

    int ret = poll(&pfd, 1, 2000);
    if (ret < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (ret == 0) continue;

    if (pfd.revents & (POLLIN | POLLHUP | POLLERR)) {
      ssize_t n = read(client_fd, chunk, sizeof(chunk));
      if (n <= 0) break;
      buf.append(chunk, n);

      size_t pos;
      while ((pos = buf.find('\n')) != std::string::npos) {
        std::string line = buf.substr(0, pos);
        buf.erase(0, pos + 1);

        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line.find_first_not_of(" \t") == std::string::npos)
          continue;

        handle_request(client_fd, line);
      }
    }
  }

  close(client_fd);
  std::cerr << "[mcp] Client disconnected (fd=" << client_fd << ")\n";
}

void InspectorMCP::run() {
  listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd_ < 0) {
    std::cerr << "[mcp] socket() failed: " << strerror(errno) << "\n";
    return;
  }

  int opt = 1;
  setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  addr.sin_port = htons(port_);

  if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    std::cerr << "[mcp] bind() port " << port_ << " failed: " << strerror(errno) << "\n";
    close(listen_fd_);
    listen_fd_ = -1;
    return;
  }

  if (listen(listen_fd_, 4) < 0) {
    std::cerr << "[mcp] listen() failed: " << strerror(errno) << "\n";
    close(listen_fd_);
    listen_fd_ = -1;
    return;
  }

  std::cerr << "[mcp] Inspector MCP server listening on 127.0.0.1:" << port_ << "\n";

  while (running_.load()) {
    struct pollfd pfd;
    pfd.fd = listen_fd_;
    pfd.events = POLLIN;
    int ret = poll(&pfd, 1, 1000);
    if (ret < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (ret == 0) continue;

    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(listen_fd_, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
    if (client_fd < 0) {
      if (running_.load())
        std::cerr << "[mcp] accept() failed: " << strerror(errno) << "\n";
      continue;
    }

    {
      std::lock_guard lock(clients_mu_);
      std::vector<std::thread> alive;
      for (auto& t : client_threads_) {
        if (t.joinable()) {
          alive.push_back(std::move(t));
        }
      }
      client_threads_ = std::move(alive);
    }

    std::lock_guard lock(clients_mu_);
    client_threads_.emplace_back([this, client_fd]() {
      handle_client(client_fd);
    });
  }

  if (listen_fd_ >= 0) {
    close(listen_fd_);
    listen_fd_ = -1;
  }
  {
    std::lock_guard lock(clients_mu_);
    for (auto& t : client_threads_) {
      if (t.joinable()) t.join();
    }
    client_threads_.clear();
  }
  std::cerr << "[mcp] Inspector MCP server stopped\n";
}
