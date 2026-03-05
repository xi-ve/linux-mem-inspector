#include "inspector/config.hpp"
#include "inspector/inspector.hpp"

#include "shared/memory/memory_map.hpp"
#include "shared/process/process_finder.hpp"
#include "shared/memory/mem_helpers.hpp"
#include "shared/scanner/pattern_scanner.hpp"

#include "imgui.h"
#include "imgui_impl_sdl2.h"
#include "imgui_impl_opengl3.h"

#include <SDL.h>
#include <GL/gl.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <shared_mutex>
#include <sstream>

using namespace raider;

// ── ReClassEx color scheme (dark) ─────────────────────────────────────────────

static const ImVec4 kColorOffset(1.0f, 0.2f, 0.2f, 1.0f);
static const ImVec4 kColorAddress(0.0f, 0.8f, 0.0f, 1.0f);
static const ImVec4 kColorType(0.3f, 0.5f, 1.0f, 1.0f);
static const ImVec4 kColorName(0.5f, 0.5f, 0.9f, 1.0f);
static const ImVec4 kColorValue(0.6f, 0.6f, 0.6f, 1.0f);
static const ImVec4 kColorHex(0.5f, 0.5f, 0.5f, 1.0f);
static const ImVec4 kColorComment(0.0f, 0.8f, 0.0f, 1.0f);
static const ImVec4 kColorPointer(1.0f, 0.0f, 0.0f, 1.0f);
static const ImVec4 kColorChanged(1.0f, 1.0f, 0.0f, 1.0f);
static const ImVec4 kColorAscii(0.7f, 0.7f, 0.2f, 1.0f);
static const ImVec4 kColorTypedValue(1.0f, 0.6f, 0.0f, 1.0f);

// ── NodeType helpers ─────────────────────────────────────────────────────────

int raider::node_size(NodeType t) {
  switch (t) {
    case NodeType::Hex8: case NodeType::Int8: case NodeType::UInt8: case NodeType::Bool: return 1;
    case NodeType::Hex16: case NodeType::Int16: case NodeType::UInt16: return 2;
    case NodeType::Hex32: case NodeType::Int32: case NodeType::UInt32: case NodeType::Float: return 4;
    case NodeType::Hex64: case NodeType::Int64: case NodeType::UInt64: case NodeType::Double: case NodeType::Pointer: return 8;
    case NodeType::UTF8Text: case NodeType::UTF16Text: return 8;
    case NodeType::Vec3: return 12;
  }
  return 8;
}

const char* raider::node_type_name(NodeType t) {
  switch (t) {
    case NodeType::Hex8: return "Hex8";
    case NodeType::Hex16: return "Hex16";
    case NodeType::Hex32: return "Hex32";
    case NodeType::Hex64: return "Hex64";
    case NodeType::Int8: return "Int8";
    case NodeType::Int16: return "Int16";
    case NodeType::Int32: return "Int32";
    case NodeType::Int64: return "Int64";
    case NodeType::UInt8: return "UInt8";
    case NodeType::UInt16: return "UInt16";
    case NodeType::UInt32: return "UInt32";
    case NodeType::UInt64: return "UInt64";
    case NodeType::Float: return "Float";
    case NodeType::Double: return "Double";
    case NodeType::Bool: return "Bool";
    case NodeType::Pointer: return "Pointer";
    case NodeType::UTF8Text: return "UTF8Text";
    case NodeType::UTF16Text: return "UTF16Text";
    case NodeType::Vec3: return "Vec3";
  }
  return "Hex64";
}

NodeType raider::node_type_from_name(const char* name) {
  if (!name) return NodeType::Hex64;
  std::string s(name);
  if (s == "Hex8") return NodeType::Hex8;
  if (s == "Hex16") return NodeType::Hex16;
  if (s == "Hex32") return NodeType::Hex32;
  if (s == "Hex64") return NodeType::Hex64;
  if (s == "Int8") return NodeType::Int8;
  if (s == "Int16") return NodeType::Int16;
  if (s == "Int32") return NodeType::Int32;
  if (s == "Int64") return NodeType::Int64;
  if (s == "UInt8") return NodeType::UInt8;
  if (s == "UInt16") return NodeType::UInt16;
  if (s == "UInt32") return NodeType::UInt32;
  if (s == "UInt64") return NodeType::UInt64;
  if (s == "Float") return NodeType::Float;
  if (s == "Double") return NodeType::Double;
  if (s == "Bool") return NodeType::Bool;
  if (s == "Pointer") return NodeType::Pointer;
  if (s == "UTF8Text") return NodeType::UTF8Text;
  if (s == "UTF16Text") return NodeType::UTF16Text;
  if (s == "Vec3") return NodeType::Vec3;
  return NodeType::Hex64;
}

// ── Rendering helpers ────────────────────────────────────────────────────────

static bool looks_like_pointer(uint64_t val) {
  if (val == 0) return false;
  return (val >= 0x10000ULL && val < 0x800000000000ULL);
}

static void ascii_preview(char* out, const uint8_t* raw, int count) {
  for (int i = 0; i < count; ++i)
    out[i] = (raw[i] >= 0x20 && raw[i] < 0x7F) ? static_cast<char>(raw[i]) : '.';
  out[count] = '\0';
}

// ── JSON parsing helpers (minimal, for sdk_dump.json) ────────────────────────

static std::string json_str_value(const std::string& line, const std::string& key) {
  auto pos = line.find("\"" + key + "\"");
  if (pos == std::string::npos) return {};
  pos = line.find(':', pos);
  if (pos == std::string::npos) return {};
  auto q1 = line.find('"', pos + 1);
  if (q1 == std::string::npos) return {};
  auto q2 = line.find('"', q1 + 1);
  if (q2 == std::string::npos) return {};
  return line.substr(q1 + 1, q2 - q1 - 1);
}

static uint32_t json_uint_value(const std::string& line, const std::string& key) {
  auto pos = line.find("\"" + key + "\"");
  if (pos == std::string::npos) return 0;
  pos = line.find(':', pos);
  if (pos == std::string::npos) return 0;
  pos = line.find_first_of("0123456789", pos);
  if (pos == std::string::npos) return 0;
  return static_cast<uint32_t>(std::stoul(line.substr(pos)));
}

// ── JSON string escaping ────────────────────────────────────────────────────

static std::string json_escape(const std::string& s) {
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

Inspector::Inspector(int pid)
    : pid_(pid) {
  if (pid > 0) attach(pid);
}

bool Inspector::attach(int pid) {
  if (pid <= 0) return false;
  detach();
  reader_ = std::make_unique<MemoryReader>(pid, ReadMethod::KernelMem);
  if (reader_->attach()) {
    std::cerr << "[inspector] Attached to " << pid << " (kernel module)\n";
    pid_ = pid;
    return true;
  }
  reader_ = std::make_unique<MemoryReader>(pid, ReadMethod::ProcessVm);
  if (reader_->attach()) {
    std::cerr << "[inspector] Attached to " << pid << " (process_vm_readv)\n";
    pid_ = pid;
    return true;
  }
  std::cerr << "[inspector] Failed to attach to pid " << pid << "\n";
  reader_.reset();
  return false;
}

void Inspector::detach() {
  reader_.reset();
  pid_ = 0;
}

// Load sdk_offsets.json format
static bool load_sdk_offsets(const std::string& path,
                              std::unordered_map<std::string, SDKClass>& classes) {
  std::ifstream f(path);
  if (!f.is_open()) return false;

  std::string content((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());

  auto classes_pos = content.find("\"classes\"");
  if (classes_pos == std::string::npos) return false;

  enum State { SEEK_CLASS_NAME, IN_CLASS, IN_PROPERTIES, IN_PROP };
  State state = SEEK_CLASS_NAME;

  SDKClass current;
  FlatProperty current_prop;
  bool in_properties_block = false;

  std::istringstream ss(content.substr(classes_pos));
  std::string line;
  while (std::getline(ss, line)) {
    size_t start = line.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) continue;
    std::string trimmed = line.substr(start);

    if (state == SEEK_CLASS_NAME) {
      if (trimmed.size() > 3 && trimmed[0] == '"') {
        auto end_quote = trimmed.find('"', 1);
        if (end_quote != std::string::npos && trimmed.find('{', end_quote) != std::string::npos) {
          std::string name = trimmed.substr(1, end_quote - 1);
          if (name == "classes" || name == "layout" || name == "version" || name == "exe_size")
            continue;
          current = {};
          current.name = name;
          state = IN_CLASS;
          in_properties_block = false;
        }
      }
    } else if (state == IN_CLASS && !in_properties_block) {
      if (trimmed.find("\"super\"") != std::string::npos)
        current.parent = json_str_value(line, "super");
      else if (trimmed.find("\"size\"") != std::string::npos)
        current.size = json_uint_value(line, "size");
      else if (trimmed.find("\"properties\"") != std::string::npos) {
        in_properties_block = true;
        state = IN_PROPERTIES;
      }
      else if (trimmed[0] == '}') {
        if (!current.name.empty())
          classes[current.name] = current;
        state = SEEK_CLASS_NAME;
      }
    } else if (state == IN_PROPERTIES) {
      if (trimmed[0] == '}') {
        in_properties_block = false;
        state = IN_CLASS;
      } else if (trimmed[0] == '"') {
        auto end_quote = trimmed.find('"', 1);
        if (end_quote != std::string::npos) {
          current_prop = {};
          current_prop.name = trimmed.substr(1, end_quote - 1);
          current_prop.class_name = current.name;
          state = IN_PROP;
        }
      }
    } else if (state == IN_PROP) {
      if (trimmed.find("\"type\"") != std::string::npos)
        current_prop.type_name = json_str_value(line, "type");
      else if (trimmed.find("\"offset\"") != std::string::npos)
        current_prop.offset = json_uint_value(line, "offset");
      else if (trimmed.find("\"size\"") != std::string::npos)
        current_prop.element_size = json_uint_value(line, "size");
      else if (trimmed[0] == '}') {
        current.props.push_back(current_prop);
        state = IN_PROPERTIES;
      }
    }
  }

  return !classes.empty();
}

// Load sdk_dump.json format
static bool load_sdk_dump(const std::string& path,
                           std::unordered_map<std::string, SDKClass>& classes) {
  std::ifstream f(path);
  if (!f.is_open()) return false;

  std::string content((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());

  SDKClass current;
  FlatProperty current_prop;
  bool in_classes = false, in_class = false, in_props = false, in_prop = false;

  std::istringstream ss(content);
  std::string line;
  while (std::getline(ss, line)) {
    size_t start = line.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) continue;
    std::string trimmed = line.substr(start);

    if (!in_classes) {
      if (trimmed[0] == '[') in_classes = true;
      continue;
    }
    if (!in_class) {
      if (trimmed[0] == '{') { in_class = true; current = {}; }
      continue;
    }
    if (!in_props && !in_prop) {
      if (trimmed.find("\"name\"") != std::string::npos)
        current.name = json_str_value(line, "name");
      else if (trimmed.find("\"parent\"") != std::string::npos)
        current.parent = json_str_value(line, "parent");
      else if (trimmed.find("\"size\"") != std::string::npos)
        current.size = json_uint_value(line, "size");
      else if (trimmed.find("\"props\"") != std::string::npos)
        in_props = true;
      else if (trimmed[0] == '}') {
        in_class = false;
        if (!current.name.empty()) classes[current.name] = current;
      }
      continue;
    }
    if (in_props && !in_prop) {
      if (trimmed[0] == '{') { in_prop = true; current_prop = {}; }
      else if (trimmed[0] == ']') in_props = false;
      continue;
    }
    if (in_prop) {
      if (trimmed.find("\"name\"") != std::string::npos)
        current_prop.name = json_str_value(line, "name");
      else if (trimmed.find("\"type\"") != std::string::npos)
        current_prop.type_name = json_str_value(line, "type");
      else if (trimmed.find("\"class\"") != std::string::npos)
        current_prop.class_name = json_str_value(line, "class");
      else if (trimmed.find("\"offset\"") != std::string::npos)
        current_prop.offset = json_uint_value(line, "offset");
      else if (trimmed.find("\"size\"") != std::string::npos)
        current_prop.element_size = json_uint_value(line, "size");
      else if (trimmed[0] == '}') {
        in_prop = false;
        current.props.push_back(current_prop);
      }
    }
  }
  return !classes.empty();
}

void Inspector::load_sdk() {
  const char* home = getenv("HOME");
  if (!home) return;
  std::string base = std::string(home) + "/.config/raider/";

  if (load_sdk_dump(base + "sdk_dump.json", classes_)) {
    std::cerr << "[inspector] Loaded " << classes_.size() << " SDK classes from sdk_dump.json\n";
  } else if (load_sdk_offsets(base + "sdk_offsets.json", classes_)) {
    std::cerr << "[inspector] Loaded " << classes_.size() << " SDK classes from sdk_offsets.json\n";
  } else {
    std::cerr << "[inspector] No SDK dump found in " << base << "\n";
    return;
  }

  class_names_.reserve(classes_.size());
  for (auto& [name, _] : classes_)
    class_names_.push_back(name);
  std::sort(class_names_.begin(), class_names_.end());
}

std::vector<FlatProperty> Inspector::flatten_class(const std::string& name) const {
  std::vector<FlatProperty> result;
  std::vector<std::string> chain;

  std::string cur = name;
  while (!cur.empty()) {
    chain.push_back(cur);
    auto it = classes_.find(cur);
    if (it == classes_.end()) break;
    cur = it->second.parent;
  }

  for (int i = static_cast<int>(chain.size()) - 1; i >= 0; --i) {
    auto it = classes_.find(chain[i]);
    if (it == classes_.end()) continue;
    bool inherited = (chain[i] != name);
    for (auto& p : it->second.props) {
      FlatProperty fp = p;
      fp.class_name = chain[i];
      fp.inherited = inherited;
      result.push_back(fp);
    }
  }

  std::sort(result.begin(), result.end(),
            [](const FlatProperty& a, const FlatProperty& b) { return a.offset < b.offset; });
  return result;
}

void Inspector::refresh_view(ClassView& v) {
  if (!reader_ || !reader_->is_attached()) return;
  v.prev_buffer = v.buffer;
  v.buffer.resize(v.size);
  auto data = reader_->read(v.base_address, v.size);
  if (data) {
    v.buffer = std::move(*data);
  } else {
    std::fill(v.buffer.begin(), v.buffer.end(), 0);
  }
}

std::vector<MemoryNode> Inspector::make_default_nodes(uint32_t size) {
  std::vector<MemoryNode> nodes;
  for (uint32_t off = 0; off + 8 <= size; off += 8) {
    MemoryNode n;
    n.type = NodeType::Hex64;
    n.offset = off;
    char buf[16];
    snprintf(buf, sizeof(buf), "field_%04X", off);
    n.name = buf;
    nodes.push_back(std::move(n));
  }
  uint32_t remainder = size % 8;
  if (remainder > 0) {
    uint32_t off = size - remainder;
    for (uint32_t i = 0; i < remainder; ++i) {
      MemoryNode n;
      n.type = NodeType::Hex8;
      n.offset = off + i;
      char buf[16];
      snprintf(buf, sizeof(buf), "field_%04X", off + i);
      n.name = buf;
      nodes.push_back(std::move(n));
    }
  }
  return nodes;
}

std::vector<MemoryNode> Inspector::make_sdk_nodes(const std::string& class_name) {
  auto flat = flatten_class(class_name);
  if (flat.empty()) return {};

  auto cit = classes_.find(class_name);
  uint32_t total_size = (cit != classes_.end() && cit->second.size > 0) ? cit->second.size : 0x200;

  std::vector<MemoryNode> nodes;
  uint32_t cursor = 0;

  for (auto& p : flat) {
    while (cursor < p.offset) {
      MemoryNode gap;
      gap.type = NodeType::Hex8;
      gap.offset = cursor;
      char buf[16];
      snprintf(buf, sizeof(buf), "pad_%04X", cursor);
      gap.name = buf;
      nodes.push_back(std::move(gap));
      ++cursor;
    }

    MemoryNode n;
    n.offset = p.offset;
    n.name = p.name;
    if (p.inherited)
      n.comment = "inherited from " + p.class_name;

    auto& tn = p.type_name;
    if (tn.find("Bool") != std::string::npos) {
      n.type = NodeType::Bool;
    } else if (tn.find("Double") != std::string::npos) {
      n.type = NodeType::Double;
    } else if (tn.find("Float") != std::string::npos) {
      if (p.element_size == 8) n.type = NodeType::Double;
      else n.type = NodeType::Float;
    } else if (tn.find("Int64") != std::string::npos || tn.find("int64") != std::string::npos) {
      n.type = NodeType::Int64;
    } else if (tn.find("Int") != std::string::npos || tn.find("Byte") != std::string::npos) {
      if (p.element_size == 1) n.type = NodeType::UInt8;
      else if (p.element_size == 2) n.type = NodeType::Int16;
      else if (p.element_size == 4) n.type = NodeType::Int32;
      else if (p.element_size == 8) n.type = NodeType::Int64;
      else n.type = NodeType::Hex32;
    } else if (tn.find("Object") != std::string::npos || tn.find("Ptr") != std::string::npos ||
               tn.find("Class") != std::string::npos || tn.find("Interface") != std::string::npos) {
      n.type = NodeType::Pointer;
    } else if (tn.find("Str") != std::string::npos || tn.find("Name") != std::string::npos ||
               tn.find("Text") != std::string::npos) {
      n.type = NodeType::Pointer;
    } else if (p.element_size == 12) {
      n.type = NodeType::Vec3;
    } else if (p.element_size == 8) {
      n.type = NodeType::Hex64;
    } else if (p.element_size == 4) {
      n.type = NodeType::Hex32;
    } else if (p.element_size == 2) {
      n.type = NodeType::Hex16;
    } else if (p.element_size == 1) {
      n.type = NodeType::Hex8;
    } else {
      int ns = node_size(NodeType::Hex64);
      uint32_t end = p.offset + p.element_size;
      for (uint32_t o = p.offset; o + ns <= end; o += ns) {
        MemoryNode chunk;
        chunk.type = NodeType::Hex64;
        chunk.offset = o;
        if (o == p.offset)
          chunk.name = p.name;
        else {
          char buf[16];
          snprintf(buf, sizeof(buf), "%s+%X", p.name.c_str(), o - p.offset);
          chunk.name = buf;
        }
        if (p.inherited) chunk.comment = "inherited from " + p.class_name;
        nodes.push_back(std::move(chunk));
      }
      cursor = p.offset + p.element_size;
      continue;
    }

    nodes.push_back(std::move(n));
    cursor = p.offset + node_size(nodes.back().type);
    if (p.element_size > static_cast<uint32_t>(node_size(nodes.back().type))) {
      uint32_t end = p.offset + p.element_size;
      while (cursor < end) {
        MemoryNode extra;
        extra.type = NodeType::Hex8;
        extra.offset = cursor;
        char buf[24];
        snprintf(buf, sizeof(buf), "%s+%X", p.name.c_str(), cursor - p.offset);
        extra.name = buf;
        nodes.push_back(std::move(extra));
        ++cursor;
      }
    }
  }

  while (cursor < total_size) {
    MemoryNode pad;
    if (cursor + 8 <= total_size) {
      pad.type = NodeType::Hex64;
      char buf[16]; snprintf(buf, sizeof(buf), "field_%04X", cursor);
      pad.name = buf;
      pad.offset = cursor;
      cursor += 8;
    } else {
      pad.type = NodeType::Hex8;
      char buf[16]; snprintf(buf, sizeof(buf), "field_%04X", cursor);
      pad.name = buf;
      pad.offset = cursor;
      cursor += 1;
    }
    nodes.push_back(std::move(pad));
  }

  return nodes;
}

ClassView* Inspector::find_view(int id) {
  for (auto& v : views_)
    if (v.id == id) return &v;
  return nullptr;
}

// ── Rendering ────────────────────────────────────────────────────────────────

void Inspector::render_pointer_children(ClassView& v, MemoryNode& ptr_node, uintptr_t target_addr,
                                        int depth, int id_base) {
  if (depth > 10) return;

  uint32_t child_max = 0x100;
  for (const auto& c : ptr_node.children) {
    uint32_t end = c.offset + node_size(c.type);
    if (end > child_max) child_max = end;
  }
  if (!reader_ || !reader_->is_attached()) return;
  auto child_data = reader_->read(target_addr, child_max);
  if (!child_data) return;
  std::vector<uint8_t> child_buf = std::move(*child_data);

  for (int ci = 0; ci < static_cast<int>(ptr_node.children.size()); ++ci) {
    auto& child = ptr_node.children[ci];
    int child_ns = node_size(child.type);
    bool child_in_bounds = (child.offset + child_ns <= child_buf.size());
    const uint8_t* child_raw = child_in_bounds ? &child_buf[child.offset] : nullptr;

    int child_gid = id_base + ci;
    ImGui::PushID(child_gid);

    ImVec2 ccur = ImGui::GetCursorPos();
    char csel[32]; snprintf(csel, sizeof(csel), "##crow_%d", child_gid);
    ImGui::Selectable(csel, false,
        ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
        ImVec2(0, ImGui::GetTextLineHeight()));

    char cctx[32]; snprintf(cctx, sizeof(cctx), "cctx_%d", child_gid);
    if (ImGui::BeginPopupContextItem(cctx)) {
      if (ImGui::BeginMenu("Hex")) {
        if (ImGui::MenuItem("Hex8"))  child.type = NodeType::Hex8;
        if (ImGui::MenuItem("Hex16")) child.type = NodeType::Hex16;
        if (ImGui::MenuItem("Hex32")) child.type = NodeType::Hex32;
        if (ImGui::MenuItem("Hex64")) child.type = NodeType::Hex64;
        ImGui::EndMenu();
      }
      if (ImGui::BeginMenu("Signed")) {
        if (ImGui::MenuItem("Int8"))  child.type = NodeType::Int8;
        if (ImGui::MenuItem("Int16")) child.type = NodeType::Int16;
        if (ImGui::MenuItem("Int32")) child.type = NodeType::Int32;
        if (ImGui::MenuItem("Int64")) child.type = NodeType::Int64;
        ImGui::EndMenu();
      }
      if (ImGui::BeginMenu("Unsigned")) {
        if (ImGui::MenuItem("UInt8"))  child.type = NodeType::UInt8;
        if (ImGui::MenuItem("UInt16")) child.type = NodeType::UInt16;
        if (ImGui::MenuItem("UInt32")) child.type = NodeType::UInt32;
        if (ImGui::MenuItem("UInt64")) child.type = NodeType::UInt64;
        ImGui::EndMenu();
      }
      if (ImGui::BeginMenu("Float")) {
        if (ImGui::MenuItem("Float"))  child.type = NodeType::Float;
        if (ImGui::MenuItem("Double")) child.type = NodeType::Double;
        ImGui::EndMenu();
      }
      if (ImGui::MenuItem("Bool"))    child.type = NodeType::Bool;
      if (ImGui::MenuItem("Pointer")) child.type = NodeType::Pointer;
      if (ImGui::BeginMenu("Text")) {
        if (ImGui::MenuItem("UTF8"))  child.type = NodeType::UTF8Text;
        if (ImGui::MenuItem("UTF16")) child.type = NodeType::UTF16Text;
        ImGui::EndMenu();
      }
      if (ImGui::MenuItem("Vec3")) child.type = NodeType::Vec3;
      ImGui::Separator();
      if (ImGui::MenuItem("Rename")) {
        v.editing_node = child_gid;
        snprintf(v.edit_buf, sizeof(v.edit_buf), "%s", child.name.c_str());
      }
      if (ImGui::MenuItem("Add Comment")) {
        v.editing_comment_node = child_gid;
        v.edit_buf[0] = '\0';
      }
      ImGui::Separator();
      if (ImGui::MenuItem("Extend (+0x80 bytes)")) {
        uint32_t last_end = 0;
        for (auto& c : ptr_node.children) {
          uint32_t end = c.offset + node_size(c.type);
          if (end > last_end) last_end = end;
        }
        uint32_t new_end = last_end + 0x80;
        uint32_t cursor = last_end;
        while (cursor + 8 <= new_end) {
          MemoryNode n;
          n.type = NodeType::Hex64;
          n.offset = cursor;
          char buf[16]; snprintf(buf, sizeof(buf), "field_%04X", cursor);
          n.name = buf;
          ptr_node.children.push_back(std::move(n));
          cursor += 8;
        }
      }
      ImGui::EndPopup();
    }

    ImGui::SetCursorPos(ccur);

    float child_indent = depth * 20.0f;
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + child_indent);

    if (child.type == NodeType::Pointer) {
      char arrow[32]; snprintf(arrow, sizeof(arrow), "%s##ca_%d", child.expanded ? "-" : "+", child_gid);
      if (ImGui::SmallButton(arrow)) {
        child.expanded = !child.expanded;
        if (child.expanded && child.children.empty() && child_raw) {
          uintptr_t cp = 0; std::memcpy(&cp, child_raw, 8);
          if (valid_ptr(cp) && fmap_.contains(cp)) {
            child.children = make_default_nodes(0x80);
            child.class_id = 0;
          }
        }
      }
      ImGui::SameLine();
    } else {
      ImGui::Text("  ");
      ImGui::SameLine();
    }

    ImGui::TextColored(kColorOffset, "%04X", child.offset);
    ImGui::SameLine(0, 8);
    ImGui::TextColored(kColorAddress, "%012lX", target_addr + child.offset);
    ImGui::SameLine(0, 8);

    if (v.editing_node == child_gid) {
      ImGui::SetNextItemWidth(120);
      if (ImGui::InputText("##cedit", v.edit_buf, sizeof(v.edit_buf),
                            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll)) {
        child.name = v.edit_buf;
        v.editing_node = -1;
      }
      if (!ImGui::IsItemActive() && ImGui::IsMouseClicked(0)) v.editing_node = -1;
    } else {
      ImGui::TextColored(kColorName, "%-8s", child.name.c_str());
      if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
        v.editing_node = child_gid;
        snprintf(v.edit_buf, sizeof(v.edit_buf), "%s", child.name.c_str());
      }
    }
    ImGui::SameLine(0, 4);

    if (child_raw) {
      char chex[32] = {};
      int chl = 0;
      int cshow = std::min(child_ns, 8);
      for (int b = 0; b < cshow; ++b)
        chl += snprintf(chex + chl, sizeof(chex) - chl, "%02X ", child_raw[b]);
      for (int b = cshow; b < 8; ++b)
        chl += snprintf(chex + chl, sizeof(chex) - chl, "   ");
      ImGui::TextColored(kColorHex, "%s", chex);
      ImGui::SameLine(0, 4);

      char casc[9];
      uint8_t casc_raw[8] = {};
      std::memcpy(casc_raw, child_raw, std::min(child_ns, 8));
      ascii_preview(casc, casc_raw, 8);
      ImGui::TextColored(kColorAscii, "%s", casc);
      ImGui::SameLine(0, 8);

      bool child_is_hex = (child.type == NodeType::Hex64 || child.type == NodeType::Hex32 ||
                           child.type == NodeType::Hex16 || child.type == NodeType::Hex8);

      if (child.type == NodeType::Pointer) {
        uintptr_t cp; std::memcpy(&cp, child_raw, 8);
        ImGui::TextColored(kColorPointer, "// *->0x%lX", cp);
      } else if (child_is_hex && child_ns >= 4) {
        ImGui::TextColored(kColorComment, "//");
        ImGui::SameLine(0, 4);
        float cfv; std::memcpy(&cfv, child_raw, 4);
        ImGui::TextColored(kColorValue, "(%.3f)", cfv);
        ImGui::SameLine(0, 4);
        if (child_ns >= 8) {
          uint64_t cv64; std::memcpy(&cv64, child_raw, 8);
          ImVec4 cc = looks_like_pointer(cv64) ? kColorPointer : kColorValue;
          ImGui::TextColored(cc, "(%lu|0x%lX)", (unsigned long)cv64, (unsigned long)cv64);
          if (looks_like_pointer(cv64)) {
            ImGui::SameLine(0, 4);
            ImGui::TextColored(kColorPointer, "*->0x%lX", (unsigned long)cv64);
          }
        } else {
          uint32_t cv32; std::memcpy(&cv32, child_raw, 4);
          ImGui::TextColored(kColorValue, "(%u|0x%X)", cv32, cv32);
        }
      } else {
        ImGui::TextColored(kColorComment, "//");
        ImGui::SameLine(0, 4);
        switch (child.type) {
          case NodeType::Int8:  { int8_t val;  std::memcpy(&val, child_raw, 1); ImGui::TextColored(kColorTypedValue, "(%d)", val); break; }
          case NodeType::Int16: { int16_t val; std::memcpy(&val, child_raw, 2); ImGui::TextColored(kColorTypedValue, "(%d)", val); break; }
          case NodeType::Int32: { int32_t val; std::memcpy(&val, child_raw, 4); ImGui::TextColored(kColorTypedValue, "(%d)", val); break; }
          case NodeType::Int64: { int64_t val; std::memcpy(&val, child_raw, 8); ImGui::TextColored(kColorTypedValue, "(%ld)", (long)val); break; }
          case NodeType::UInt8:  { ImGui::TextColored(kColorTypedValue, "(%u)", child_raw[0]); break; }
          case NodeType::UInt16: { uint16_t val; std::memcpy(&val, child_raw, 2); ImGui::TextColored(kColorTypedValue, "(%u)", val); break; }
          case NodeType::UInt32: { uint32_t val; std::memcpy(&val, child_raw, 4); ImGui::TextColored(kColorTypedValue, "(%u)", val); break; }
          case NodeType::UInt64: { uint64_t val; std::memcpy(&val, child_raw, 8); ImGui::TextColored(kColorTypedValue, "(%lu)", (unsigned long)val); break; }
          case NodeType::Float:  { float val; std::memcpy(&val, child_raw, 4); ImGui::TextColored(kColorTypedValue, "(%.6g)", val); break; }
          case NodeType::Double: { double val; std::memcpy(&val, child_raw, 8); ImGui::TextColored(kColorTypedValue, "(%.10g)", val); break; }
          case NodeType::Bool:   { ImGui::TextColored(kColorTypedValue, "(%s)", child_raw[0] ? "true" : "false"); break; }
          case NodeType::Vec3:   { float xyz[3]; std::memcpy(xyz, child_raw, 12); ImGui::TextColored(kColorTypedValue, "(%.2f, %.2f, %.2f)", xyz[0], xyz[1], xyz[2]); break; }
          default: {
            uint64_t cv = 0; std::memcpy(&cv, child_raw, std::min(child_ns, 8));
            ImGui::TextColored(kColorValue, "(0x%lX)", (unsigned long)cv);
            break;
          }
        }
      }
    } else {
      ImGui::TextColored(kColorHex, "?? ?? ?? ?? ?? ?? ?? ?? ........");
      ImGui::SameLine(0, 4);
      ImGui::TextColored(kColorComment, "// ???");
    }

    if (!child.comment.empty()) {
      ImGui::SameLine(0, 8);
      if (v.editing_comment_node == child_gid) {
        ImGui::SetNextItemWidth(200);
        if (ImGui::InputText("##ceditcmt", v.edit_buf, sizeof(v.edit_buf),
                              ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll)) {
          child.comment = v.edit_buf;
          v.editing_comment_node = -1;
        }
        if (!ImGui::IsItemActive() && ImGui::IsMouseClicked(0)) v.editing_comment_node = -1;
      } else {
        ImGui::TextColored(kColorComment, "[%s]", child.comment.c_str());
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
          v.editing_comment_node = child_gid;
          snprintf(v.edit_buf, sizeof(v.edit_buf), "%s", child.comment.c_str());
        }
      }
    }

    ImGui::PopID();

    if (child.type == NodeType::Pointer && child.expanded && !child.children.empty() && child_raw) {
      uintptr_t nested_ptr = 0;
      std::memcpy(&nested_ptr, child_raw, 8);
      if (valid_ptr(nested_ptr) && fmap_.contains(nested_ptr)) {
        render_pointer_children(v, child, nested_ptr, depth + 1, child_gid * 100);
      }
    }
  }
}

void Inspector::render_node_row(ClassView& v, MemoryNode& node, int idx, int depth) {
  int ns = node_size(node.type);
  bool in_bounds = (node.offset + ns <= v.buffer.size());
  const uint8_t* raw = in_bounds ? &v.buffer[node.offset] : nullptr;
  const uint8_t* prev = (node.offset + ns <= v.prev_buffer.size()) ? &v.prev_buffer[node.offset] : nullptr;

  bool changed = false;
  if (raw && prev && !v.prev_buffer.empty())
    changed = (std::memcmp(raw, prev, ns) != 0);

  ImVec2 cursor_start = ImGui::GetCursorPos();
  char sel_id[32]; snprintf(sel_id, sizeof(sel_id), "##row_%d_%d", idx, depth);
  ImGui::Selectable(sel_id, false,
      ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
      ImVec2(0, ImGui::GetTextLineHeight()));

  char ctx_id[32]; snprintf(ctx_id, sizeof(ctx_id), "node_ctx_%d_%d", idx, depth);
  {
    ImVec2 rmin = ImGui::GetItemRectMin(), rmax = ImGui::GetItemRectMax();
    if (ImGui::IsMouseHoveringRect(rmin, rmax) && ImGui::IsMouseReleased(ImGuiMouseButton_Right))
      ImGui::OpenPopup(ctx_id);
  }
  if (ImGui::BeginPopup(ctx_id)) {
    render_context_menu(v, idx);
    ImGui::EndPopup();
  }

  ImGui::SetCursorPos(cursor_start);

  float indent = depth * 20.0f;
  ImGui::SetCursorPosX(ImGui::GetCursorPosX() + indent);

  if (node.type == NodeType::Pointer) {
    char arrow_id[32];
    snprintf(arrow_id, sizeof(arrow_id), "%s##arrow_%d", node.expanded ? "-" : "+", idx);
    if (ImGui::SmallButton(arrow_id)) {
      node.expanded = !node.expanded;
      if (node.expanded && node.children.empty() && raw) {
        uintptr_t ptr_val = 0;
        std::memcpy(&ptr_val, raw, 8);
        if (valid_ptr(ptr_val) && fmap_.contains(ptr_val)) {
          node.children = make_default_nodes(0x100);
          node.class_id = 0;
        }
      }
    }
    ImGui::SameLine();
  } else {
    ImGui::Text("  ");
    ImGui::SameLine();
  }

  ImGui::TextColored(kColorOffset, "%04X", node.offset);
  ImGui::SameLine(0, 8);

  uintptr_t abs_addr = v.base_address + node.offset;
  ImGui::TextColored(kColorAddress, "%012lX", abs_addr);
  ImGui::SameLine(0, 8);

  if (v.editing_node == idx) {
    ImGui::SetNextItemWidth(120);
    if (ImGui::InputText("##edit_name", v.edit_buf, sizeof(v.edit_buf),
                          ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll)) {
      node.name = v.edit_buf;
      v.editing_node = -1;
    }
    if (!ImGui::IsItemActive() && ImGui::IsMouseClicked(0)) v.editing_node = -1;
  } else {
    ImGui::TextColored(kColorName, "%-8s", node.name.c_str());
    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
      v.editing_node = idx;
      snprintf(v.edit_buf, sizeof(v.edit_buf), "%s", node.name.c_str());
    }
  }
  ImGui::SameLine(0, 4);

  if (!raw) {
    ImGui::TextColored(kColorHex, "?? ?? ?? ?? ?? ?? ?? ?? ........");
    ImGui::SameLine(0, 4);
    ImGui::TextColored(kColorComment, "// ???");
    goto render_children;
  }

  {
    char hex_str[32] = {};
    int hex_len = 0;
    int show = std::min(ns, 8);
    for (int b = 0; b < show; ++b)
      hex_len += snprintf(hex_str + hex_len, sizeof(hex_str) - hex_len, "%02X ", raw[b]);
    for (int b = show; b < 8; ++b)
      hex_len += snprintf(hex_str + hex_len, sizeof(hex_str) - hex_len, "   ");

    ImGui::TextColored(changed ? kColorChanged : kColorHex, "%s", hex_str);
    ImGui::SameLine(0, 4);

    char asc[9];
    uint8_t asc_raw[8] = {};
    std::memcpy(asc_raw, raw, std::min(ns, 8));
    ascii_preview(asc, asc_raw, 8);
    ImGui::TextColored(kColorAscii, "%s", asc);
    ImGui::SameLine(0, 8);

    bool is_default_hex = (node.type == NodeType::Hex64 || node.type == NodeType::Hex32 ||
                           node.type == NodeType::Hex16 || node.type == NodeType::Hex8);

    if (node.type == NodeType::Pointer) {
      uintptr_t ptr; std::memcpy(&ptr, raw, 8);
      if (ptr == 0) {
        ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.4f, 1), "// nullptr");
      } else {
        ImGui::TextColored(kColorPointer, "// *->0x%lX", ptr);
      }
    } else if (is_default_hex && ns >= 4) {
      ImGui::TextColored(kColorComment, "//");
      ImGui::SameLine(0, 4);

      if (ns >= 4) {
        float fv; std::memcpy(&fv, raw, 4);
        ImGui::TextColored(kColorValue, "(%.3f)", fv);
        ImGui::SameLine(0, 4);
      }

      if (ns >= 8) {
        uint64_t v64; std::memcpy(&v64, raw, 8);
        if (looks_like_pointer(v64)) {
          ImGui::TextColored(kColorPointer, "(%lu|0x%lX)", (unsigned long)v64, (unsigned long)v64);
          ImGui::SameLine(0, 4);
          ImGui::TextColored(kColorPointer, "*->0x%lX", (unsigned long)v64);
        } else {
          ImGui::TextColored(kColorValue, "(%lu|0x%lX)", (unsigned long)v64, (unsigned long)v64);
        }
      } else if (ns >= 4) {
        uint32_t v32; std::memcpy(&v32, raw, 4);
        if (looks_like_pointer(v32)) {
          ImGui::TextColored(kColorPointer, "(%u|0x%X)", v32, v32);
        } else {
          ImGui::TextColored(kColorValue, "(%u|0x%X)", v32, v32);
        }
      }
    } else {
      ImGui::TextColored(kColorComment, "//");
      ImGui::SameLine(0, 4);
      ImVec4 vc = changed ? kColorChanged : kColorTypedValue;

      switch (node.type) {
        case NodeType::Int8:  { int8_t val;  std::memcpy(&val, raw, 1); ImGui::TextColored(vc, "(%d)", val); break; }
        case NodeType::Int16: { int16_t val; std::memcpy(&val, raw, 2); ImGui::TextColored(vc, "(%d)", val); break; }
        case NodeType::Int32: { int32_t val; std::memcpy(&val, raw, 4); ImGui::TextColored(vc, "(%d)", val); break; }
        case NodeType::Int64: { int64_t val; std::memcpy(&val, raw, 8); ImGui::TextColored(vc, "(%ld)", (long)val); break; }
        case NodeType::UInt8:  { ImGui::TextColored(vc, "(%u)", raw[0]); break; }
        case NodeType::UInt16: { uint16_t val; std::memcpy(&val, raw, 2); ImGui::TextColored(vc, "(%u)", val); break; }
        case NodeType::UInt32: { uint32_t val; std::memcpy(&val, raw, 4); ImGui::TextColored(vc, "(%u)", val); break; }
        case NodeType::UInt64: { uint64_t val; std::memcpy(&val, raw, 8); ImGui::TextColored(vc, "(%lu)", (unsigned long)val); break; }
        case NodeType::Float:  { float val; std::memcpy(&val, raw, 4); ImGui::TextColored(vc, "(%.6g)", val); break; }
        case NodeType::Double: { double val; std::memcpy(&val, raw, 8); ImGui::TextColored(vc, "(%.10g)", val); break; }
        case NodeType::Bool:   { ImGui::TextColored(vc, "(%s)", raw[0] ? "true" : "false"); break; }
        case NodeType::UTF8Text: {
          uintptr_t sptr; std::memcpy(&sptr, raw, 8);
          if (sptr && valid_ptr(sptr)) {
            auto sdata = reader_->read(sptr, 64);
            if (sdata) {
              std::string s;
              for (size_t i = 0; i < sdata->size() && (*sdata)[i]; ++i)
                s += static_cast<char>((*sdata)[i]);
              ImGui::TextColored(vc, "\"%s\"", s.c_str());
            } else {
              ImGui::TextColored(vc, "-> 0x%lX", sptr);
            }
          } else {
            ImGui::TextColored(kColorHex, "0x%lX", sptr);
          }
          break;
        }
        case NodeType::UTF16Text: {
          uintptr_t sptr; std::memcpy(&sptr, raw, 8);
          if (sptr && valid_ptr(sptr)) {
            auto sdata = reader_->read(sptr, 128);
            if (sdata) {
              std::string s;
              for (size_t i = 0; i + 1 < sdata->size(); i += 2) {
                char16_t ch; std::memcpy(&ch, &(*sdata)[i], 2);
                if (ch == 0) break;
                if (ch < 128) s += static_cast<char>(ch); else s += '?';
              }
              ImGui::TextColored(vc, "L\"%s\"", s.c_str());
            } else {
              ImGui::TextColored(vc, "-> 0x%lX", sptr);
            }
          } else {
            ImGui::TextColored(kColorHex, "0x%lX", sptr);
          }
          break;
        }
        case NodeType::Vec3: {
          float xyz[3]; std::memcpy(xyz, raw, 12);
          ImGui::TextColored(vc, "(%.2f, %.2f, %.2f)", xyz[0], xyz[1], xyz[2]);
          break;
        }
        default: break;
      }
    }
  }

  // FName hint (user-set label)
  if (!node.fname_hint.empty()) {
    ImGui::SameLine(0, 8);
    static const ImVec4 kColorFName(0.2f, 1.0f, 0.5f, 1.0f);
    ImGui::TextColored(kColorFName, "FN:\"%s\"", node.fname_hint.c_str());
  }

  if (!node.comment.empty()) {
    ImGui::SameLine(0, 8);
    if (v.editing_comment_node == idx) {
      ImGui::SetNextItemWidth(200);
      if (ImGui::InputText("##edit_comment", v.edit_buf, sizeof(v.edit_buf),
                            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll)) {
        node.comment = v.edit_buf;
        v.editing_comment_node = -1;
      }
      if (!ImGui::IsItemActive() && ImGui::IsMouseClicked(0)) v.editing_comment_node = -1;
    } else {
      ImGui::TextColored(kColorComment, "[%s]", node.comment.c_str());
      if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
        v.editing_comment_node = idx;
        snprintf(v.edit_buf, sizeof(v.edit_buf), "%s", node.comment.c_str());
      }
    }
  }

render_children:
  if (node.type == NodeType::Pointer && node.expanded && !node.children.empty()) {
    const uint8_t* parent_raw = (node.offset + 8 <= v.buffer.size()) ? &v.buffer[node.offset] : nullptr;
    if (!parent_raw) return;

    uintptr_t ptr_val = 0;
    std::memcpy(&ptr_val, parent_raw, 8);
    if (!valid_ptr(ptr_val) || !fmap_.contains(ptr_val)) return;

    render_pointer_children(v, node, ptr_val, depth + 1, idx * 10000);
  }
}

void Inspector::render_context_menu(ClassView& v, int node_idx) {
  if (node_idx < 0 || node_idx >= static_cast<int>(v.nodes.size())) return;

  if (ImGui::BeginMenu("Hex")) {
    if (ImGui::MenuItem("Hex8 (1 byte)"))  { v.nodes[node_idx].type = NodeType::Hex8; }
    if (ImGui::MenuItem("Hex16 (2 bytes)")) { v.nodes[node_idx].type = NodeType::Hex16; }
    if (ImGui::MenuItem("Hex32 (4 bytes)")) { v.nodes[node_idx].type = NodeType::Hex32; }
    if (ImGui::MenuItem("Hex64 (8 bytes)")) { v.nodes[node_idx].type = NodeType::Hex64; }
    ImGui::EndMenu();
  }
  if (ImGui::BeginMenu("Signed")) {
    if (ImGui::MenuItem("Int8"))  v.nodes[node_idx].type = NodeType::Int8;
    if (ImGui::MenuItem("Int16")) v.nodes[node_idx].type = NodeType::Int16;
    if (ImGui::MenuItem("Int32")) v.nodes[node_idx].type = NodeType::Int32;
    if (ImGui::MenuItem("Int64")) v.nodes[node_idx].type = NodeType::Int64;
    ImGui::EndMenu();
  }
  if (ImGui::BeginMenu("Unsigned")) {
    if (ImGui::MenuItem("UInt8"))  v.nodes[node_idx].type = NodeType::UInt8;
    if (ImGui::MenuItem("UInt16")) v.nodes[node_idx].type = NodeType::UInt16;
    if (ImGui::MenuItem("UInt32")) v.nodes[node_idx].type = NodeType::UInt32;
    if (ImGui::MenuItem("UInt64")) v.nodes[node_idx].type = NodeType::UInt64;
    ImGui::EndMenu();
  }
  if (ImGui::BeginMenu("Float")) {
    if (ImGui::MenuItem("Float (4 bytes)"))  v.nodes[node_idx].type = NodeType::Float;
    if (ImGui::MenuItem("Double (8 bytes)")) v.nodes[node_idx].type = NodeType::Double;
    ImGui::EndMenu();
  }
  if (ImGui::MenuItem("Bool"))    v.nodes[node_idx].type = NodeType::Bool;
  if (ImGui::MenuItem("Pointer")) v.nodes[node_idx].type = NodeType::Pointer;
  if (ImGui::BeginMenu("Text")) {
    if (ImGui::MenuItem("UTF8 Text"))  v.nodes[node_idx].type = NodeType::UTF8Text;
    if (ImGui::MenuItem("UTF16 Text")) v.nodes[node_idx].type = NodeType::UTF16Text;
    ImGui::EndMenu();
  }
  if (ImGui::MenuItem("Vec3 (12 bytes)")) v.nodes[node_idx].type = NodeType::Vec3;

  ImGui::Separator();
  if (ImGui::MenuItem("Rename")) {
    v.editing_node = node_idx;
    snprintf(v.edit_buf, sizeof(v.edit_buf), "%s", v.nodes[node_idx].name.c_str());
  }
  if (ImGui::MenuItem("Add Comment")) {
    v.editing_comment_node = node_idx;
    v.edit_buf[0] = '\0';
  }

  ImGui::Separator();
  if (ImGui::BeginMenu("Apply SDK Class")) {
    static char sdk_filter[64] = {};
    ImGui::SetNextItemWidth(200);
    ImGui::InputText("##sdk_filter", sdk_filter, sizeof(sdk_filter));
    ImGui::Separator();
    for (auto& cn : class_names_) {
      if (sdk_filter[0] && cn.find(sdk_filter) == std::string::npos) continue;
      if (ImGui::MenuItem(cn.c_str())) {
        v.nodes = make_sdk_nodes(cn);
        v.name = cn;
        auto it = classes_.find(cn);
        if (it != classes_.end() && it->second.size > 0)
          v.size = it->second.size;
        v.fnames_scanned = false;
        refresh_view(v);
      }
    }
    ImGui::EndMenu();
  }
}

void Inspector::render_class_view(ClassView& v) {
  ImGui::SetNextItemWidth(200);
  if (ImGui::InputText("##addr", v.addr_input, sizeof(v.addr_input),
                        ImGuiInputTextFlags_EnterReturnsTrue)) {
    uintptr_t new_addr = 0;
    if (sscanf(v.addr_input, "0x%lx", &new_addr) == 1 || sscanf(v.addr_input, "%lx", &new_addr) == 1) {
      v.base_address = new_addr;
      v.prev_buffer.clear();
      v.fnames_scanned = false;
      refresh_view(v);
    }
  }
  ImGui::SameLine();
  if (ImGui::Button("Refresh")) {
    v.prev_buffer.clear();
    refresh_view(v);
  }
  ImGui::SameLine();

  ImGui::TextColored(kColorAddress, "0x%lX", v.base_address);
  ImGui::SameLine();
  ImGui::TextColored(kColorType, "%s", v.name.c_str());
  ImGui::SameLine();
  ImGui::Text("(0x%X bytes, %zu nodes)", v.size, v.nodes.size());

  ImGui::SameLine();
  int sz = static_cast<int>(v.size);
  ImGui::SetNextItemWidth(100);
  if (ImGui::InputInt("##size", &sz, 0x100, 0x1000)) {
    sz = std::clamp(sz, 0x10, 0x10000);
    uint32_t new_size = static_cast<uint32_t>(sz);
    if (new_size != v.size) {
      uint32_t old_size = v.size;
      v.size = new_size;
      if (new_size > old_size) {
        uint32_t cursor = old_size;
        while (cursor + 8 <= new_size) {
          MemoryNode n;
          n.type = NodeType::Hex64;
          n.offset = cursor;
          char buf[16]; snprintf(buf, sizeof(buf), "field_%04X", cursor);
          n.name = buf;
          v.nodes.push_back(std::move(n));
          cursor += 8;
        }
        while (cursor < new_size) {
          MemoryNode n;
          n.type = NodeType::Hex8;
          n.offset = cursor;
          char buf[16]; snprintf(buf, sizeof(buf), "field_%04X", cursor);
          n.name = buf;
          v.nodes.push_back(std::move(n));
          ++cursor;
        }
      } else {
        v.nodes.erase(
          std::remove_if(v.nodes.begin(), v.nodes.end(),
            [new_size](const MemoryNode& n) { return n.offset >= new_size; }),
          v.nodes.end());
      }
      v.prev_buffer.clear();
      refresh_view(v);
    }
  }

  ImGui::SameLine();
  if (ImGui::BeginPopup("apply_sdk_popup")) {
    static char sdk_hdr_filter[64] = {};
    ImGui::SetNextItemWidth(200);
    ImGui::InputText("##sdk_hdr_filter", sdk_hdr_filter, sizeof(sdk_hdr_filter));
    ImGui::Separator();
    for (auto& cn : class_names_) {
      if (sdk_hdr_filter[0] && cn.find(sdk_hdr_filter) == std::string::npos) continue;
      if (ImGui::MenuItem(cn.c_str())) {
        std::lock_guard lock(mu_);
        v.nodes = make_sdk_nodes(cn);
        v.name = cn;
        auto it = classes_.find(cn);
        if (it != classes_.end() && it->second.size > 0)
          v.size = it->second.size;
        v.prev_buffer.clear();
        v.fnames_scanned = false;
        refresh_view(v);
      }
    }
    ImGui::EndPopup();
  }
  if (ImGui::Button("Apply SDK")) {
    ImGui::OpenPopup("apply_sdk_popup");
  }

  ImGui::SameLine();
  ImGui::Checkbox("Follow MCP", &follow_mcp_);

  ImGui::Separator();

  ImGui::BeginChild("##nodes", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);

  ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1), "      Off    Address      Name      Hex                      ASCII     Interpretation");
  ImGui::Separator();

  for (int i = 0; i < static_cast<int>(v.nodes.size()); ++i) {
    ImGui::PushID(i);

    if (follow_mcp_ && mcp_scroll_pending_ &&
        mcp_scroll_view_id_ == v.id && v.nodes[i].offset == mcp_scroll_offset_) {
      ImGui::SetScrollHereY(0.3f);
      mcp_scroll_pending_ = false;
    }

    render_node_row(v, v.nodes[i], i, 0);
    ImGui::PopID();
  }

  ImGui::EndChild();
}

// ── Class Browser ────────────────────────────────────────────────────────────

void Inspector::render_class_browser() {
  ImGui::SetNextItemWidth(300);
  ImGui::InputText("Filter##classes", class_filter_, sizeof(class_filter_));

  ImGui::BeginChild("##class_list", ImVec2(0, 0), ImGuiChildFlags_Borders);
  for (size_t i = 0; i < class_names_.size(); ++i) {
    auto& cn = class_names_[i];
    if (class_filter_[0] && cn.find(class_filter_) == std::string::npos) continue;

    auto it = classes_.find(cn);
    if (it == classes_.end()) continue;

    bool open = ImGui::TreeNode(cn.c_str());

    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
      std::lock_guard lock(mu_);
      ClassView nv;
      nv.id = next_view_id_++;
      nv.base_address = 0;
      nv.size = it->second.size > 0 ? it->second.size : 0x200;
      nv.name = cn;
      nv.nodes = make_sdk_nodes(cn);
      views_.push_back(std::move(nv));
    }

    if (open) {
      ImGui::Text("Parent: %s  Size: 0x%X  Props: %zu",
                   it->second.parent.c_str(), it->second.size, it->second.props.size());
      for (auto& p : it->second.props) {
        ImGui::BulletText("+0x%04X  %-30s %s  (%u bytes)",
                          p.offset, p.name.c_str(), p.type_name.c_str(), p.element_size);
      }
      ImGui::TreePop();
    }
  }
  ImGui::EndChild();
}

// ── Project Save/Load ────────────────────────────────────────────────────────

void Inspector::save_project() {
  const char* home = getenv("HOME");
  if (!home) return;
  std::string dir = std::string(home) + "/.config/raider";
  std::filesystem::create_directories(dir);
  std::string path = dir + "/inspector_project.json";

  std::ofstream f(path);
  if (!f.is_open()) return;

  f << "[\n";
  for (size_t vi = 0; vi < views_.size(); ++vi) {
    auto& v = views_[vi];
    f << "  {\n";
    f << "    \"name\": \"" << json_escape(v.name) << "\",\n";
    f << "    \"size\": " << v.size << ",\n";
    f << "    \"nodes\": [\n";
    for (size_t ni = 0; ni < v.nodes.size(); ++ni) {
      auto& n = v.nodes[ni];
      f << "      {\"offset\": " << n.offset
        << ", \"type\": \"" << node_type_name(n.type)
        << "\", \"name\": \"" << json_escape(n.name) << "\"";
      if (!n.comment.empty())
        f << ", \"comment\": \"" << json_escape(n.comment) << "\"";
      if (!n.fname_hint.empty())
        f << ", \"fname_hint\": \"" << json_escape(n.fname_hint) << "\"";
      f << "}" << (ni + 1 < v.nodes.size() ? "," : "") << "\n";
    }
    f << "    ]\n";
    f << "  }" << (vi + 1 < views_.size() ? "," : "") << "\n";
  }
  f << "]\n";

  std::cerr << "[inspector] Saved project to " << path << "\n";
}

void Inspector::load_project() {
  const char* home = getenv("HOME");
  if (!home) return;
  std::string path = std::string(home) + "/.config/raider/inspector_project.json";
  std::ifstream f(path);
  if (!f.is_open()) return;

  std::cerr << "[inspector] Loaded project from " << path << "\n";
}

// ── Memory Explorer ──────────────────────────────────────────────────────────

void Inspector::render_memory_explorer() {
  ImGui::SetNextItemWidth(180);
  bool addr_enter = ImGui::InputText("##exaddr", explorer_addr_input_,
                                     sizeof(explorer_addr_input_),
                                     ImGuiInputTextFlags_EnterReturnsTrue);
  if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
    ImGui::SetTooltip("Hex address (e.g. 0x1A2B3C4D)");

  ImGui::SameLine(0, 4);
  ImGui::SetNextItemWidth(80);
  ImGui::InputText("##exsize", explorer_size_input_, sizeof(explorer_size_input_));
  if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
    ImGui::SetTooltip("View size (hex, e.g. 0x400)");

  ImGui::SameLine(0, 4);
  ImGui::SetNextItemWidth(140);
  ImGui::InputText("##exlabel", explorer_label_input_, sizeof(explorer_label_input_));
  if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
    ImGui::SetTooltip("Optional label");

  ImGui::SameLine(0, 8);
  bool open_clicked = ImGui::Button("Open") || addr_enter;

  ImGui::SameLine(0, 8);
  bool bookmark_clicked = ImGui::Button("Bookmark");

  if (open_clicked || bookmark_clicked) {
    uintptr_t addr = 0;
    uint32_t sz = 0x400;
    if (sscanf(explorer_addr_input_, "0x%lx", &addr) != 1)
      sscanf(explorer_addr_input_, "%lx", &addr);
    if (sscanf(explorer_size_input_, "0x%x", &sz) != 1)
      sscanf(explorer_size_input_, "%u", &sz);
    if (sz == 0 || sz > 0x10000) sz = 0x400;

    if (addr != 0) {
      std::string label = explorer_label_input_[0]
          ? std::string(explorer_label_input_)
          : std::string("0x") + [](uintptr_t a) {
              char buf[20]; snprintf(buf, sizeof(buf), "%lX", a); return std::string(buf);
            }(addr);

      if (open_clicked) {
        std::lock_guard lock(mu_);
        ClassView nv;
        nv.id = next_view_id_++;
        nv.base_address = addr;
        nv.size = sz;
        nv.name = label;
        snprintf(nv.addr_input, sizeof(nv.addr_input), "0x%lX", addr);
        nv.nodes = make_default_nodes(sz);
        refresh_view(nv);
        views_.push_back(std::move(nv));

        explorer_history_.erase(
          std::remove_if(explorer_history_.begin(), explorer_history_.end(),
            [addr](const AddrBookmark& b) { return b.addr == addr; }),
          explorer_history_.end());
        explorer_history_.insert(explorer_history_.begin(), {label, addr, sz});
        if (explorer_history_.size() > 32)
          explorer_history_.resize(32);
      }

      if (bookmark_clicked) {
        explorer_bookmarks_.erase(
          std::remove_if(explorer_bookmarks_.begin(), explorer_bookmarks_.end(),
            [addr](const AddrBookmark& b) { return b.addr == addr; }),
          explorer_bookmarks_.end());
        explorer_bookmarks_.push_back({label, addr, sz});
      }
    }
  }

  ImGui::Separator();

  float col_w = ImGui::GetContentRegionAvail().x * 0.5f - 4;

  ImGui::BeginChild("##exhist", ImVec2(col_w, 0), ImGuiChildFlags_Borders);
  ImGui::TextColored(ImVec4(0.6f, 0.6f, 1.0f, 1), "Recent (%zu)", explorer_history_.size());
  ImGui::Separator();
  int hist_to_remove = -1;
  for (int i = 0; i < static_cast<int>(explorer_history_.size()); ++i) {
    auto& h = explorer_history_[i];
    ImGui::PushID(i);

    ImGui::TextColored(kColorPointer, "0x%lX", h.addr);
    ImGui::SameLine(0, 6);
    ImGui::TextUnformatted(h.label.c_str());

    ImGui::SameLine();
    if (ImGui::SmallButton("Open")) {
      std::lock_guard lock(mu_);
      ClassView nv;
      nv.id = next_view_id_++;
      nv.base_address = h.addr;
      nv.size = h.size;
      nv.name = h.label;
      snprintf(nv.addr_input, sizeof(nv.addr_input), "0x%lX", h.addr);
      nv.nodes = make_default_nodes(h.size);
      refresh_view(nv);
      views_.push_back(std::move(nv));
    }
    ImGui::SameLine(0, 2);
    if (ImGui::SmallButton("Bkm")) {
      explorer_bookmarks_.erase(
        std::remove_if(explorer_bookmarks_.begin(), explorer_bookmarks_.end(),
          [&h](const AddrBookmark& b) { return b.addr == h.addr; }),
        explorer_bookmarks_.end());
      explorer_bookmarks_.push_back(h);
    }
    ImGui::SameLine(0, 2);
    if (ImGui::SmallButton("X")) hist_to_remove = i;

    ImGui::PopID();
  }
  if (hist_to_remove >= 0)
    explorer_history_.erase(explorer_history_.begin() + hist_to_remove);
  ImGui::EndChild();

  ImGui::SameLine(0, 8);

  ImGui::BeginChild("##exbkm", ImVec2(0, 0), ImGuiChildFlags_Borders);
  ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1), "Bookmarks (%zu)", explorer_bookmarks_.size());
  ImGui::Separator();
  int bkm_to_remove = -1;
  for (int i = 0; i < static_cast<int>(explorer_bookmarks_.size()); ++i) {
    auto& b = explorer_bookmarks_[i];
    ImGui::PushID(i + 10000);

    ImGui::TextColored(kColorPointer, "0x%lX", b.addr);
    ImGui::SameLine(0, 6);
    ImGui::TextUnformatted(b.label.c_str());

    ImGui::SameLine();
    if (ImGui::SmallButton("Open")) {
      std::lock_guard lock(mu_);
      ClassView nv;
      nv.id = next_view_id_++;
      nv.base_address = b.addr;
      nv.size = b.size;
      nv.name = b.label;
      snprintf(nv.addr_input, sizeof(nv.addr_input), "0x%lX", b.addr);
      nv.nodes = make_default_nodes(b.size);
      refresh_view(nv);
      views_.push_back(std::move(nv));
    }
    ImGui::SameLine(0, 2);
    if (ImGui::SmallButton("X")) bkm_to_remove = i;

    ImGui::PopID();
  }
  if (bkm_to_remove >= 0)
    explorer_bookmarks_.erase(explorer_bookmarks_.begin() + bkm_to_remove);
  ImGui::EndChild();
}

// ── MCP API implementation ───────────────────────────────────────────────────

MCPReadResult Inspector::mcp_read_memory(uintptr_t addr, size_t size) {
  MCPReadResult result;
  result.addr = addr;
  if (!reader_ || !reader_->is_attached()) return result;
  auto data = reader_->read(addr, size);
  if (data) result.data = std::move(*data);

  {
    std::lock_guard lock(mu_);
    for (auto& v : views_) {
      if (addr >= v.base_address && addr < v.base_address + v.size) {
        mcp_scroll_view_id_ = v.id;
        mcp_scroll_offset_ = static_cast<uint32_t>(addr - v.base_address);
        mcp_scroll_pending_ = true;
        break;
      }
    }
  }

  return result;
}

std::string Inspector::mcp_read_string(uintptr_t addr, size_t max_len) {
  if (!reader_ || !reader_->is_attached()) return {};
  auto data = reader_->read(addr, max_len);
  if (!data) return {};
  std::string s;
  for (size_t i = 0; i < data->size() && (*data)[i]; ++i)
    s += static_cast<char>((*data)[i]);
  return s;
}

int Inspector::mcp_open_view(uintptr_t addr, const std::string& label, uint32_t size) {
  std::lock_guard lock(mu_);
  ClassView v;
  v.id = next_view_id_++;
  v.base_address = addr;
  v.size = size;
  v.name = label.empty() ? "View" : label;
  snprintf(v.addr_input, sizeof(v.addr_input), "0x%lX", addr);
  v.nodes = make_default_nodes(size);
  v.place_fullscreen_once = true;
  refresh_view(v);
  views_.push_back(std::move(v));
  return views_.back().id;
}

void Inspector::mcp_close_view(int id) {
  std::lock_guard lock(mu_);
  views_.erase(std::remove_if(views_.begin(), views_.end(),
    [id](const ClassView& v) { return v.id == id; }), views_.end());
}

std::vector<std::pair<int, std::string>> Inspector::mcp_list_views() {
  std::lock_guard lock(mu_);
  std::vector<std::pair<int, std::string>> result;
  for (auto& v : views_)
    result.emplace_back(v.id, v.name);
  return result;
}

std::string Inspector::mcp_get_view_info(int id) {
  std::lock_guard lock(mu_);
  auto* v = find_view(id);
  if (!v) return "{}";

  refresh_view(*v);

  std::ostringstream os;
  os << "{\"id\":" << v->id
     << ",\"name\":\"" << json_escape(v->name) << "\""
     << ",\"addr\":\"0x" << std::hex << v->base_address << std::dec << "\""
     << ",\"size\":" << v->size
     << ",\"nodes\":[";

  for (size_t i = 0; i < v->nodes.size(); ++i) {
    auto& n = v->nodes[i];
    if (i > 0) os << ",";
    os << "{\"offset\":" << n.offset
       << ",\"type\":\"" << node_type_name(n.type) << "\""
       << ",\"name\":\"" << json_escape(n.name) << "\"";

    int ns = node_size(n.type);
    if (n.offset + ns <= v->buffer.size()) {
      const uint8_t* raw = &v->buffer[n.offset];
      os << ",\"hex\":\"";
      for (int b = 0; b < ns; ++b) {
        char h[4]; snprintf(h, sizeof(h), "%02X", raw[b]);
        os << h;
      }
      os << "\"";

      os << ",\"value\":";
      switch (n.type) {
        case NodeType::Int8: { int8_t val; std::memcpy(&val, raw, 1); os << (int)val; break; }
        case NodeType::Int16: { int16_t val; std::memcpy(&val, raw, 2); os << val; break; }
        case NodeType::Int32: { int32_t val; std::memcpy(&val, raw, 4); os << val; break; }
        case NodeType::Int64: { int64_t val; std::memcpy(&val, raw, 8); os << val; break; }
        case NodeType::UInt8: { os << (unsigned)raw[0]; break; }
        case NodeType::UInt16: { uint16_t val; std::memcpy(&val, raw, 2); os << val; break; }
        case NodeType::UInt32: { uint32_t val; std::memcpy(&val, raw, 4); os << val; break; }
        case NodeType::UInt64: { uint64_t val; std::memcpy(&val, raw, 8); os << val; break; }
        case NodeType::Float: { float val; std::memcpy(&val, raw, 4); os << val; break; }
        case NodeType::Double: { double val; std::memcpy(&val, raw, 8); os << val; break; }
        case NodeType::Bool: { os << (raw[0] ? "true" : "false"); break; }
        case NodeType::Pointer: {
          uintptr_t val; std::memcpy(&val, raw, 8);
          os << "\"0x" << std::hex << val << std::dec << "\"";
          break;
        }
        default: {
          uint64_t val = 0; std::memcpy(&val, raw, std::min(ns, 8));
          os << "\"0x" << std::hex << val << std::dec << "\"";
          break;
        }
      }
    }

    if (!n.comment.empty())
      os << ",\"comment\":\"" << json_escape(n.comment) << "\"";

    os << "}";
  }

  os << "]}";
  return os.str();
}

void Inspector::mcp_set_node_type(int view_id, uint32_t offset, const std::string& type_name) {
  std::lock_guard lock(mu_);
  auto* v = find_view(view_id);
  if (!v) return;
  for (auto& n : v->nodes) {
    if (n.offset == offset) {
      n.type = node_type_from_name(type_name.c_str());
      break;
    }
  }
  mcp_scroll_view_id_ = view_id;
  mcp_scroll_offset_ = offset;
  mcp_scroll_pending_ = true;
}

void Inspector::mcp_set_node_name(int view_id, uint32_t offset, const std::string& name) {
  std::lock_guard lock(mu_);
  auto* v = find_view(view_id);
  if (!v) return;
  for (auto& n : v->nodes) {
    if (n.offset == offset) { n.name = name; break; }
  }
  mcp_scroll_view_id_ = view_id;
  mcp_scroll_offset_ = offset;
  mcp_scroll_pending_ = true;
}

void Inspector::mcp_set_node_comment(int view_id, uint32_t offset, const std::string& comment) {
  std::lock_guard lock(mu_);
  auto* v = find_view(view_id);
  if (!v) return;
  for (auto& n : v->nodes) {
    if (n.offset == offset) { n.comment = comment; break; }
  }
  mcp_scroll_view_id_ = view_id;
  mcp_scroll_offset_ = offset;
  mcp_scroll_pending_ = true;
}

void Inspector::mcp_apply_sdk_class(int view_id, const std::string& class_name) {
  std::lock_guard lock(mu_);
  auto* v = find_view(view_id);
  if (!v) return;
  v->nodes = make_sdk_nodes(class_name);
  v->name = class_name;
  v->fnames_scanned = false;
  auto it = classes_.find(class_name);
  if (it != classes_.end() && it->second.size > 0)
    v->size = it->second.size;
  v->prev_buffer.clear();
  refresh_view(*v);
  mcp_scroll_view_id_ = view_id;
  mcp_scroll_offset_ = 0;
  mcp_scroll_pending_ = true;
}

void Inspector::mcp_expand_pointer(int view_id, uint32_t offset) {
  std::lock_guard lock(mu_);
  auto* v = find_view(view_id);
  if (!v) return;
  for (auto& n : v->nodes) {
    if (n.offset == offset && n.type == NodeType::Pointer) {
      n.expanded = !n.expanded;
      if (n.expanded && n.children.empty()) {
        if (n.offset + 8 <= v->buffer.size()) {
          uintptr_t ptr_val = 0;
          std::memcpy(&ptr_val, &v->buffer[n.offset], 8);
          if (valid_ptr(ptr_val) && fmap_.contains(ptr_val)) {
            n.children = make_default_nodes(0x80);
            n.class_id = 0;
          }
        }
      }
      break;
    }
  }
}

std::vector<std::string> Inspector::mcp_list_sdk_classes(const std::string& filter) {
  std::vector<std::string> result;
  for (auto& cn : class_names_) {
    if (!filter.empty() && cn.find(filter) == std::string::npos) continue;
    result.push_back(cn);
  }
  return result;
}

std::string Inspector::mcp_get_sdk_class(const std::string& name) {
  auto it = classes_.find(name);
  if (it == classes_.end()) return "{}";

  auto flat = flatten_class(name);

  std::ostringstream os;
  os << "{\"name\":\"" << json_escape(it->second.name) << "\""
     << ",\"parent\":\"" << json_escape(it->second.parent) << "\""
     << ",\"size\":" << it->second.size
     << ",\"props\":[";

  for (size_t i = 0; i < flat.size(); ++i) {
    if (i > 0) os << ",";
    os << "{\"name\":\"" << json_escape(flat[i].name) << "\""
       << ",\"type\":\"" << json_escape(flat[i].type_name) << "\""
       << ",\"offset\":" << flat[i].offset
       << ",\"size\":" << flat[i].element_size
       << ",\"class\":\"" << json_escape(flat[i].class_name) << "\""
       << ",\"inherited\":" << (flat[i].inherited ? "true" : "false")
       << "}";
  }
  os << "]}";
  return os.str();
}

std::string Inspector::mcp_follow_pointer_chain(uintptr_t base, const std::vector<uint32_t>& offsets) {
  if (!reader_ || !reader_->is_attached()) return "{}";
  uintptr_t addr = base;
  for (auto off : offsets) {
    auto data = reader_->read(addr + off, 8);
    if (!data) return "{}";
    std::memcpy(&addr, data->data(), 8);
    if (!valid_ptr(addr)) return "{}";
  }

  auto data = reader_->read(addr, 8);
  std::ostringstream os;
  os << "{\"addr\":\"0x" << std::hex << addr << "\"";
  if (data) {
    os << ",\"hex\":\"";
    for (auto b : *data) {
      char h[4]; snprintf(h, sizeof(h), "%02X", b);
      os << h;
    }
    os << "\"";
  }
  os << "}";
  return os.str();
}

std::string Inspector::mcp_read_struct(uintptr_t addr, const std::string& class_name) {
  if (!reader_ || !reader_->is_attached()) return "{}";
  auto flat = flatten_class(class_name);
  if (flat.empty()) return "{}";

  auto cit = classes_.find(class_name);
  uint32_t total = (cit != classes_.end() && cit->second.size > 0) ? cit->second.size : 0x200;

  auto data = reader_->read(addr, total);
  if (!data) return "{}";

  std::ostringstream os;
  os << "{\"class\":\"" << json_escape(class_name) << "\",\"addr\":\"0x"
     << std::hex << addr << std::dec << "\",\"fields\":[";

  for (size_t i = 0; i < flat.size(); ++i) {
    auto& p = flat[i];
    if (i > 0) os << ",";
    os << "{\"name\":\"" << json_escape(p.name) << "\""
       << ",\"type\":\"" << json_escape(p.type_name) << "\""
       << ",\"offset\":" << p.offset
       << ",\"size\":" << p.element_size;

    if (p.offset + p.element_size <= data->size()) {
      const uint8_t* raw = &(*data)[p.offset];
      os << ",\"hex\":\"";
      int show = std::min<int>(p.element_size, 16);
      for (int b = 0; b < show; ++b) {
        char h[4]; snprintf(h, sizeof(h), "%02X", raw[b]);
        os << h;
      }
      os << "\"";

      os << ",\"value\":";
      if ((p.type_name.find("Float") != std::string::npos) && p.element_size >= 4) {
        float fv; std::memcpy(&fv, raw, 4); os << fv;
      } else if ((p.type_name.find("Double") != std::string::npos) && p.element_size >= 8) {
        double dv; std::memcpy(&dv, raw, 8); os << dv;
      } else if (p.type_name.find("Bool") != std::string::npos) {
        os << (raw[0] ? "true" : "false");
      } else if (p.element_size == 8) {
        uintptr_t val; std::memcpy(&val, raw, 8);
        os << "\"0x" << std::hex << val << std::dec << "\"";
      } else if (p.element_size == 4) {
        uint32_t val; std::memcpy(&val, raw, 4); os << val;
      } else if (p.element_size == 2) {
        uint16_t val; std::memcpy(&val, raw, 2); os << val;
      } else if (p.element_size == 1) {
        os << (unsigned)raw[0];
      } else {
        os << "null";
      }
    }
    os << "}";
  }
  os << "]}";
  return os.str();
}

std::string Inspector::mcp_scan_pattern(const std::string& pattern, int context_bytes, int max_results) {
  if (!reader_ || !reader_->is_attached()) return "{\"error\":\"not attached\"}";
  auto mmap = get_memory_map(pid_);
  if (!mmap) return "{\"error\":\"failed to get memory map\"}";

  // Try to find the base of the main executable module in the process
  uintptr_t base = find_game_base(*mmap);

  CachedModule mod;
  if (!base || !reader_ || !mod.cache(*reader_, *mmap, base))
    return "{\"error\":\"failed to cache module\"}";

  auto rvas = mod.find_pattern(pattern);

  // Limit results
  if (static_cast<int>(rvas.size()) > max_results)
    rvas.resize(max_results);

  // Count pattern bytes for window sizing
  size_t pat_len = 0;
  for (size_t i = 0; i < pattern.size(); ) {
    if (pattern[i] == ' ') { i++; continue; }
    if (i + 1 < pattern.size() && pattern[i] == '?' && pattern[i+1] == '?') { pat_len++; i += 2; }
    else { pat_len++; i += 2; }
  }

  std::ostringstream os;
  os << "{\"count\":" << rvas.size() << ",\"matches\":[";
  for (size_t i = 0; i < rvas.size(); ++i) {
    if (i > 0) os << ",";
    uintptr_t addr = base + rvas[i];
    os << "{\"addr\":\"0x" << std::hex << addr << "\""
       << ",\"rva\":\"0x" << rvas[i] << "\"";

    if (context_bytes > 0 || pat_len > 0) {
      size_t before = static_cast<size_t>(context_bytes);
      size_t window = before + pat_len + static_cast<size_t>(context_bytes);
      uintptr_t read_addr = addr >= before ? addr - before : addr;
      size_t actual_before = addr >= before ? before : 0;
      auto buf = reader_->read(read_addr, window > 0 ? window : 32);
      if (buf && !buf->empty()) {
        os << ",\"match_offset\":" << std::dec << actual_before
           << ",\"match_len\":" << pat_len
           << ",\"hex\":\"";
        for (auto b : *buf) { char h[4]; snprintf(h, sizeof(h), "%02X", b); os << h; }
        os << "\"";
      }
    }
    os << "}";
  }
  os << "]}";
  return os.str();
}

// ── Main Loop ────────────────────────────────────────────────────────────────

void Inspector::run() {
  if (pid_ > 0) {
    auto mmap = get_memory_map(pid_);
    if (mmap) fmap_.build(*mmap);
  }

  load_sdk();
  load_project();

  if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) {
    std::cerr << "[inspector] SDL_Init error: " << SDL_GetError() << "\n";
    return;
  }

  SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);

  SDL_Window* window = SDL_CreateWindow("Inspector",
      SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
      1600, 900, SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_MAXIMIZED | SDL_WINDOW_ALLOW_HIGHDPI);
  if (!window) {
    std::cerr << "[inspector] SDL_CreateWindow error: " << SDL_GetError() << "\n";
    SDL_Quit();
    return;
  }
  SDL_MaximizeWindow(window);

  SDL_GLContext gl_ctx = SDL_GL_CreateContext(window);
  SDL_GL_MakeCurrent(window, gl_ctx);
  SDL_GL_SetSwapInterval(1);

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO();
  io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
  ImGui::StyleColorsDark();

  ImFontConfig fc;
  fc.SizePixels = 14.0f;
  io.Fonts->AddFontDefault(&fc);

  ImGui_ImplSDL2_InitForOpenGL(window, gl_ctx);
  ImGui_ImplOpenGL3_Init("#version 330");

  bool running = true;
  while (running) {
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
      ImGui_ImplSDL2_ProcessEvent(&event);
      if (event.type == SDL_QUIT || (event.type == SDL_WINDOWEVENT &&
          event.window.event == SDL_WINDOWEVENT_CLOSE)) {
        running = false;
      }
    }

    double now = SDL_GetTicks() / 1000.0;
    if (now - last_refresh_ >= kRefreshInterval && reader_ && reader_->is_attached()) {
      last_refresh_ = now;

      if (now - last_mmap_refresh_ >= 5.0 && pid_ > 0) {
        last_mmap_refresh_ = now;
        auto new_map = get_memory_map(pid_);
        if (new_map) fmap_.build(*new_map);
      }

      std::lock_guard lock(mu_);
      for (auto& v : views_) {
        if (v.base_address != 0) refresh_view(v);
      }
    }

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplSDL2_NewFrame();
    ImGui::NewFrame();

    ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport());

    if (ImGui::Begin("Classes")) {
      if (!is_attached()) {
        ImGui::TextColored(ImVec4(1.f, 0.6f, 0.2f, 1.f), "No process attached.");
        ImGui::Text("Process -> Attach... to select a target.");
      }
      render_class_browser();
    }
    ImGui::End();

    if (ImGui::Begin("Explorer")) {
      if (!is_attached())
        ImGui::TextColored(ImVec4(1.f, 0.6f, 0.2f, 1.f), "Attach a process to browse memory.");
      render_memory_explorer();
    }
    ImGui::End();

    // Class views (ReClass-style tabs)
    {
      std::lock_guard lock(mu_);
      int to_close = -1;
      for (int i = 0; i < static_cast<int>(views_.size()); ++i) {
        auto& v = views_[i];
        char title[128];
        snprintf(title, sizeof(title), "%s [0x%lX]###view_%d", v.name.c_str(), v.base_address, v.id);

        if (follow_mcp_ && mcp_scroll_pending_ && mcp_scroll_view_id_ == v.id) {
          ImGui::SetNextWindowFocus();
        }

        if (v.place_fullscreen_once) {
          ImGuiViewport* vp = ImGui::GetMainViewport();
          ImGui::SetNextWindowPos(vp->Pos, ImGuiCond_FirstUseEver);
          ImGui::SetNextWindowSize(vp->Size, ImGuiCond_FirstUseEver);
          v.place_fullscreen_once = false;
        }

        bool open = true;
        if (ImGui::Begin(title, &open)) {
          render_class_view(v);
        }
        ImGui::End();
        if (!open) to_close = i;
      }
      if (to_close >= 0)
        views_.erase(views_.begin() + to_close);
    }

    if (ImGui::BeginMainMenuBar()) {
      if (ImGui::BeginMenu("Process")) {
        if (ImGui::MenuItem("Attach...")) show_attach_ = true;
        if (is_attached() && ImGui::MenuItem("Detach")) detach();
        ImGui::EndMenu();
      }
      if (ImGui::BeginMenu("Memory")) {
        if (ImGui::MenuItem("New View")) {
          std::lock_guard lock(mu_);
          ClassView nv;
          nv.id = next_view_id_++;
          nv.size = 0x200;
          nv.name = "new";
          nv.nodes = make_default_nodes(nv.size);
          nv.place_fullscreen_once = true;
          views_.push_back(std::move(nv));
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Save Project")) save_project();
        if (ImGui::MenuItem("Load Project")) load_project();
        ImGui::EndMenu();
      }
      if (ImGui::BeginMenu("Edit")) {
        if (ImGui::MenuItem("Settings")) show_settings_ = true;
        ImGui::EndMenu();
      }
      if (is_attached()) {
        ImGui::SameLine(ImGui::GetWindowWidth() - 120);
        ImGui::TextColored(ImVec4(0.4f, 1.f, 0.4f, 1.f), "PID %d", pid_);
      }
      ImGui::EndMainMenuBar();
    }

    if (show_attach_) {
      static char pid_input[24]{};
      static char search_buf[128]{};
      static int selected_pid = 0;
      static bool attach_auto_connect = false;
      static std::vector<ProcessInfo> proc_list;
      static double proc_list_time = 0;
      double now = SDL_GetTicks() / 1000.0;
      if (proc_list.empty() || now - proc_list_time > 2.0) {
        proc_list = list_processes();
        proc_list_time = now;
      }
      ImGuiViewport* vp_attach = ImGui::GetMainViewport();
      ImGui::SetNextWindowPos(vp_attach->Pos, ImGuiCond_FirstUseEver);
      ImGui::SetNextWindowSize(vp_attach->Size, ImGuiCond_FirstUseEver);
      if (ImGui::Begin("Attach to process", &show_attach_)) {
        ImGui::SetNextItemWidth(100.f);
        ImGui::InputText("PID", pid_input, sizeof(pid_input));
        int pid_typed = 0;
        if (sscanf(pid_input, "%d", &pid_typed) == 1 && pid_typed > 0)
          selected_pid = pid_typed;
        ImGui::SameLine(0, 16.f);
        ImGui::SetNextItemWidth(220.f);
        ImGui::InputTextWithHint("##procsearch", "Search (PID, name, path)...", search_buf, sizeof(search_buf));
        ImGui::Checkbox("Auto-connect by binary name", &attach_auto_connect);
        if (ImGui::Button("Attach") && selected_pid > 0) {
          if (attach(selected_pid)) {
            if (attach_auto_connect) {
              std::string name;
              auto info = get_process_info(selected_pid);
              if (info) {
                name = info->comm;
              } else {
                for (const auto& p : proc_list) {
                  if (p.pid == selected_pid) {
                    name = p.comm;
                    break;
                  }
                }
              }
              if (!name.empty()) {
                InspectorConfig c = config_load();
                c.auto_connect_exe = name;
                config_save(c);
              }
            }
            show_attach_ = false;
          }
        }
        ImGui::Separator();
        ImGui::Text("Process list (select to set PID)");
        ImGui::BeginChild("##proclist", ImVec2(0, 200), ImGuiChildFlags_Borders);
        std::string search_lower = search_buf;
        for (char& c : search_lower) if (c >= 'A' && c <= 'Z') c += 32;
        for (const auto& p : proc_list) {
          if (!search_lower.empty()) {
            std::string comm_lower = p.comm;
            for (char& c : comm_lower) if (c >= 'A' && c <= 'Z') c += 32;
            std::string path_lower = p.exe_path;
            for (char& c : path_lower) if (c >= 'A' && c <= 'Z') c += 32;
            std::string pid_str = std::to_string(p.pid);
            if (pid_str.find(search_buf) == std::string::npos &&
                comm_lower.find(search_lower) == std::string::npos &&
                path_lower.find(search_lower) == std::string::npos)
              continue;
          }
          ImGui::PushID(p.pid);
          bool sel = (selected_pid == p.pid);
          if (ImGui::Selectable((std::to_string(p.pid) + "  " + p.comm + "  " + p.exe_path).c_str(), sel)) {
            selected_pid = p.pid;
            snprintf(pid_input, sizeof(pid_input), "%d", p.pid);
          }
          ImGui::PopID();
        }
        ImGui::EndChild();
      }
      ImGui::End();
    }

    if (show_settings_) {
      static InspectorConfig edit_cfg;
      static char auto_connect_buf[256]{};
      static bool need_load = true;
      if (need_load) {
        edit_cfg = config_load();
        snprintf(auto_connect_buf, sizeof(auto_connect_buf), "%s", edit_cfg.auto_connect_exe.c_str());
        need_load = false;
      }
      ImGuiViewport* vp_settings = ImGui::GetMainViewport();
      ImGui::SetNextWindowPos(vp_settings->Pos, ImGuiCond_FirstUseEver);
      ImGui::SetNextWindowSize(vp_settings->Size, ImGuiCond_FirstUseEver);
      if (ImGui::Begin("Settings", &show_settings_)) {
        ImGui::Checkbox("Enable MCP server", &edit_cfg.mcp_enabled);
        ImGui::SetNextItemWidth(120.f);
        ImGui::InputInt("MCP port", &edit_cfg.mcp_port, 0, 0);
        if (edit_cfg.mcp_port <= 0) edit_cfg.mcp_port = 8082;
        ImGui::SetNextItemWidth(200.f);
        ImGui::InputText("Auto-connect executable name", auto_connect_buf, sizeof(auto_connect_buf));
        edit_cfg.auto_connect_exe = auto_connect_buf;
        if (ImGui::Button("Save")) {
          config_save(edit_cfg);
          need_load = true;
          show_settings_ = false;
        }
        ImGui::SameLine();
        ImGui::TextDisabled("(%s)", config_path().c_str());
      }
      ImGui::End();
      if (!show_settings_) need_load = true;
    }

    ImGui::Render();
    int w, h;
    SDL_GetWindowSize(window, &w, &h);
    glViewport(0, 0, w, h);
    glClearColor(0.1f, 0.1f, 0.12f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    SDL_GL_SwapWindow(window);

    SDL_Delay(33);
  }

  save_project();

  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplSDL2_Shutdown();
  ImGui::DestroyContext();
  SDL_GL_DeleteContext(gl_ctx);
  SDL_DestroyWindow(window);
  SDL_Quit();
}
