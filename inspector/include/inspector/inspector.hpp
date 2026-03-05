#pragma once

#include "shared/memory/mem_helpers.hpp"
#include "shared/memory/memory_reader.hpp"
#include "shared/memory/memory_map.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace raider {

// ── SDK types ─────────────────────────────────────────────────────────────────

struct FlatProperty {
  std::string class_name;
  std::string name;
  std::string type_name;
  uint32_t offset{};
  uint32_t element_size{};
  bool inherited{false};
};

struct SDKClass {
  std::string name;
  std::string parent;
  uint32_t size{};
  std::vector<FlatProperty> props;
};

// ── Node type system ─────────────────────────────────────────────────────────

enum class NodeType {
  Hex8, Hex16, Hex32, Hex64,
  Int8, Int16, Int32, Int64,
  UInt8, UInt16, UInt32, UInt64,
  Float, Double, Bool,
  Pointer,
  UTF8Text, UTF16Text,
  Vec3,
};

int node_size(NodeType t);
const char* node_type_name(NodeType t);
NodeType node_type_from_name(const char* name);

// ── Memory node (one row in the ReClass view) ────────────────────────────────

struct MemoryNode {
  NodeType type{NodeType::Hex64};
  uint32_t offset{};
  std::string name;
  std::string comment;
  std::string fname_hint;  // user-set label hint shown in UI
  bool expanded{false};
  int class_id{-1};                 // for Pointer: which ClassView to expand into
  std::vector<MemoryNode> children; // for Pointer: inline sub-nodes
};

// ── Class view (one "class" tab in the inspector) ────────────────────────────

struct ClassView {
  int id{};
  std::string name;
  uintptr_t base_address{};
  uint32_t size{0x200};
  std::vector<MemoryNode> nodes;
  std::vector<uint8_t> buffer;
  std::vector<uint8_t> prev_buffer;
  bool fnames_scanned{false};

  // UI state
  char addr_input[24]{};
  bool editing_name{false};
  int editing_node{-1};
  int editing_comment_node{-1};
  char edit_buf[128]{};
  bool place_fullscreen_once{false};
};

// ── MCP result types ─────────────────────────────────────────────────────────

struct MCPReadResult {
  uintptr_t addr;
  std::vector<uint8_t> data;
};

// ── Inspector class ──────────────────────────────────────────────────────────

class Inspector {
public:
  explicit Inspector(int pid = 0);
  void run();

  bool attach(int pid);
  void detach();
  bool is_attached() const { return reader_ != nullptr && reader_->is_attached(); }
  int pid() const { return pid_; }

  // ── MCP API (thread-safe, mutex-protected) ─────────────────────────────
  MCPReadResult mcp_read_memory(uintptr_t addr, size_t size);
  std::string mcp_read_string(uintptr_t addr, size_t max_len);

  int mcp_open_view(uintptr_t addr, const std::string& label, uint32_t size = 0x200);
  void mcp_close_view(int id);
  std::vector<std::pair<int, std::string>> mcp_list_views();
  std::string mcp_get_view_info(int id);

  void mcp_set_node_type(int view_id, uint32_t offset, const std::string& type_name);
  void mcp_set_node_name(int view_id, uint32_t offset, const std::string& name);
  void mcp_set_node_comment(int view_id, uint32_t offset, const std::string& comment);
  void mcp_apply_sdk_class(int view_id, const std::string& class_name);
  void mcp_expand_pointer(int view_id, uint32_t offset);

  std::vector<std::string> mcp_list_sdk_classes(const std::string& filter);
  std::string mcp_get_sdk_class(const std::string& name);

  std::string mcp_follow_pointer_chain(uintptr_t base, const std::vector<uint32_t>& offsets);
  std::string mcp_read_struct(uintptr_t addr, const std::string& class_name);
  std::string mcp_scan_pattern(const std::string& pattern, int context_bytes, int max_results);

private:
  void load_sdk();
  std::vector<FlatProperty> flatten_class(const std::string& name) const;
  void refresh_view(ClassView& v);
  std::vector<MemoryNode> make_default_nodes(uint32_t size);
  std::vector<MemoryNode> make_sdk_nodes(const std::string& class_name);
  void split_node_at(ClassView& v, int node_idx, NodeType new_type);
  ClassView* find_view(int id);

  void render_node_row(ClassView& v, MemoryNode& node, int idx, int depth);
  void render_pointer_children(ClassView& v, MemoryNode& ptr_node, uintptr_t target_addr,
                               int depth, int id_base);
  void render_class_view(ClassView& v);
  void render_class_browser();
  void render_memory_explorer();
  void render_context_menu(ClassView& v, int node_idx);

  void save_project();
  void load_project();

  int pid_{0};
  std::unique_ptr<MemoryReader> reader_;
  FastMemMap fmap_;

  std::mutex mu_;  // protects views_ for MCP access
  std::vector<ClassView> views_;
  int next_view_id_{1};

  std::unordered_map<std::string, SDKClass> classes_;
  std::vector<std::string> class_names_;

  char class_filter_[128]{};

  // Memory explorer state
  char explorer_addr_input_[24]{};
  char explorer_size_input_[12]{"0x400"};
  char explorer_label_input_[64]{};
  struct AddrBookmark { std::string label; uintptr_t addr; uint32_t size; };
  std::vector<AddrBookmark> explorer_history_;
  std::vector<AddrBookmark> explorer_bookmarks_;

  double last_refresh_{0};
  double last_mmap_refresh_{0};
  static constexpr double kRefreshInterval = 0.25;

  double highlight_duration_{1.0};
  double last_highlight_time_{0};

  // MCP follow mode: auto-scroll to last MCP-modified node
  bool follow_mcp_{true};
  int mcp_scroll_view_id_{-1};
  uint32_t mcp_scroll_offset_{0};
  bool mcp_scroll_pending_{false};

  bool show_settings_{false};
  bool show_attach_{false};
};

} // namespace raider
