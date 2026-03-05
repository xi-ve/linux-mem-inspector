#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace raider {

struct MemoryRegion {
    uintptr_t   start{};
    uintptr_t   end{};
    bool        readable{};
    bool        writable{};
    bool        executable{};
    std::string pathname;
};

std::optional<std::vector<MemoryRegion>> get_memory_map(int pid);

// O(log n) membership test — build once from a full map, query in hot paths.
struct FastMemMap {
    struct Range { uintptr_t start, end; };
    std::vector<Range> ranges;

    void build(const std::vector<MemoryRegion>& map);
    bool contains(uintptr_t addr) const;
};

} // namespace raider
