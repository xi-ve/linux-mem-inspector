#pragma once
#include "shared/memory/memory_map.hpp"
#include "shared/memory/memory_reader.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace raider {

// Snapshot of game .text and .rdata sections held in process memory.
// Caching once avoids TOCTOU races and reduces syscall overhead for
// multi-pass pattern scanners.
struct CachedModule {
    struct Region {
        uintptr_t rva;
        size_t    offset;   // byte offset into `data`
        size_t    size;
        bool      executable;
    };

    std::vector<uint8_t> data;
    std::vector<Region>  regions;
    uintptr_t            base{};

    bool cache(MemoryReader& reader, const std::vector<MemoryRegion>& map,
               uintptr_t game_base);

    // Returns pointer into cached data at rva, sets *avail to contiguous
    // bytes available. Returns nullptr if rva is not cached.
    const uint8_t* at_rva(uintptr_t rva, size_t* avail = nullptr) const;

    // Hex-with-wildcard pattern search. Returns all matching RVAs.
    std::vector<uintptr_t> find_pattern(const std::string& pattern) const;

    bool is_data_rva(uintptr_t rva) const;
};

// Locate the game's base load address in the memory map.
// ARC Raiders loads at 0x140000000 under Proton/Wine.
uintptr_t find_game_base(const std::vector<MemoryRegion>& map);

} // namespace raider
