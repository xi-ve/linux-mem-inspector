#include "shared/memory/memory_map.hpp"
#include <algorithm>
#include <charconv>
#include <fstream>
#include <string>

namespace raider {

namespace {
std::optional<uintptr_t> parse_hex(std::string_view s) {
    uintptr_t v = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v, 16);
    if (ec != std::errc{} || ptr != s.data() + s.size()) return std::nullopt;
    return v;
}
} // namespace

std::optional<std::vector<MemoryRegion>> get_memory_map(int pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream f(path);
    if (!f) return std::nullopt;

    std::vector<MemoryRegion> regions;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        size_t dash  = line.find('-');
        size_t space = line.find(' ', dash + 1);
        if (dash == std::string::npos || space == std::string::npos) continue;

        auto s = parse_hex({line.data(), dash});
        auto e = parse_hex({line.data() + dash + 1, space - dash - 1});
        if (!s || !e) continue;

        if (line.size() < space + 5) continue;
        const char* p = line.data() + space + 1;

        MemoryRegion r;
        r.start      = *s;
        r.end        = *e;
        r.readable   = p[0] == 'r';
        r.writable   = p[1] == 'w';
        r.executable = p[2] == 'x';

        size_t path_pos = line.find('/', space);
        if (path_pos != std::string::npos)
            r.pathname = line.substr(path_pos);

        regions.push_back(std::move(r));
    }
    return regions;
}

void FastMemMap::build(const std::vector<MemoryRegion>& map) {
    ranges.clear();
    for (const auto& r : map)
        if (r.readable) ranges.push_back({r.start, r.end});

    std::sort(ranges.begin(), ranges.end(),
              [](const Range& a, const Range& b){ return a.start < b.start; });

    std::vector<Range> merged;
    for (const auto& r : ranges) {
        if (!merged.empty() && r.start <= merged.back().end)
            merged.back().end = std::max(merged.back().end, r.end);
        else
            merged.push_back(r);
    }
    ranges = std::move(merged);
}

bool FastMemMap::contains(uintptr_t addr) const {
    if (!addr || ranges.empty()) return false;
    auto it = std::upper_bound(ranges.begin(), ranges.end(), addr,
                               [](uintptr_t a, const Range& r){ return a < r.start; });
    if (it == ranges.begin()) return false;
    return addr < (--it)->end;
}

} // namespace raider
