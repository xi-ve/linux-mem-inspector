#include "shared/scanner/pattern_scanner.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>

namespace raider {

// ── Pattern parsing ───────────────────────────────────────────────────────

namespace {

struct ParsedPat {
    std::vector<uint8_t> bytes;
    std::vector<bool>    mask;
};

ParsedPat parse(const std::string& pat) {
    ParsedPat p;
    size_t i = 0;
    while (i < pat.size()) {
        if (pat[i] == ' ') { i++; continue; }
        if (i + 1 < pat.size() && pat[i] == '?' && pat[i+1] == '?') {
            p.bytes.push_back(0);
            p.mask.push_back(false);
            i += 2;
        } else {
            char hex[3] = {pat[i], pat[i+1], '\0'};
            p.bytes.push_back(static_cast<uint8_t>(std::strtoul(hex, nullptr, 16)));
            p.mask.push_back(true);
            i += 2;
        }
    }
    return p;
}

std::vector<size_t> search(const uint8_t* data, size_t len, const ParsedPat& pat) {
    std::vector<size_t> hits;
    if (pat.bytes.empty() || pat.bytes.size() > len) return hits;
    size_t end = len - pat.bytes.size();
    for (size_t i = 0; i <= end; i++) {
        bool ok = true;
        for (size_t j = 0; j < pat.bytes.size(); j++) {
            if (pat.mask[j] && data[i+j] != pat.bytes[j]) { ok = false; break; }
        }
        if (ok) hits.push_back(i);
    }
    return hits;
}

bool is_wine(const std::string& path) {
    return path.find("/wine/") != std::string::npos;
}

} // namespace

// ── CachedModule ──────────────────────────────────────────────────────────

bool CachedModule::cache(MemoryReader& reader, const std::vector<MemoryRegion>& map,
                         uintptr_t game_base) {
    base = game_base;
    data.clear();
    regions.clear();

    struct RegInfo { uintptr_t start, rva; size_t size; bool executable; };
    std::vector<RegInfo> regs;
    size_t total = 0;

    for (const auto& reg : map) {
        if (!reg.readable) continue;
        if (is_wine(reg.pathname)) continue;
        if (reg.start < game_base || reg.start > game_base + 0x20000000ULL) continue;
        size_t sz = reg.end - reg.start;
        regs.push_back({reg.start, reg.start - game_base, sz, reg.executable});
        total += sz;
    }

    if (regs.empty()) return false;
    data.resize(total);

    size_t offset = 0;
    for (const auto& r : regs) {
        constexpr size_t kChunk = 1u << 20;
        size_t done = 0;
        while (done < r.size) {
            size_t chunk = std::min(kChunk, r.size - done);
            auto buf = reader.read(r.start + done, chunk);
            if (buf && !buf->empty()) {
                std::memcpy(data.data() + offset + done, buf->data(), buf->size());
                if (buf->size() < chunk)
                    std::memset(data.data() + offset + done + buf->size(), 0, chunk - buf->size());
            } else {
                std::memset(data.data() + offset + done, 0, chunk);
            }
            done += chunk;
        }
        regions.push_back({r.rva, offset, r.size, r.executable});
        offset += r.size;
    }

    return true;
}

const uint8_t* CachedModule::at_rva(uintptr_t rva, size_t* avail) const {
    for (const auto& reg : regions) {
        if (rva >= reg.rva && rva < reg.rva + reg.size) {
            size_t off = rva - reg.rva;
            if (avail) *avail = reg.size - off;
            return data.data() + reg.offset + off;
        }
    }
    if (avail) *avail = 0;
    return nullptr;
}

std::vector<uintptr_t> CachedModule::find_pattern(const std::string& pattern) const {
    auto pat = parse(pattern);
    if (pat.bytes.empty()) return {};

    std::vector<uintptr_t> results;
    for (const auto& reg : regions) {
        if (!reg.executable) continue;
        for (size_t m : search(data.data() + reg.offset, reg.size, pat))
            results.push_back(reg.rva + m);
    }
    return results;
}

bool CachedModule::is_data_rva(uintptr_t rva) const {
    for (const auto& reg : regions)
        if (rva >= reg.rva && rva < reg.rva + reg.size)
            return !reg.executable;
    return false;
}

// ── find_game_base ────────────────────────────────────────────────────────

uintptr_t find_game_base(const std::vector<MemoryRegion>& map) {
    constexpr uintptr_t kBase = 0x140000000;

    for (const auto& reg : map)
        if (reg.readable && kBase >= reg.start && kBase < reg.end)
            return kBase;

    // Fallback: largest anonymous executable region
    uintptr_t best = 0;
    size_t    best_sz = 0;
    for (const auto& reg : map) {
        if (!reg.readable || !reg.executable) continue;
        if (is_wine(reg.pathname)) continue;
        size_t sz = reg.end - reg.start;
        if (sz > best_sz) { best_sz = sz; best = reg.start; }
    }
    return best;
}

} // namespace raider
