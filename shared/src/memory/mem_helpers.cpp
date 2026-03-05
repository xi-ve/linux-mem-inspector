#include "shared/memory/mem_helpers.hpp"
#include <cstring>

namespace raider {

namespace {
template<typename T>
T read_typed(MemoryReader& r, uintptr_t addr) {
    T v{};
    uint8_t buf[sizeof(T)];
    if (r.read_into(addr, buf)) std::memcpy(&v, buf, sizeof(T));
    return v;
}
} // namespace

uint8_t  read_u8 (MemoryReader& r, uintptr_t addr) { return read_typed<uint8_t> (r, addr); }
uint32_t read_u32(MemoryReader& r, uintptr_t addr) { return read_typed<uint32_t>(r, addr); }
uint64_t read_u64(MemoryReader& r, uintptr_t addr) { return read_typed<uint64_t>(r, addr); }
float    read_f32(MemoryReader& r, uintptr_t addr) { return read_typed<float>   (r, addr); }

bool valid_ptr(uintptr_t p) {
    return p > 0x10000 && p < 0x800000000000ULL;
}

} // namespace raider
