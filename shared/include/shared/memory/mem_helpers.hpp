#pragma once
#include "shared/memory/memory_reader.hpp"
#include <cstdint>

namespace raider {

uint8_t   read_u8 (MemoryReader& r, uintptr_t addr);
uint32_t  read_u32(MemoryReader& r, uintptr_t addr);
uint64_t  read_u64(MemoryReader& r, uintptr_t addr);
float     read_f32(MemoryReader& r, uintptr_t addr);

bool valid_ptr(uintptr_t p);

} // namespace raider
