#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace raider {

// KernelMem: reads via /dev/raider_mem (page-table walk, no mmap_lock).
//            Requires raider_mem.ko to be loaded. Falls back to ProcessVm.
// ProcessVm: reads via process_vm_readv(2). Fallback when kmod unavailable.
// ProcMem is intentionally removed (unsafe under EAC).
enum class ReadMethod { KernelMem, ProcessVm };

class MemoryReader {
public:
    // ProcessVm (process_vm_readv) is the default; use KernelMem explicitly
    // to leverage the raider_mem kernel module when available.
    explicit MemoryReader(int pid, ReadMethod method = ReadMethod::ProcessVm);
    ~MemoryReader();

    MemoryReader(const MemoryReader&)            = delete;
    MemoryReader& operator=(const MemoryReader&) = delete;
    MemoryReader(MemoryReader&&)                 = default;
    MemoryReader& operator=(MemoryReader&&)      = default;

    bool attach();
    void detach();
    bool is_attached() const { return attached_; }

    std::optional<std::vector<uint8_t>> read(uintptr_t address, size_t size);
    bool read_into(uintptr_t address, std::span<uint8_t> out);

    // Fast single 8-byte read via RAIDER_READ8 (one ioctl, minimal overhead).
    // Returns 0 on failure. Use for pointer chasing.
    uint64_t read_u64(uintptr_t address) const;

    // Returns the GS base (Wine TEB address) of the target process via
    // RAIDER_GET_GS_BASE ioctl. Returns 0 on failure or if kmod unavailable.
    uint64_t get_gs_base() const;

    int        pid()    const { return pid_; }
    ReadMethod method() const { return method_; }

private:
    bool attach_kernel();
    bool attach_vm();
    bool read_kernel(uintptr_t address, std::span<uint8_t> out);
    bool read_vm(uintptr_t address, std::span<uint8_t> out);

    int        pid_;
    ReadMethod method_;
    int        kmod_fd_{ -1 };   // /dev/raider_mem fd (KernelMem)
    bool       attached_{};
};

} // namespace raider
