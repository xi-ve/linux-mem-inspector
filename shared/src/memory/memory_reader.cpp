#include "shared/memory/memory_reader.hpp"
#include "shared/memory/raider_mem_ioctl.h"
#include <fcntl.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>

static constexpr const char* kKmodDevice = "/dev/raider_mem";

namespace raider {

MemoryReader::MemoryReader(int pid, ReadMethod method)
    : pid_(pid), method_(method) {}

MemoryReader::~MemoryReader() { detach(); }

bool MemoryReader::attach_kernel() {
    kmod_fd_ = open(kKmodDevice, O_RDWR);
    if (kmod_fd_ < 0) return false;
    raider_set_pid sp{ pid_, 0 };
    if (ioctl(kmod_fd_, RAIDER_SET_PID, &sp) < 0) {
        close(kmod_fd_);
        kmod_fd_ = -1;
        return false;
    }
    return true;
}

bool MemoryReader::attach_vm() {
    std::string status = "/proc/" + std::to_string(pid_) + "/status";
    return access(status.c_str(), F_OK) == 0;
}

bool MemoryReader::attach() {
    if (attached_) return true;
    if (method_ == ReadMethod::KernelMem) {
        if (attach_kernel()) { attached_ = true; return true; }
        // Fallback to ProcessVm if kmod unavailable
        fprintf(stderr, "[reader] /dev/raider_mem unavailable — falling back to process_vm_readv\n");
        method_ = ReadMethod::ProcessVm;
    }
    if (!attach_vm()) return false;
    attached_ = true;
    return true;
}

void MemoryReader::detach() {
    if (!attached_) return;
    if (kmod_fd_ >= 0) { close(kmod_fd_); kmod_fd_ = -1; }
    attached_ = false;
}

bool MemoryReader::read_kernel(uintptr_t address, std::span<uint8_t> out) {
    // Use pread: offset = target VA, kmod routes to target process memory.
    uint8_t* ptr  = out.data();
    size_t   left = out.size();
    off_t    off  = static_cast<off_t>(address);
    while (left > 0) {
        ssize_t n = pread(kmod_fd_, ptr, left, off);
        if (n <= 0) return false;
        ptr  += static_cast<size_t>(n);
        off  += static_cast<off_t>(n);
        left -= static_cast<size_t>(n);
    }
    return true;
}

bool MemoryReader::read_vm(uintptr_t address, std::span<uint8_t> out) {
    iovec local  = { out.data(), out.size() };
    iovec remote = { reinterpret_cast<void*>(address), out.size() };
    ssize_t n = process_vm_readv(static_cast<pid_t>(pid_), &local, 1, &remote, 1, 0);
    return n == static_cast<ssize_t>(out.size());
}

std::optional<std::vector<uint8_t>> MemoryReader::read(uintptr_t address, size_t size) {
    std::vector<uint8_t> buf(size);
    if (!read_into(address, buf)) return std::nullopt;
    return buf;
}

bool MemoryReader::read_into(uintptr_t address, std::span<uint8_t> out) {
    if (!attached_ || out.empty()) return false;
    if (method_ == ReadMethod::KernelMem) return read_kernel(address, out);
    return read_vm(address, out);
}

uint64_t MemoryReader::get_gs_base() const {
    if (kmod_fd_ < 0) return 0;
    raider_gs_base gs{};
    if (ioctl(kmod_fd_, RAIDER_GET_GS_BASE, &gs) < 0) return 0;
    return gs.gs_base;
}

uint64_t MemoryReader::read_u64(uintptr_t address) const {
    if (kmod_fd_ >= 0) {
        raider_read8 r8{ .addr = address };
        if (ioctl(kmod_fd_, RAIDER_READ8, &r8) == 0 && r8.result == 8)
            return r8.value;
        return 0;
    }
    // Fallback via process_vm_readv
    uint64_t val = 0;
    iovec local{ &val, sizeof(val) };
    iovec remote{ reinterpret_cast<void*>(address), sizeof(val) };
    process_vm_readv(pid_, &local, 1, &remote, 1, 0);
    return val;
}

} // namespace raider
