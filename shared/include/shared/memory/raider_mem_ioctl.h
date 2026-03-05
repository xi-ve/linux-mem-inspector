/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * raider_mem_ioctl.h — Shared ioctl definitions for raider_mem kernel module.
 * Used by both kernel module and userspace.
 */
#ifndef RAIDER_MEM_IOCTL_H
#define RAIDER_MEM_IOCTL_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <linux/types.h>
#include <sys/ioctl.h>
#endif

struct raider_set_pid {
	__s32 pid;
	__u32 _pad;
};

/* Scatter-gather entry for RAIDER_BATCH_READ */
struct raider_sg_entry {
	__u64 addr;    /* target virtual address to read */
	__u64 buf;     /* userspace buffer pointer */
	__u32 len;     /* bytes to read */
	__s32 result;  /* bytes read, or negative errno */
};

struct raider_batch_read {
	__u64 entries;  /* pointer to array of raider_sg_entry */
	__u32 count;    /* number of entries */
	__u32 _pad;
};

/*
 * Fixed-stride multi-read: read `count` chunks of `stride` bytes each from
 * addresses in `addrs` (u64 array) into contiguous `out` buffer.
 * Results packed: out[0..stride-1] = read from addrs[0], etc.
 * `results` (optional, may be NULL): s32 array, bytes read per entry.
 */
struct raider_multi_read {
	__u64 addrs;    /* pointer to __u64[count] array of target addresses */
	__u64 out;      /* pointer to contiguous output buffer (count * stride) */
	__u64 results;  /* pointer to __s32[count] or 0 to skip */
	__u32 count;    /* number of reads */
	__u32 stride;   /* bytes per read (must be <= 4096) */
};

/*
 * Get the GS base (Windows TEB address) for any thread in the target process.
 * Wine/Proton sets GS to point to the TEB via arch_prctl(ARCH_SET_GS).
 * This is read directly from task->thread.gsbase — no ptrace required.
 * TEB+0x60 = PEB pointer (Windows layout).
 */
struct raider_gs_base {
	__u64 gs_base;  /* first non-zero gsbase found among process threads */
};

/*
 * Fast single 8-byte read at a target virtual address.
 * Minimal overhead: one page walk + one 8-byte kernel read.
 */
struct raider_read8 {
	__u64 addr;    /* target virtual address */
	__u64 value;   /* output: 8 bytes read */
	__s32 result;  /* 8 on success, 0 on failure */
	__u32 _pad;
};

#define RAIDER_BATCH_MAX 1024
#define RAIDER_MULTI_MAX 4096

/* Pre-allocated MULTI_READ: stride must be <= RAIDER_MULTI_PREALLOC_STRIDE */
#define RAIDER_MULTI_PREALLOC_STRIDE 256

#define RAIDER_SET_PID     _IOW('R', 1, struct raider_set_pid)
#define RAIDER_BATCH_READ  _IOWR('R', 2, struct raider_batch_read)
#define RAIDER_MULTI_READ  _IOWR('R', 3, struct raider_multi_read)
#define RAIDER_GET_GS_BASE _IOR('R',  4, struct raider_gs_base)
#define RAIDER_READ8       _IOWR('R', 5, struct raider_read8)

#endif /* RAIDER_MEM_IOCTL_H */
