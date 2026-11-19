/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * toygpu UAPI: shared by the kernel module and user space.
 *
 * Model (a tiny caricature of a GPU driver):
 *   - each open() of /dev/toygpu is a "client" with up to TOYGPU_MAX_BOS buffer objects
 *   - BO_CREATE allocates a buffer object (BO) and returns a handle
 *   - mmap(offset = handle * page_size) maps a BO into the process
 *   - SUBMIT points at a command buffer in user memory; the "GPU" executes each
 *     command (WRITE32 value at offset in the target BO)
 */
#ifndef TOYGPU_UAPI_H
#define TOYGPU_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define TOYGPU_MAX_BOS      64
#define TOYGPU_MAX_BO_SIZE  (1u << 20)      /* 1 MiB */
#define TOYGPU_MAX_CMDS     256

struct toygpu_info {
	__u32 version;
	__u8  num_engines;
	/* 3 bytes of implicit padding here (a UAPI review would ask for explicit fields) */
	__u64 vram_size;
	__u32 max_bos;
	/* 4 bytes of implicit tail padding */
};

struct toygpu_bo_create {
	__u64 size;         /* in: bytes (1 .. TOYGPU_MAX_BO_SIZE) */
	__u32 handle;       /* out */
	__u32 flags;        /* in: must be 0 */
};

struct toygpu_bo_destroy {
	__u32 handle;
	__u32 pad;          /* must be 0 */
};

#define TOYGPU_OP_WRITE32 1

struct toygpu_cmd {
	__u32 op;           /* TOYGPU_OP_WRITE32 */
	__u32 offset;       /* byte offset into the target BO, 4-byte aligned */
	__u32 value;
	__u32 pad;          /* must be 0 */
};

struct toygpu_cmdbuf {      /* lives in user memory */
	__u32 num_cmds;
	__u32 pad;
	struct toygpu_cmd cmds[];
};

struct toygpu_submit {
	__u32 handle;       /* target BO */
	__u32 flags;        /* must be 0 */
	__u64 cmdbuf_ptr;   /* user pointer to struct toygpu_cmdbuf */
};

#define TOYGPU_IOC               'G'
#define TOYGPU_IOCTL_GET_INFO    _IOR(TOYGPU_IOC, 0x00, struct toygpu_info)
#define TOYGPU_IOCTL_BO_CREATE   _IOWR(TOYGPU_IOC, 0x01, struct toygpu_bo_create)
#define TOYGPU_IOCTL_BO_DESTROY  _IOW(TOYGPU_IOC, 0x02, struct toygpu_bo_destroy)
#define TOYGPU_IOCTL_SUBMIT      _IOW(TOYGPU_IOC, 0x03, struct toygpu_submit)

#endif /* TOYGPU_UAPI_H */
