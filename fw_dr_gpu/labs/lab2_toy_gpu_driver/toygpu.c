// SPDX-License-Identifier: GPL-2.0
/*
 * toygpu - a deliberately tiny "GPU-like" character driver for practicing
 * driver security review.
 *
 *   make            -> FIXED build (the code you'd want to ship)
 *   make VULN=1     -> VULNERABLE build: 8 classic driver bugs compiled in, each
 *                      marked "BUG(n)" (answer key in README.md)
 *
 * Load ONLY inside a throwaway VM, ideally with a KASAN kernel. Never on a shared host.
 *
 * Exercise: read only the code inside "#ifdef TOYGPU_VULNERABLE" branches and the
 * shared code, find the bugs yourself, then compare with the fixed branches.
 */
#include <linux/fs.h>
#include <linux/kref.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nospec.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "toygpu_uapi.h"

struct toygpu_bo {
	struct kref ref;
	size_t size;            /* bytes, page aligned */
	unsigned int order;     /* allocation is PAGE_SIZE << order, physically contiguous */
	struct page *pages;
	void *vaddr;
};

struct toygpu_ctx {             /* one per open(): a GPU "client" */
	struct mutex lock;      /* protects bos[] */
	struct toygpu_bo *bos[TOYGPU_MAX_BOS];
};

static void toygpu_bo_release(struct kref *ref)
{
	struct toygpu_bo *bo = container_of(ref, struct toygpu_bo, ref);

	__free_pages(bo->pages, bo->order);
	kfree(bo);
}

static void toygpu_bo_put(struct toygpu_bo *bo)
{
	kref_put(&bo->ref, toygpu_bo_release);
}

/* Look up a BO by handle and take a reference on it. */
static struct toygpu_bo *toygpu_bo_get(struct toygpu_ctx *ctx, u32 handle)
{
	struct toygpu_bo *bo;

#ifdef TOYGPU_VULNERABLE
	/* BUG(2) */
	mutex_lock(&ctx->lock);
	bo = ctx->bos[handle];
#else
	if (handle >= TOYGPU_MAX_BOS)
		return NULL;
	handle = array_index_nospec(handle, TOYGPU_MAX_BOS);
	mutex_lock(&ctx->lock);
	bo = ctx->bos[handle];
#endif
	if (bo)
		kref_get(&bo->ref);
	mutex_unlock(&ctx->lock);
	return bo;
}

/* ------------------------------------------------------------------ GET_INFO */

static long toygpu_get_info(void __user *uarg)
{
	struct toygpu_info info;

#ifndef TOYGPU_VULNERABLE
	memset(&info, 0, sizeof(info));         /* fixes BUG(1): zero the padding too */
#endif
	info.version = 1;
	info.num_engines = 1;
	info.vram_size = (u64)TOYGPU_MAX_BOS * TOYGPU_MAX_BO_SIZE;
	info.max_bos = TOYGPU_MAX_BOS;
	if (copy_to_user(uarg, &info, sizeof(info)))   /* BUG(1) in the vulnerable build */
		return -EFAULT;
	return 0;
}

/* ----------------------------------------------------------------- BO_CREATE */

static long toygpu_bo_create(struct toygpu_ctx *ctx, void __user *uarg)
{
	struct toygpu_bo_create args;
	struct toygpu_bo *bo;
	u32 handle;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;
	if (args.flags)
		return -EINVAL;
	if (args.size == 0 || args.size > TOYGPU_MAX_BO_SIZE)
		return -EINVAL;

	bo = kzalloc(sizeof(*bo), GFP_KERNEL);
	if (!bo)
		return -ENOMEM;
	kref_init(&bo->ref);
	bo->size = PAGE_ALIGN(args.size);
	bo->order = get_order(bo->size);
#ifdef TOYGPU_VULNERABLE
	bo->pages = alloc_pages(GFP_KERNEL, bo->order);                 /* BUG(8) */
#else
	bo->pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, bo->order);
#endif
	if (!bo->pages) {
		kfree(bo);
		return -ENOMEM;
	}
	bo->vaddr = page_address(bo->pages);

	mutex_lock(&ctx->lock);
	for (handle = 0; handle < TOYGPU_MAX_BOS; handle++)
		if (!ctx->bos[handle])
			break;
	if (handle == TOYGPU_MAX_BOS) {
		mutex_unlock(&ctx->lock);
		toygpu_bo_put(bo);
		return -ENOSPC;
	}
	ctx->bos[handle] = bo;                  /* the table owns the initial reference */
	mutex_unlock(&ctx->lock);

	args.handle = handle;
	if (copy_to_user(uarg, &args, sizeof(args)))
		return -EFAULT;                 /* BO is reclaimed at close() */
	return 0;
}

/* ---------------------------------------------------------------- BO_DESTROY */

static long toygpu_bo_destroy(struct toygpu_ctx *ctx, void __user *uarg)
{
	struct toygpu_bo_destroy args;
	struct toygpu_bo *bo;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;
	if (args.pad || args.handle >= TOYGPU_MAX_BOS)
		return -EINVAL;

	mutex_lock(&ctx->lock);
	bo = ctx->bos[args.handle];
#ifdef TOYGPU_VULNERABLE
	if (bo) {                                                       /* BUG(6) */
		__free_pages(bo->pages, bo->order);
		kfree(bo);
	}
#else
	ctx->bos[args.handle] = NULL;           /* no new lookup can find it */
#endif
	mutex_unlock(&ctx->lock);
	if (!bo)
		return -ENOENT;
#ifndef TOYGPU_VULNERABLE
	toygpu_bo_put(bo);  /* actually freed when the last mapping/submit drops its reference */
#endif
	return 0;
}

/* -------------------------------------------------------------------- SUBMIT */

static int toygpu_exec(struct toygpu_bo *bo, const struct toygpu_cmd *cmd)
{
	if (cmd->op != TOYGPU_OP_WRITE32 || cmd->pad)
		return -EINVAL;
#ifdef TOYGPU_VULNERABLE
	if (cmd->offset >= bo->size)                                    /* BUG(5) */
		return -EINVAL;
	memcpy(bo->vaddr + cmd->offset, &cmd->value, sizeof(cmd->value));
#else
	if (cmd->offset > bo->size - sizeof(u32) || !IS_ALIGNED(cmd->offset, sizeof(u32)))
		return -EINVAL;
	WRITE_ONCE(*(u32 *)(bo->vaddr + cmd->offset), cmd->value);
#endif
	return 0;
}

static long toygpu_submit(struct toygpu_ctx *ctx, void __user *uarg)
{
	struct toygpu_submit args;
	struct toygpu_cmdbuf __user *ucb;
	struct toygpu_cmdbuf *kcb;
	struct toygpu_bo *bo;
	long ret = 0;
	u32 n, i;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;
	if (args.flags)
		return -EINVAL;
	ucb = u64_to_user_ptr(args.cmdbuf_ptr);

	if (get_user(n, &ucb->num_cmds))                        /* user fetch #1 */
		return -EFAULT;
#ifdef TOYGPU_VULNERABLE
	{
		u32 bytes = sizeof(*kcb) + n * sizeof(struct toygpu_cmd);   /* BUG(3) */

		kcb = kmalloc(bytes, GFP_KERNEL);
		if (!kcb)
			return -ENOMEM;
		if (copy_from_user(kcb, ucb, bytes)) {          /* user fetch #2 */
			kfree(kcb);
			return -EFAULT;
		}
	}
#else
	if (n == 0 || n > TOYGPU_MAX_CMDS)
		return -EINVAL;
	kcb = memdup_user(ucb, struct_size(kcb, cmds, n));     /* user fetch #2 */
	if (IS_ERR(kcb))
		return PTR_ERR(kcb);
	kcb->num_cmds = n;      /* fixes BUG(4): only the validated value is trusted */
#endif

	bo = toygpu_bo_get(ctx, args.handle);
	if (!bo) {
		ret = -ENOENT;
		goto out_free;
	}
	for (i = 0; i < kcb->num_cmds; i++) {                   /* BUG(4) in the vulnerable build */
		ret = toygpu_exec(bo, &kcb->cmds[i]);
		if (ret)
			break;
	}
	toygpu_bo_put(bo);
out_free:
	kfree(kcb);
	return ret;
}

/* ---------------------------------------------------------------------- mmap */

static void toygpu_vm_open(struct vm_area_struct *vma)
{
	struct toygpu_bo *bo = vma->vm_private_data;

	kref_get(&bo->ref);             /* VMA duplicated (fork) or split */
}

static void toygpu_vm_close(struct vm_area_struct *vma)
{
	toygpu_bo_put(vma->vm_private_data);
}

static const struct vm_operations_struct toygpu_vm_ops = {
	.open = toygpu_vm_open,
	.close = toygpu_vm_close,
};

static int toygpu_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct toygpu_ctx *ctx = file->private_data;
	unsigned long len = vma->vm_end - vma->vm_start;
	struct toygpu_bo *bo;
	int ret;

#ifdef TOYGPU_VULNERABLE
	bo = toygpu_bo_get(ctx, vma->vm_pgoff);        /* offset = handle * PAGE_SIZE */
	if (!bo)
		return -ENOENT;
	ret = remap_pfn_range(vma, vma->vm_start, page_to_pfn(bo->pages),  /* BUG(7) */
			      len, vma->vm_page_prot);
	toygpu_bo_put(bo);
	return ret;
#else
	if (vma->vm_pgoff >= TOYGPU_MAX_BOS)
		return -EINVAL;
	bo = toygpu_bo_get(ctx, vma->vm_pgoff);
	if (!bo)
		return -ENOENT;
	if (len > bo->size) {
		toygpu_bo_put(bo);
		return -EINVAL;
	}
	/* remap_pfn_range() also sets VM_IO|VM_PFNMAP|VM_DONTEXPAND|VM_DONTDUMP */
	ret = remap_pfn_range(vma, vma->vm_start, page_to_pfn(bo->pages), len, vma->vm_page_prot);
	if (ret) {
		toygpu_bo_put(bo);
		return ret;
	}
	vma->vm_private_data = bo;      /* the mapping keeps the BO alive until munmap() */
	vma->vm_ops = &toygpu_vm_ops;
	return 0;
#endif
}

/* ------------------------------------------------------------ file plumbing */

static int toygpu_open(struct inode *inode, struct file *file)
{
	struct toygpu_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);

	if (!ctx)
		return -ENOMEM;
	mutex_init(&ctx->lock);
	file->private_data = ctx;
	return 0;
}

static int toygpu_release(struct inode *inode, struct file *file)
{
	struct toygpu_ctx *ctx = file->private_data;
	int i;

	for (i = 0; i < TOYGPU_MAX_BOS; i++)
		if (ctx->bos[i])
			toygpu_bo_put(ctx->bos[i]);
	mutex_destroy(&ctx->lock);
	kfree(ctx);
	return 0;
}

static long toygpu_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct toygpu_ctx *ctx = file->private_data;
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case TOYGPU_IOCTL_GET_INFO:
		return toygpu_get_info(uarg);
	case TOYGPU_IOCTL_BO_CREATE:
		return toygpu_bo_create(ctx, uarg);
	case TOYGPU_IOCTL_BO_DESTROY:
		return toygpu_bo_destroy(ctx, uarg);
	case TOYGPU_IOCTL_SUBMIT:
		return toygpu_submit(ctx, uarg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations toygpu_fops = {
	.owner          = THIS_MODULE,
	.open           = toygpu_open,
	.release        = toygpu_release,
	.unlocked_ioctl = toygpu_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
	.mmap           = toygpu_mmap,
};

static struct miscdevice toygpu_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "toygpu",
	.fops  = &toygpu_fops,
	.mode  = 0666,  /* like /dev/nvidia*: every local user reaches every ioctl */
};

static int __init toygpu_init(void)
{
#ifdef TOYGPU_VULNERABLE
	pr_warn("toygpu: VULNERABLE training build loaded - use only in a throwaway VM\n");
#endif
	return misc_register(&toygpu_misc);
}

static void __exit toygpu_exit(void)
{
	misc_deregister(&toygpu_misc);
}

module_init(toygpu_init);
module_exit(toygpu_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Toy GPU-like driver for driver security review practice");
