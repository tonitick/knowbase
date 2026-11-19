# 02 — Linux Kernel Driver Essentials (with the security lens on)

A device driver is glue between kernel subsystems (PCI core, DMA, IRQ, char/DRM, power
management) and a device. For each building block below: **what it is, the API, and the
security rule that goes with it.**

Lifecycle: `module_init` → driver registered → PCI core matches IDs → `probe()` → device in
use (ioctl/mmap/IRQs) → `remove()` → `module_exit`.

---

## 1. PCI driver skeleton (`probe`/`remove`)

```c
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/interrupt.h>

#define TOY_INTR_STATUS 0x100
#define TOY_INTR_EN     0x104

struct toy_dev {
	void __iomem *regs;     /* BAR0 */
	atomic_t pending;
};

static const struct pci_device_id toy_ids[] = {
	{ PCI_DEVICE(0x1234, 0x5678) },
	{ }
};
MODULE_DEVICE_TABLE(pci, toy_ids);       /* lets udev autoload the module */

static irqreturn_t toy_irq(int irq, void *data);
static irqreturn_t toy_irq_thread(int irq, void *data);

static int toy_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct toy_dev *td;
	int ret;

	td = devm_kzalloc(&pdev->dev, sizeof(*td), GFP_KERNEL);
	if (!td)
		return -ENOMEM;

	ret = pcim_enable_device(pdev);                 /* Memory Space Enable, managed */
	if (ret)
		return ret;

	ret = pcim_iomap_regions(pdev, BIT(0), "toy");  /* request + ioremap BAR0 */
	if (ret)                                        /* (newer kernels: pcim_iomap_region) */
		return ret;
	td->regs = pcim_iomap_table(pdev)[0];

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(47));
	if (ret)
		return ret;
	pci_set_master(pdev);                           /* Bus Master Enable: may DMA now */

	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSIX | PCI_IRQ_MSI);
	if (ret < 0)
		return ret;
	ret = request_threaded_irq(pci_irq_vector(pdev, 0), toy_irq,
				   toy_irq_thread, 0, "toy", td);
	if (ret)
		goto err_vectors;

	pci_set_drvdata(pdev, td);
	writel(1, td->regs + TOY_INTR_EN);
	dev_info(&pdev->dev, "id reg %08x\n", readl(td->regs + 0x0));
	return 0;

err_vectors:
	pci_free_irq_vectors(pdev);
	return ret;
}

static void toy_remove(struct pci_dev *pdev)
{
	struct toy_dev *td = pci_get_drvdata(pdev);

	writel(0, td->regs + TOY_INTR_EN);              /* 1. quiesce the device       */
	free_irq(pci_irq_vector(pdev, 0), td);          /* 2. no more handlers running */
	pci_free_irq_vectors(pdev);
	pci_clear_master(pdev);                         /* 3. stop DMA ...             */
	/* 4. ... only now may DMA'd memory be freed (devm/pcim do the rest) */
}

static struct pci_driver toy_driver = {
	.name = "toy", .id_table = toy_ids,
	.probe = toy_probe, .remove = toy_remove,
};
module_pci_driver(toy_driver);
MODULE_LICENSE("GPL");
```

**Security rules:**
- **Teardown order:** quiesce the device → free IRQ → stop DMA → free memory. Freeing memory
  the device can still DMA into is a use-after-free *by hardware*.
- Error paths in probe must unwind exactly (goto ladders, or `devm_`/`pcim_` managed resources).
  Leaks and double-frees hide there, and error paths are rarely tested.
- `MODULE_DEVICE_TABLE` + aliases decide *which hardware autoloads your code*. Every probe
  path is attack surface for a malicious device (USB/Thunderbolt) or a malicious hypervisor
  (Confidential Computing guests).

---

## 2. MMIO

```c
u32 v = readl(td->regs + REG);          /* ordered vs. normal memory accesses */
writel(v | BIT(3), td->regs + REG);
(void)readl(td->regs + REG);            /* read back: flush the posted write  */

#include <linux/iopoll.h>
u32 val;
int ret = readl_poll_timeout(td->regs + STATUS, val, val & READY, 10, 100000);
/* never spin forever on a register: hung or malicious device → hung kernel */
```

- Pointers are `void __iomem *`. Use the accessors; sparse (`make C=1`) flags direct dereference.
- `readl_relaxed`/`writel_relaxed` drop the ordering guarantees (faster, but you need explicit barriers).
- **Rule: values read from the device are input.** If an index or length comes from a
  register or a device-written ring entry, bounds-check it before using it to index host
  memory. Linux Confidential Computing guest hardening treats the device and hypervisor as
  untrusted for exactly this reason.

---

## 3. DMA API

```c
/* Coherent: long-lived memory both sides touch (rings, descriptors). */
void *ring = dma_alloc_coherent(&pdev->dev, RING_BYTES, &ring_dma, GFP_KERNEL);
writel(lower_32_bits(ring_dma), td->regs + RING_LO);
writel(upper_32_bits(ring_dma), td->regs + RING_HI);

/* Streaming: one transfer of an existing buffer; ownership moves CPU <-> device. */
dma_addr_t a = dma_map_single(&pdev->dev, buf, len, DMA_TO_DEVICE);
if (dma_mapping_error(&pdev->dev, a))
	return -ENOMEM;
/* ... kick device, wait for completion ... */
dma_unmap_single(&pdev->dev, a, len, DMA_TO_DEVICE);

/* User buffers (zero-copy): pin, build an sg table, map */
long n = pin_user_pages_fast(uaddr, npages, FOLL_WRITE | FOLL_LONGTERM, pages);
sg_alloc_table_from_pages(&sgt, pages, n, offset, len, GFP_KERNEL);
dma_map_sgtable(&pdev->dev, &sgt, DMA_BIDIRECTIONAL, 0);
```

**Rules:**
- Map **exactly** the buffer needed, with the **narrowest direction**. With an IOMMU,
  `DMA_TO_DEVICE` can be enforced as device-read-only.
- Unmap promptly. A stale mapping lets the device keep touching pages after they're reused.
- Never DMA to/from the stack (vmapped stacks) or to `vmalloc` memory without the right API.
- **Double fetch from device memory:** if the CPU reads a length from a DMA-coherent ring
  (which the device can change at any time), copy it once into a local variable, validate the
  copy, and use only the copy.
- Pinned pages (`FOLL_LONGTERM`) must be unpinned on every path, including process exit.
  Use MMU notifiers (`mmu_interval_notifier`) or HMM when you must track CPU page-table
  changes. NVIDIA UVM does this kind of tracking.

---

## 4. Interrupts

```c
static irqreturn_t toy_irq(int irq, void *data)          /* hard IRQ: atomic, fast */
{
	struct toy_dev *td = data;
	u32 status = readl(td->regs + TOY_INTR_STATUS);

	if (!status)
		return IRQ_NONE;                 /* not ours (shared line) or device gone */
	writel(status, td->regs + TOY_INTR_STATUS);       /* ack */
	atomic_or(status, &td->pending);
	return IRQ_WAKE_THREAD;
}

static irqreturn_t toy_irq_thread(int irq, void *data)   /* process context: may sleep */
{
	struct toy_dev *td = data;
	u32 work = atomic_xchg(&td->pending, 0);
	/* handle completions, take mutexes, GFP_KERNEL allocations OK here */
	return IRQ_HANDLED;
}
```

| Context | Can sleep? | Allocations | Locks |
|---|---|---|---|
| Process (syscall, kthread, workqueue, threaded IRQ) | yes | `GFP_KERNEL` | mutex, rwsem, spinlock |
| Softirq / tasklet / timer | no | `GFP_ATOMIC` | `spin_lock_bh` |
| Hard IRQ | no | `GFP_ATOMIC` | `spin_lock`, plus `spin_lock_irqsave` on the process side for shared data |

Bottom halves: threaded IRQs (preferred), workqueues (`INIT_WORK`/`queue_work`), tasklets (legacy).
Watch out for **interrupt storms** (device keeps asserting) and handlers racing with `remove()`.

---

## 5. The user-facing interface: char device, ioctl, mmap

This is **the** attack surface. NVIDIA's `/dev/nvidia*` nodes are world read/write (0666) by
default, so every ioctl is reachable by any local user, any container given the device,
and the browser GPU process.

### 5.1 Registering a device node
```c
static const struct file_operations toy_fops = {
	.owner          = THIS_MODULE,
	.open           = toy_open,           /* allocate per-open context → file->private_data */
	.release        = toy_release,        /* free it (last close)                          */
	.unlocked_ioctl = toy_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,   /* 32-bit userspace on 64-bit kernel */
	.mmap           = toy_mmap,
};
static struct miscdevice toy_misc = {
	.minor = MISC_DYNAMIC_MINOR, .name = "toy", .fops = &toy_fops, .mode = 0600,
};
misc_register(&toy_misc);
```

### 5.2 ioctl design (UAPI rules reviewers check)
```c
/* include/uapi/...: fixed-width types, no implicit padding, pointers as __u64 */
struct toy_submit {
	__u32 handle;
	__u32 flags;        /* reject unknown bits */
	__u64 cmds_ptr;     /* user pointer → u64_to_user_ptr() */
	__u32 num_cmds;
	__u32 reserved;     /* must be zero → allows future extension */
};
#define TOY_IOCTL_SUBMIT _IOW('T', 0x02, struct toy_submit)

static long toy_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct toy_ctx *ctx = f->private_data;
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case TOY_IOCTL_SUBMIT: {
		struct toy_submit a;
		struct toy_cmd *cmds;

		if (copy_from_user(&a, uarg, sizeof(a)))       /* copy ONCE */
			return -EFAULT;
		if (a.flags & ~TOY_SUBMIT_VALID_FLAGS || a.reserved)
			return -EINVAL;
		if (a.num_cmds == 0 || a.num_cmds > TOY_MAX_CMDS)
			return -EINVAL;
		cmds = memdup_user(u64_to_user_ptr(a.cmds_ptr),
				   array_size(a.num_cmds, sizeof(*cmds))); /* overflow-safe */
		if (IS_ERR(cmds))
			return PTR_ERR(cmds);
		/* validate every cmd against the *kernel copy*, then execute */
		...
		kfree(cmds);
		return 0;
	}
	default:
		return -ENOTTY;      /* unknown command */
	}
}
```

`copy_from_user()` facts interviewers like:
- returns the number of bytes **not** copied (non-zero → `-EFAULT`)
- may sleep (page faults), so it's illegal under a spinlock or in atomic context
- does `access_ok()`, toggles SMAP (`stac`/`clac`), and with `CONFIG_HARDENED_USERCOPY` checks
  the kernel side stays inside one slab object or stack frame
- a user pointer is never dereferenced directly (`__user` annotation + sparse catch it)

Outbound: zero the whole struct before filling (`memset(&out, 0, sizeof(out))`) so padding
and unset fields don't leak kernel stack/heap. Check UAPI layout with `pahole`.

### 5.3 mmap
```c
static int toy_mmap(struct file *f, struct vm_area_struct *vma)
{
	struct toy_ctx *ctx = f->private_data;
	unsigned long len = vma->vm_end - vma->vm_start;
	unsigned long off = vma->vm_pgoff << PAGE_SHIFT;

	if (off >= ctx->buf_size || len > ctx->buf_size - off)  /* overflow-safe bounds */
		return -EINVAL;
	/* remap_pfn_range() sets VM_IO|VM_PFNMAP|VM_DONTEXPAND|VM_DONTDUMP itself;
	 * fault-based mappings must set VM_DONTEXPAND explicitly (6.3+: vm_flags_set()) */
	return remap_pfn_range(vma, vma->vm_start,
			       (ctx->buf_phys + off) >> PAGE_SHIFT, len, vma->vm_page_prot);
}
```
- Registers/doorbells: `pgprot_noncached()` + `io_remap_pfn_range()`, mapping **exactly one
  page containing only user-safe registers**. Apertures: `pgprot_writecombine()`.
- **Lifetime rule:** if the backing memory can be freed while user-mapped, either hold a
  reference for the VMA's lifetime (`vm_ops->open/close` + `kref`) or zap all user mappings
  (`unmap_mapping_range()`) before freeing. Breaking this rule is the #1 GPU driver UAF class
  (many exploited Mali/Adreno bugs): the user keeps a mapping to a physical page the kernel
  has reused.
- Fault-based mapping (`vm_ops->fault` + `vmf_insert_pfn`) lets the driver move or evict
  memory (TTM/GEM do this) and is the modern pattern.

### 5.4 Other interfaces
`sysfs` (stable attributes, permissions matter), `debugfs` (not ABI, often dangerous; should be
root-only and absent in production), `procfs`, netlink, and module parameters (`/sys/module/*/parameters`).

---

## 6. DRM (the Linux GPU subsystem) in five bullets

- **Nodes:** `/dev/dri/cardN` (primary: modesetting, DRM master) and `/dev/dri/renderD12N`
  (**render nodes**: unprivileged compute/render only, no modeset). Least privilege by design.
- **GEM** objects (buffers) are referenced by per-file **handles**. **dma-buf** (PRIME) exports
  a buffer as an fd to share across processes/devices. **dma_fence**/sync_file handle synchronization.
- **TTM** = VRAM/GTT memory manager (the `ast` driver on this box uses the TTM-based VRAM helpers).
- **KMS** = modesetting objects (CRTC, plane, connector), atomic commits.
- **`drm_ioctl()` does the copy-in/copy-out for drivers** using the size encoded in the ioctl
  number (zero-extending older/shorter structs) and enforces per-ioctl flags
  (`DRM_RENDER_ALLOW`, `DRM_MASTER`, `DRM_AUTH`). Drivers receive a kernel copy. That's a
  "secure by construction" pattern worth citing.
- NVIDIA's `nvidia-drm.ko` plugs into DRM for display/PRIME, but CUDA uses NVIDIA's own
  `/dev/nvidia*` interface (see 03).

---

## 7. Memory allocation cheat sheet

| API | Use | Gotcha |
|---|---|---|
| `kmalloc/kzalloc` | small, physically contiguous | `kzalloc` when content will reach user or device |
| `kvmalloc_array/kvzalloc` | possibly large | overflow-checked count×size |
| `vmalloc/vmalloc_user` | large, virtually contiguous | `vmalloc_user` is zeroed + mmap-able |
| `alloc_pages(GFP_.. \| __GFP_ZERO, order)` | page-level | **zero pages that a user/tenant will see** |
| `dma_alloc_coherent` | device-shared | treat contents as device-controlled |
| `struct_size()/array_size()/check_mul_overflow()` | size math | saturate/detect overflow |

---

## 8. Concurrency and object lifetime

```c
struct toy_bo { struct kref ref; size_t size; struct page *pages; };

static void toy_bo_release(struct kref *ref)
{
	struct toy_bo *bo = container_of(ref, struct toy_bo, ref);
	__free_pages(bo->pages, get_order(bo->size));
	kfree(bo);
}

/* Lookup takes the reference *while holding the lock that protects the table*. */
static struct toy_bo *toy_bo_get(struct toy_ctx *ctx, u32 handle)
{
	struct toy_bo *bo;

	mutex_lock(&ctx->lock);
	bo = xa_load(&ctx->bos, handle);          /* xarray: modern handle table */
	if (bo)
		kref_get(&bo->ref);
	mutex_unlock(&ctx->lock);
	return bo;                                /* caller: kref_put(&bo->ref, toy_bo_release) */
}

/* Destroy: remove from the table first (no new lookups), then drop the table's ref. */
mutex_lock(&ctx->lock);
bo = xa_erase(&ctx->bos, handle);
mutex_unlock(&ctx->lock);
if (bo)
	kref_put(&bo->ref, toy_bo_release);
```

- `refcount_t` saturates instead of wrapping, so a refcount overflow can't become a UAF.
- Races between two ioctls on the same fd (or two fds sharing an object) are the second
  big bug class after missing validation. Run lockdep + KCSAN in testing.
- Lock ordering: document it, and let lockdep enforce it.

---

## 9. Firmware loading

```c
const struct firmware *fw;
int ret = request_firmware(&fw, "toy/toy_fw_v2.bin", &pdev->dev);  /* /lib/firmware/... */
if (ret)
	return ret;
/* fw->data / fw->size: parse DEFENSIVELY (magic, versions, offsets+sizes in range) */
release_firmware(fw);
```
- **The kernel does not verify firmware signatures.** Module signing doesn't cover
  `/lib/firmware`. Authenticity must be enforced **by the device** (NVIDIA: hardware/BROM-verified
  HS ucode, see 04) or by IMA appraisal (`func=FIRMWARE_CHECK`).
- The driver still parses the file. Under Secure Boot + kernel lockdown, "root → kernel" is a
  security boundary, so a parsing bug in a firmware/VBIOS header parser is a real vulnerability.

---

## 10. Power management and reset

- Suspend/resume and runtime PM: after power loss the device must **re-establish its
  security state** (secure boot again, re-lock protected registers, re-create WPR) before
  serving clients again. Resume paths are classic places for missing re-initialization.
- Reset (FLR / bus reset) between tenants must clear device state (VRAM, caches, engine contexts).

---

## 11. Building, signing, debugging (toolchain fluency)

```bash
# Kbuild out-of-tree module
echo 'obj-m := toy.o' > Makefile
make -C /lib/modules/$(uname -r)/build M=$PWD modules       # build
make -C /lib/modules/$(uname -r)/build M=$PWD C=1 modules   # + sparse static checks
modinfo toy.ko ; cat /proc/sys/kernel/tainted               # P=proprietary O=out-of-tree E=unsigned

# Debugging
dmesg -w
echo 'module toy +p' > /sys/kernel/debug/dynamic_debug/control
bpftrace -e 'kprobe:nvidia_ioctl { @[comm] = count(); }'    # who's calling the NVIDIA driver
./scripts/faddr2line toy.ko toy_ioctl+0x5c/0x200            # oops offset → source line
# QEMU + gdb kernel debugging:  qemu ... -s -S ;  gdb vmlinux -ex 'target remote :1234'
#   (gdb) lx-symbols ; lx-dmesg ; bt ; info registers
```
- Debug kernels for testing drivers: `KASAN` (OOB/UAF), `UBSAN` (UB, array bounds), `KCSAN`
  (data races), `KMSAN` (uninitialized memory → info leaks), `LOCKDEP`, `KMEMLEAK`.
- Distribution flow for NVIDIA's modules: **DKMS** rebuilds them per kernel. Under Secure
  Boot they must be signed with an enrolled MOK (Machine Owner Key).
- gcc fluency: `gcc -Q --help=common -O2 | grep -E 'stack|cf-prot'` (which flags are on),
  `gcc -dM -E - </dev/null | grep -i fortify` (default macros), `-frecord-gcc-switches`
  (embeds flags in the binary, auditable later), `-S`/`-E` (asm / preprocessed output).

---

## 12. Windows equivalents (NVIDIA ships both; know the mapping)

| Linux | Windows |
|---|---|
| `module_init` / `probe` | `DriverEntry` / `AddDevice` (KMDF `EvtDriverDeviceAdd`) |
| `unlocked_ioctl` | `IRP_MJ_DEVICE_CONTROL` (`DeviceIoControl`) |
| `copy_from_user` | `METHOD_BUFFERED` (I/O manager copies). `METHOD_NEITHER` = raw user pointers → `ProbeForRead` + `__try/__except` (bug-prone) |
| process/atomic context | IRQL: `PASSIVE_LEVEL`, `DISPATCH_LEVEL`, `DIRQL` |
| KASAN / lockdep | Driver Verifier, Special Pool |
| module signing / lockdown | Driver signing (attestation/WHQL), HVCI ("memory integrity"), vulnerable-driver blocklist |
| DRM driver ioctls | **WDDM**: `dxgkrnl.sys` calls the KMD's `DxgkDdi*` callbacks. `DxgkDdiEscape` = private UMD→KMD blob channel, historically a rich source of NVIDIA kernel bugs |
| GPU hang recovery | TDR (Timeout Detection and Recovery) |
