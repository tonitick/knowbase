# Lab 1 — Explore a Real PCI Graphics Device (no root needed)

This server has no NVIDIA GPU, but it has a real PCI display controller: the BMC's
**ASPEED AST2xxx** (`1a03:2000`), driven by the in-kernel **`ast` DRM driver** (TTM/VRAM
helpers, KMS). Everything a GPU driver does at the PCI level is visible here.

```bash
python3 pci_inspect.py                 # all display-class devices
python3 pci_inspect.py 0000:03:00.0    # a specific BDF
lspci -nn -s 03:00.0 -vv               # compare (capabilities need sudo)
```

## What you'll see on this machine (and how to read it)

```
PCI device 0000:03:00.0   vendor 0x1a03  device 0x2000  class 0x030000   ← VGA-compatible controller
  bound driver: ast   modalias: pci:v00001A03d00002000...                 ← how udev picked the module
  command: I/O space=on, Memory space=on, Bus Master (may DMA)=off        ← this device does no DMA!
  capabilities: ... (list continues at 0x40: run as root to read it)      ← unprivileged reads stop at 64 B
  BAR0  0x9c000000  size 16 MiB  32-bit non-prefetchable memory           ← VRAM (framebuffer)
  BAR1  0x9d000000  size 128 KiB 32-bit non-prefetchable memory           ← MMIO registers
  BAR2  0x2000      size 128 B   I/O ports                                ← legacy VGA I/O
  ROM   0xc0000     size 128 KiB (shadow copy of the legacy VGA BIOS)     ← the option ROM
  no IOMMU group: device DMA is NOT translated                            ← see discussion
  /dev/dri/card0  mode 0660 group video  you cannot open it  [primary node]
```

## Questions to answer (write the answers down; they're interview material)

1. **Which BAR holds registers and which holds memory? How can you tell without the
   datasheet?** Sizes give a hint, but the driver source is the answer. In v5.15,
   `drivers/gpu/drm/ast/ast_main.c` does `ast->regs = pcim_iomap(pdev, 1, 0)` (BAR1 = MMIO
   registers) and `pcim_iomap(pdev, 2, 0)` (BAR2 = I/O ports). `ast_mm.c` hands BAR0 to
   `drmm_vram_helper_init(dev, pci_resource_start(pdev, 0), ...)` (BAR0 = VRAM). Browse at
   elixir.bootlin.com/linux/v5.15/source/drivers/gpu/drm/ast/.
2. **Bus Master is off. What does that mean?** The device cannot initiate DMA. A GPU always
   has it on: pushbuffer fetch, copy engines, page tables in sysmem. Who sets it?
   (`pci_set_master()` in probe.) What should a driver do with it at remove time, and why?
3. **There are no IOMMU groups on this server at all** (`ls /sys/kernel/iommu_groups` is
   empty for all 294 PCI devices). What does that mean for a GPU whose firmware is
   compromised, or for a Thunderbolt device? What do `intel_iommu=on` and `iommu=pt`
   change, and what does each cost?
4. **Why do unprivileged users only see 64 bytes of config space?** (The kernel limits
   non-`CAP_SYS_ADMIN` reads. Some devices have side-effecting config registers, and
   capability data can be sensitive.)
5. **Who can reach this driver's ioctls?** `card0` is 0660 group `video`. Compare: NVIDIA's
   `/dev/nvidia*` default to 0666, and DRM render nodes (`renderD128`) are usually world- or
   `render`-group accessible. What's the security trade-off?
6. **Compare with an NVIDIA GPU** (typical `lspci -v`):
   ```
   Region 0: Memory (32-bit, non-prefetchable) [size=16M]   ← BAR0 registers (NV_PMC_BOOT_0 at offset 0)
   Region 1: Memory (64-bit, prefetchable)     [size=256M+] ← BAR1 VRAM aperture via GPU MMU (ReBAR: all VRAM)
   Region 3: Memory (64-bit, prefetchable)     [size=32M]   ← instance-memory aperture (driver use)
   Region 5: I/O ports [size=128]
   Expansion ROM [size=512K+]                               ← VBIOS
   Capabilities: Power Management, MSI, PCIe, (MSI-X), AER, (Resizable BAR), (SR-IOV on datacenter parts) ...
   ```
   Why is the NVIDIA VRAM BAR prefetchable while the AST framebuffer BAR isn't? (Prefetchable
   means reads have no side effects, so the CPU may write-combine or speculate.) Note that
   `ast_mm.c` still maps its non-prefetchable VRAM BAR **write-combined**
   (`arch_io_reserve_memtype_wc`): the driver knows it's plain memory. The mapping attribute
   is the driver's decision, and getting it wrong for a *register* BAR breaks side-effect ordering.
7. Find the `ast` module's firmware reference: `modinfo ast | grep firmware` →
   `ast_dp501_fw.bin`. Who verifies that file's integrity? (The kernel doesn't; see 02 §9.)

## Optional, with sudo, on a machine you own
```bash
sudo lspci -vvv -s 03:00.0                 # full capability list, link status, ASPM
sudo python3 pci_inspect.py 0000:03:00.0   # adds the capability + extended-capability walk
sudo cat /proc/iomem | grep -i -A2 03:00.0 # where the BARs sit in the physical address map
sudo bpftrace -e 'kprobe:ast_* { @[func] = count(); }'   # which driver functions run
```
