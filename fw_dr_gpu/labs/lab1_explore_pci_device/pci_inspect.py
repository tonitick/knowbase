#!/usr/bin/env python3
"""
pci_inspect.py - read-only tour of a PCI device as the kernel sees it (no root needed).

  python3 pci_inspect.py              # every display-class device (VGA / 3D / display)
  python3 pci_inspect.py 0000:03:00.0 # a specific device

Everything comes from sysfs/procfs. Nothing is written. As root you additionally get the
full config space and the capability list (unprivileged reads stop at 64 bytes).
"""
import glob
import os
import re
import struct
import sys

SYS = "/sys/bus/pci/devices"

# include/linux/ioport.h
IORESOURCE_IO, IORESOURCE_MEM = 0x100, 0x200
IORESOURCE_PREFETCH, IORESOURCE_READONLY = 0x2000, 0x4000
IORESOURCE_MEM_64, IORESOURCE_DISABLED = 0x100000, 0x10000000

CAP_NAMES = {0x01: "Power Management", 0x05: "MSI", 0x09: "Vendor Specific", 0x10: "PCI Express",
             0x11: "MSI-X", 0x12: "SATA", 0x13: "Advanced Features"}
EXT_CAP_NAMES = {0x0001: "AER", 0x0002: "VC", 0x0003: "Device Serial Number", 0x000B: "Vendor Specific",
                 0x000D: "ACS", 0x000E: "ARI", 0x000F: "ATS", 0x0010: "SR-IOV", 0x0013: "PRI",
                 0x0015: "Resizable BAR", 0x001B: "PASID", 0x001E: "L1 PM Substates",
                 0x0023: "DVSEC", 0x002E: "DOE (SPDM transport)", 0x0030: "IDE (link encryption)"}


def rd(path, default=None):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def human(n):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" or n == int(n) else f"{n:.1f} {unit}"
        n /= 1024


def display_devices():
    out = []
    for dev in sorted(glob.glob(f"{SYS}/*")):
        cls = rd(f"{dev}/class", "0x000000")
        if int(cls, 16) >> 16 == 0x03:          # base class 0x03 = display controller
            out.append(os.path.basename(dev))
    return out


def section(title):
    print(f"\n  -- {title} " + "-" * max(0, 60 - len(title)))


def show_bars(dev):
    section("BARs / resources  (/sys/.../resource)")
    lines = (rd(f"{dev}/resource", "") or "").splitlines()
    names = {i: f"BAR{i}" for i in range(6)}
    names[6] = "ROM"
    for i, line in enumerate(lines):
        start, end, flags = (int(x, 16) for x in line.split())
        if not flags or end <= start:
            continue
        size = end - start + 1
        if flags & IORESOURCE_IO:
            kind = "I/O ports"
        elif flags & IORESOURCE_MEM:
            kind = ("64-bit" if flags & IORESOURCE_MEM_64 else "32-bit") + \
                   (" prefetchable" if flags & IORESOURCE_PREFETCH else " non-prefetchable") + " memory"
        else:
            kind = f"flags {flags:#x}"
        extra = " (disabled)" if flags & IORESOURCE_DISABLED else ""
        if i == 6 and flags & 0x2:              # IORESOURCE_ROM_SHADOW (PCI bus-specific bit)
            extra += " (shadow copy of the legacy VGA BIOS, the option ROM / 'VBIOS')"
        addr = f"{start:#014x}" if start else "(address hidden: not root)"
        print(f"    {names.get(i, f'res{i}'):5} {addr}  size {human(size):>9}  {kind}{extra}")
    print("    hint: registers live in non-prefetchable BARs; framebuffer/VRAM apertures are prefetchable (WC)")


def show_config(dev):
    section("config space  (/sys/.../config)")
    try:
        with open(f"{dev}/config", "rb") as f:
            cfg = f.read()
    except OSError as e:
        print(f"    unreadable: {e}")
        return
    vendor, device, command, status = struct.unpack_from("<HHHH", cfg, 0)
    rev, prog_if, subclass, base = cfg[8], cfg[9], cfg[10], cfg[11]
    print(f"    vendor:device {vendor:04x}:{device:04x}  class {base:02x}{subclass:02x}{prog_if:02x}  rev {rev:#x}"
          f"  ({len(cfg)} bytes readable{'' if len(cfg) > 64 else ': unprivileged users only get the first 64'})")
    bits = [("I/O space", 0), ("Memory space", 1), ("Bus Master (may DMA)", 2), ("INTx disabled", 10)]
    print("    command:", ", ".join(f"{n}={'on' if command >> b & 1 else 'off'}" for n, b in bits))
    if not status & 0x10:
        return
    ptr, seen, caps = cfg[0x34] & 0xFC, set(), []
    while ptr and ptr + 1 < len(cfg) and ptr not in seen:
        seen.add(ptr)
        caps.append(CAP_NAMES.get(cfg[ptr], f"cap {cfg[ptr]:#04x}"))
        ptr = cfg[ptr + 1] & 0xFC
    if ptr and ptr >= len(cfg):
        caps.append(f"... (list continues at {ptr:#x}: run as root to read it)")
    print("    capabilities:", ", ".join(caps) if caps else "(none in the readable window)")
    if len(cfg) > 0x100:
        ext, off, seen = [], 0x100, set()
        while off and off + 4 <= len(cfg) and off not in seen:
            seen.add(off)
            hdr = struct.unpack_from("<I", cfg, off)[0]
            if hdr in (0, 0xFFFFFFFF):
                break
            ext.append(EXT_CAP_NAMES.get(hdr & 0xFFFF, f"ext {hdr & 0xFFFF:#06x}"))
            off = (hdr >> 20) & 0xFFC
        print("    extended capabilities:", ", ".join(ext) if ext else "(none)")


def show_irq_dma(dev, driver):
    section("interrupts / DMA / IOMMU")
    msi = sorted(os.listdir(f"{dev}/msi_irqs")) if os.path.isdir(f"{dev}/msi_irqs") else []
    print(f"    legacy irq line: {rd(f'{dev}/irq')}   MSI/MSI-X vectors in use: {', '.join(msi) or 'none'}")
    if driver:
        word = re.compile(rf"(?<![\w-]){re.escape(driver)}(?![\w-])")   # whole word, not 'fasteoi'
        hits = [l.split()[0].rstrip(":") + " -> " + " ".join(l.split()[-2:])
                for l in (rd("/proc/interrupts", "") or "").splitlines() if word.search(l)]
        print(f"    /proc/interrupts lines mentioning '{driver}': {hits or 'none (driver may not use IRQs)'}")
    print(f"    DMA mask bits: {rd(f'{dev}/dma_mask_bits')}   coherent DMA mask bits: "
          f"{rd(f'{dev}/consistent_dma_mask_bits')}")
    grp = os.path.realpath(f"{dev}/iommu_group") if os.path.exists(f"{dev}/iommu_group") else None
    if grp:
        members = os.listdir(f"{grp}/devices")
        print(f"    IOMMU group {os.path.basename(grp)} with {len(members)} device(s): {', '.join(members)}")
        print("    -> device DMA goes through IOMMU translation; the group is the unit of VFIO passthrough")
    else:
        print("    no IOMMU group: device DMA is NOT translated (bus address == physical address);")
        print("    a buggy or malicious device could reach any physical memory it can address")
    cmd = rd("/proc/cmdline", "")
    flags = [w for w in cmd.split() if w.startswith(("iommu", "intel_iommu", "amd_iommu"))]
    print(f"    IOMMU-related kernel parameters: {flags or 'none (distro defaults)'}")


def show_driver(dev):
    section("driver binding")
    drv = os.path.basename(os.path.realpath(f"{dev}/driver")) if os.path.exists(f"{dev}/driver") else None
    print(f"    bound driver: {drv or 'none'}   modalias: {rd(f'{dev}/modalias')}")
    print(f"    enabled: {rd(f'{dev}/enable')}   boot_vga: {rd(f'{dev}/boot_vga', 'n/a')}   "
          f"power_state: {rd(f'{dev}/power_state', 'n/a')}   numa_node: {rd(f'{dev}/numa_node')}")
    link = rd(f"{dev}/current_link_speed")
    if link:
        print(f"    PCIe link: {link} x{rd(f'{dev}/current_link_width')} "
              f"(max {rd(f'{dev}/max_link_speed')} x{rd(f'{dev}/max_link_width')})")
    if drv and os.path.isdir(f"/sys/module/{drv}/parameters"):
        params = {p: rd(f"/sys/module/{drv}/parameters/{p}", "(root only)")
                  for p in sorted(os.listdir(f"/sys/module/{drv}/parameters"))}
        print(f"    module parameters: {params}")
    return drv


def show_drm(dev):
    nodes = sorted(os.listdir(f"{dev}/drm")) if os.path.isdir(f"{dev}/drm") else []
    if not nodes:
        return
    section("DRM device nodes (who can reach the driver's ioctls?)")
    for n in nodes:
        if n.startswith("control"):
            continue                            # legacy control node, no /dev entry
        path = f"/dev/dri/{n}"
        try:
            st = os.stat(path)
            import grp
            gname = grp.getgrgid(st.st_gid).gr_name
            mode = oct(st.st_mode & 0o777)
            access = "you CAN open it" if os.access(path, os.R_OK | os.W_OK) else "you cannot open it"
            role = "render node: unprivileged GPU work, no modeset" if n.startswith("render") else \
                   "primary node: modesetting (DRM master)"
            print(f"    {path:22} mode {mode} group {gname:8} {access:20} [{role}]")
        except OSError:
            print(f"    {n}: (no /dev node)")


def inspect(bdf):
    dev = f"{SYS}/{bdf}"
    if not os.path.isdir(dev):
        sys.exit(f"no such PCI device: {bdf}")
    print("=" * 72)
    print(f"PCI device {bdf}   vendor {rd(f'{dev}/vendor')}  device {rd(f'{dev}/device')}  "
          f"class {rd(f'{dev}/class')}")
    drv = show_driver(dev)
    show_config(dev)
    show_bars(dev)
    show_irq_dma(dev, drv)
    show_drm(dev)


def main():
    targets = sys.argv[1:] or display_devices()
    if not targets:
        sys.exit("no display-class PCI devices found; pass a BDF like 0000:03:00.0")
    for bdf in targets:
        inspect(bdf)
    print()


if __name__ == "__main__":
    main()
