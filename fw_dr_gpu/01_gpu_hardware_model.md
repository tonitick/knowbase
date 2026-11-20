# 01 — How a GPU Looks to Software

Goal: be able to draw the box diagram below from memory, and explain which part is the
security boundary in each step.

```
  CPU cores ──── memory controller ──── system RAM ("sysmem")
      │
  PCIe root complex ──── IOMMU (Intel VT-d / AMD-Vi / Arm SMMU)
      │                     ▲ translates/limits device DMA, remaps interrupts
      │ PCIe link (TLPs: memory read/write, completions, MSI writes)
      ▼
 ┌──────────────────────────────── GPU ─────────────────────────────────┐
 │ PCIe endpoint: config space, BAR decoders, MSI-X table, (SR-IOV VFs)  │
 │                                                                       │
 │ Host / PBDMA ──► engines:  GR (GPCs → TPCs → SMs)  = graphics/compute │
 │  (fetches         ▲        CE  = copy engines (DMA mover)            │
 │   commands)       │        NVDEC/NVENC/NVJPG/OFA = media             │
 │ Scheduler (runlists, TSGs, timeslice, preemption)                     │
 │                                                                       │
 │ GMMU (GPU page tables, TLBs) ── L2 cache ── memory controllers ── VRAM │
 │                                                                       │
 │ Microcontrollers: GSP (runs GSP-RM firmware), SEC2, PMU, FECS/GPCCS,  │
 │   NVDEC/NVENC falcons, FSP (Hopper+ root of trust)                    │
 │ Display (DISP), NVLink, fuses (IDs, keys, revocation counters),       │
 │ VBIOS in SPI flash, InfoROM (persistent config + error logs)          │
 └───────────────────────────────────────────────────────────────────────┘
```

---

## 1. PCIe: how the CPU finds and talks to the GPU

**Naming: which "firmware"?** Two unrelated things share the word. In these notes "firmware"
alone means **device firmware** (code for the GPU itself). The host's own boot code is always
called **platform firmware**. Everything on the host side runs on the host CPU, in three layers:

| Name | Runs on | What it is | Role in PCIe/BAR setup |
|---|---|---|---|
| **Platform firmware** (UEFI/BIOS) | Host CPU, from motherboard flash | Boots the machine before the OS | Enumerates PCIe, sizes each BAR, assigns addresses |
| **Kernel PCI core** | Host CPU | Generic OS code, same for every vendor | Re-reads the BARs, may reassign them, records start/length |
| **Device driver** (`nvidia.ko`, nouveau, nova) | Host CPU | Vendor-specific kernel module | Only *uses* the already-assigned BARs: enables the device and maps them |
| **Device firmware** (VBIOS, ucode, GSP-RM: see 04 §1) | The GPU's own microcontrollers | Code shipped for the card | None. BAR sizes are fixed by the PCIe endpoint hardware |

One edge case: the VBIOS is device firmware (stored on the card), but its UEFI GOP driver /
legacy VGA option ROM is loaded by platform firmware and executes **on the host CPU**.

**Enumeration.** At boot, platform firmware (UEFI/BIOS) and then the kernel's PCI core walk the
PCIe hierarchy and read every function's **configuration space** (256 B legacy, 4 KB extended
for PCIe). Key fields:

| Offset | Field | Why you care |
|---|---|---|
| 0x00/0x02 | Vendor ID / Device ID | NVIDIA = `0x10de`. Driver matching (`pci_device_id` tables). |
| 0x04 | Command register | bit1 *Memory Space Enable*, bit2 **Bus Master Enable** (BME). Without BME the device cannot DMA. |
| 0x09–0x0B | Class code | `0x0300` VGA-compatible (GeForce/RTX with display), `0x0302` 3D controller (datacenter: A100/H100, no display). |
| 0x10–0x24 | BAR0–BAR5 | Base Address Registers: windows of device memory/registers mapped into the CPU's physical address space. |
| 0x30 | Expansion ROM BAR | Where the **VBIOS** (option ROM) is exposed. |
| 0x34 | Capabilities pointer | Linked list: PM, MSI, MSI-X, PCIe, and extended caps: AER, SR-IOV, ACS, ATS, PASID, Resizable BAR, DOE/SPDM. |

**BARs.** Platform firmware (and again the kernel's PCI core, not the GPU driver) sizes each BAR
(write all 1s, read back the mask) and assigns it an address.
BAR low bits encode: I/O vs memory, 32- vs 64-bit (a 64-bit BAR consumes two slots), and
*prefetchable* (safe to cache/write-combine; used for memory apertures, never for side-effecting
registers).

**Typical NVIDIA BAR layout** (sizes vary by product; `lspci -v` on an NVIDIA box):

```
Region 0: Memory at f6000000 (32-bit, non-prefetchable) [size=16M]  ← BAR0: registers (MMIO)
Region 1: Memory at e0000000 (64-bit, prefetchable)     [size=256M] ← BAR1: VRAM aperture
Region 3: Memory at f0000000 (64-bit, prefetchable)     [size=32M]  ← "BAR2": instance-memory aperture (driver use)
Region 5: I/O ports at e000 [size=128]                              ← legacy VGA I/O
Expansion ROM at f7000000 [disabled] [size=512K]                    ← VBIOS
```

- **BAR0** = the register file ("priv registers"), grouped in units (envytools names:
  `PMC` master control, `PBUS`, `PFIFO`, `PGRAPH`, `PFB`, `PDISP`, ...). Offset 0 is
  `NV_PMC_BOOT_0`, which identifies the chip — the first register every NVIDIA driver reads.
- **BAR1** = a CPU window into VRAM. It goes **through the GPU's own MMU** (a dedicated
  BAR1 address space), so the driver chooses which VRAM pages are visible at all. With
  *Resizable BAR* (consumer) or on datacenter parts it can cover all of VRAM. Used for CPU
  access to VRAM, display scan-out buffers, and GPUDirect RDMA (a NIC DMA-ing into GPU memory
  via BAR1).
- **Security angle:** BAR1 mappings are a classic place for bugs (expose another context's
  VRAM to the CPU), and in Confidential Computing mode BAR access to protected memory is
  blocked by hardware.

**On this machine** there is no NVIDIA GPU, but the BMC display device (ASPEED, `ast` driver)
is a real PCI graphics device: BAR0 = 16 MB VRAM, BAR1 = 128 KB MMIO, BAR2 = I/O ports.
See `labs/lab1_explore_pci_device/`.

---

## 2. MMIO: talking to registers

- The CPU does an ordinary load/store to an address inside a BAR → the root complex turns
  it into a PCIe **Memory Read/Write TLP** → the device decodes it as a register access.
- Registers are mapped **uncached** (UC). Memory apertures (BAR1) are usually
  **write-combining** (WC).
- **Writes are posted** (fire-and-forget, may be buffered); **reads are non-posted** (the CPU
  stalls ~1 µs for the completion). To be sure a write landed, *read back* from the same device.
- If a GPU drops off the bus, every MMIO read returns `0xFFFFFFFF`. Drivers check for that
  (NVIDIA: *Xid 79, "GPU has fallen off the bus"*).
- Linux: `ioremap()`/`pci_iomap()` then `readl()/writel()` (ordered) or `*_relaxed()` variants.
  Never dereference an `__iomem` pointer directly (sparse will complain).

---

## 3. DMA: the device reads/writes host memory itself

Most data does **not** go through MMIO; the GPU masters its own transactions:

- fetching command buffers (pushbuffers) placed in sysmem
- copy engines moving data between sysmem and VRAM (`cudaMemcpy`)
- page tables, semaphores, notifiers, fault buffers in sysmem
- microcontrollers loading firmware images through their DMA interface

**Bus address ≠ physical address.** The device uses *bus addresses* (IOVAs). Without an IOMMU
these equal physical addresses, so **any device can read/write all of RAM**. That's a DMA attack
(Thunderbolt/Thunderclap, malicious PCIe cards, a compromised device firmware).

**IOMMU** (VT-d / AMD-Vi / SMMU):
- per-device (per **IOMMU group**) page tables: the device can only touch what the kernel mapped for it
- **interrupt remapping**: stops a device from forging arbitrary MSI writes
- **IOTLB invalidation timing matters**: Linux "lazy" mode (`iommu.strict=0`) batches flushes,
  leaving a window where a device can still access freed pages. Strict mode closes it at a
  performance cost.
- **ATS** (Address Translation Services) lets a device cache translations. Requests marked
  "translated" bypass IOMMU checks, so ATS is only safe for trusted devices. Linux disables
  ATS on devices it marks *untrusted* (external ports).
- **ACS** (Access Control Services) forces peer-to-peer traffic up to the root complex so the
  IOMMU sees it. This matters for isolating functions/VFs assigned to different VMs.

**SWIOTLB / bounce buffers.** When a device can't reach some memory, the kernel copies through
a bounce buffer. In confidential VMs (SEV-SNP/TDX) *all* DMA goes through shared,
unencrypted bounce buffers, because the device can't read the VM's encrypted private memory.
Hopper Confidential Computing builds on exactly this (see 04).

---

## 4. Interrupts

- Legacy INTx (shared wire) → **MSI** (the device writes a magic value to a magic address) →
  **MSI-X** (a table of many vectors, the table itself lives in a BAR).
- GPUs have an internal interrupt tree. NVIDIA distinguishes **stall** interrupts (an engine
  needs software attention, e.g. an exception or fault) from **non-stall** interrupts
  (notifications such as "work completed / semaphore released" that CUDA events wait on).
- With GSP-RM (Turing+), many interrupts are serviced by GSP firmware. The CPU-side driver
  handles the rest and forwards as needed.

---

## 5. GPU memory and address spaces

**Physical memory types:** VRAM (GDDR/HBM), sysmem (pinned host pages, reached via DMA), and
peer memory (another GPU over NVLink/PCIe P2P).

**On-chip memories:** registers, shared memory/L1 (per SM), L2 (global). These must be
cleared or isolated between contexts. *LeftoverLocals* (2024) showed several non-NVIDIA GPUs
leaking local memory across kernels.

**GPU virtual memory (GMMU):**
- Each **VA space** (≈ each CUDA context / process) has its own multi-level page tables.
  Channels point at their VA space through the **instance block**'s page-directory base.
- PTE fields you should be able to name: *valid*, *aperture* (VRAM / sysmem-coherent /
  sysmem-non-coherent / peer), *read-only*, *privileged*, *volatile* (uncached), *kind*
  (compression/format). Page sizes are 4 KB small and 64 KB / 2 MB big.
- **Only the driver (kernel RM / GSP-RM / UVM) writes page tables.** User mode never does.
  That is the core isolation invariant of the whole design.
- **Unmap ordering invariant:** clear PTE → **invalidate GPU TLB and wait** → only then free or
  reuse the physical pages. Skipping or reordering this gives a GPU-side use-after-free.
  It's the same rule as IOMMU IOTLB flushing.
- **Faults:**
  - *Replayable* (Pascal+): the fault goes to a fault buffer, UVM migrates or maps the page,
    then the access is replayed. This is how CUDA managed memory pages on demand.
  - *Non-replayable / fatal*: the channel is torn down (**Xid 31**, MMU fault).
- **Memory scrubbing:** VRAM handed to a new allocation/tenant must be zeroed. Firmware also
  scrubs VRAM after boot for ECC initialization.

---

## 6. Command submission: channels, pushbuffers, doorbells

This is the most "GPU-specific" concept and a favorite interview topic.

```
 user process                                   GPU
 ────────────                                   ───
 1. write methods into a PUSHBUFFER (in GPU-visible memory)
 2. append GPFIFO entry {pushbuffer addr, length} to the ring
 3. update GP_PUT in USERD
 4. write work-submit token to the DOORBELL ───────► Host/PBDMA wakes up
                                                     5. reads GPFIFO entries
                                                     6. fetches pushbuffer, decodes methods
                                                     7. routes methods to the engine object
                                                        (e.g. compute class → QMD launch)
                                                     8. writes semaphore / raises non-stall
                                                        interrupt when done
```

- **Channel** = a hardware submission context: instance block (page-directory base + saved
  fetch state), GPFIFO ring, USERD (GP_PUT/GP_GET), bound engine objects.
- **Methods** = (subchannel, method offset, data) commands addressed to a *class* object
  (e.g. `AMPERE_COMPUTE_A`). A compute launch points the engine at a **QMD** (Queue Meta Data:
  grid/block dims, shader address, constant buffers, shared memory size).
- **TSG** (time-slice group) = channels that share one engine context. **Runlists** = what the
  hardware scheduler time-slices between. **FECS/GPCCS** firmware save and restore graphics
  context state on switches.
- **Doorbell**: on Volta+, a "usermode" register page is mapped into the process. Submission
  needs **no syscall** on the fast path.

**Why no syscall is still safe.** The kernel sets everything up (allocates the channel, builds
the VA space, maps the pushbuffer and doorbell), then gets out of the way. Isolation is enforced
by **hardware + firmware**, not by the kernel inspecting commands:

1. each channel can only address its own VA space (page tables the driver controls)
2. privileged methods/registers are not reachable from user channels
3. context switches must not leak state between contexts
4. timeslicing, preemption (compute preemption since Pascal) and watchdogs keep one tenant
   from monopolizing the GPU
5. errors are contained: robust-channel (RC) recovery kills only the faulting channel/TSG

Contrast: some older Intel GPUs needed a *software command parser* in the kernel to validate
batch buffers. A hardware gap there (CVE-2019-0155) let the blitter write arbitrary memory.

---

## 7. Engines and units (what each one implies for security)

| Unit | Job | Security relevance |
|---|---|---|
| GR / SMs | Graphics + compute | Context isolation, local/shared memory clearing, perf-counter side channels |
| CE (copy engines) | DMA between VRAM/sysmem/peers | Can touch sysmem → depends on IOMMU + correct mappings. In CC mode they encrypt/decrypt bounce buffers. |
| NVDEC/NVENC/NVJPG/OFA | Media codecs | Parse **untrusted bitstreams** (hardware + firmware), an input-validation attack surface |
| Host/PBDMA + scheduler | Fetch and schedule work | Privileged-method enforcement, DoS (timeslice/watchdog) |
| GMMU | Address translation | The isolation primitive. TLB invalidation correctness. |
| GSP (RISC-V) | Runs GSP-RM (most of the driver's "brain") | Huge firmware attack surface; RPC trust boundary with the CPU driver |
| SEC2 | Security engine (crypto, secure-boot helpers, content protection) | Holds secrets and must be hardened |
| PMU | Power/clock management | Signed firmware requirement (Maxwell 2+) |
| FSP (Hopper+) | Internal root of trust, chain of trust, config knobs | The anchor of secure boot and attestation |
| DISP | Display | Content-protection keys, scan-out buffers |
| Fuses | Chip ID, keys, revocation versions, debug/production mode | Anti-rollback, debug lock |
| VBIOS / InfoROM | Boot code+tables / persistent config & error logs | Must be signed. Persistent config knobs (ECC, CC mode, vGPU mode). |

---

## 8. Reliability vocabulary (comes up in on-call / release discussions)

- **ECC** (SECDED) on VRAM/caches. **Page retirement** (older) / **row remapping** (A100+).
  ECC also mitigates Rowhammer on GDDR6 (*GPUHammer*, 2025). Non-default ECC configurations are
  a security-relevant setting.
- **Xid** errors in the kernel log: `NVRM: Xid (PCI:0000:01:00): 31, ...`. Common ones:
  13 (graphics engine exception), 31 (MMU fault), 43 (GPU stopped processing), 48 (double-bit
  ECC), 79 (fell off the bus), 119/120 (GSP RPC timeout / GSP error).
- **Reset:** FLR (function level reset), secondary bus reset, GPU recovery. Needed between
  tenants in passthrough so no state carries over.

---

## 9. Glossary (quick recall)

| Term | One-liner |
|---|---|
| Platform firmware | UEFI/BIOS on the host CPU: enumerates PCIe and assigns BARs before the OS runs |
| Device firmware | Code for the GPU's own microcontrollers (VBIOS ucode, GSP-RM, ...); what "firmware" alone means in these notes |
| BAR | Window of device memory/registers in CPU physical address space |
| MMIO | CPU load/store to device registers through a BAR |
| DMA / bus master | Device-initiated memory access |
| IOMMU / IOVA | Per-device address translation + protection / the addresses devices use |
| MSI-X | Message-signalled interrupts (device writes to an address) |
| Channel / GPFIFO / pushbuffer | GPU submission context / ring of pointers / command stream |
| USERD / doorbell | Put/get pointers / "new work" notification register |
| TSG / runlist | Channel group sharing a context / scheduler list |
| QMD | Compute launch descriptor |
| Instance block | Per-channel struct with page-directory base and saved state |
| GMMU / PDE / PTE | GPU MMU and its page-table entries |
| UVM | Unified (managed) memory; GPU page-fault servicing in `nvidia-uvm.ko` |
| GSP / GSP-RM | GPU System Processor (RISC-V) / Resource Manager firmware running on it |
| Falcon | NVIDIA's legacy proprietary microcontroller ISA (being replaced by RISC-V) |
| HS / LS / NS | Heavy-secure / light-secure / non-secure microcontroller modes |
| WPR | Write-protected VRAM region only secure firmware can touch |
| FSP / FMC | Hopper+ root-of-trust processor / the first firmware stage it verifies and boots |
| MIG | Multi-Instance GPU: hardware partitioning (A100+) |
| SR-IOV VF | Virtual function: hardware-assisted device virtualization |
| CC | Confidential Computing (H100+): GPU inside the VM's trust boundary |
