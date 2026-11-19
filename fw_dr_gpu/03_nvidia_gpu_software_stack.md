# 03 — The NVIDIA GPU Software Stack (Linux first, Windows mapped)

```
 Applications: CUDA apps / PyTorch, games, compositors, browsers (GPU process)
 ───────────────────────────── user-mode driver (UMD) ─────────────────────────────
  libcuda.so            CUDA driver API (cuInit, cuLaunchKernel ...)
  libnvidia-ptxjitcompiler / NVVM   PTX → SASS JIT compilers  (compile untrusted-ish input!)
  libGLX_nvidia / libEGL_nvidia / libnvidia-glcore   OpenGL/EGL (+ Vulkan ICD)
  libnvidia-ml (NVML) → nvidia-smi, DCGM        libnvcuvid / libnvidia-encode (video)
 ────────────────── device nodes (ioctl + mmap), default mode 0666 ──────────────────
  /dev/nvidiactl   /dev/nvidia0..N   /dev/nvidia-uvm(-tools)   /dev/nvidia-modeset
  /dev/nvidia-caps/*  (MIG & capability gating)    /dev/dri/card*, renderD* (nvidia-drm)
 ───────────────────────────────── kernel modules ──────────────────────────────────
  nvidia.ko          OS interface layer + Resource Manager (RM) "kernel RM"
  nvidia-uvm.ko      Unified memory: GPU page-fault servicing, migration, HMM
  nvidia-modeset.ko  NVKMS: display / modesetting
  nvidia-drm.ko      DRM/KMS integration: PRIME, Wayland/GBM, fbdev
  nvidia-peermem.ko  GPUDirect RDMA with NICs
 ───────────── PCIe: MMIO + shared-memory RPC queues ─────────────
  GSP-RM firmware (RISC-V)  + engine ucode (FECS/GPCCS, PMU, SEC2, NVDEC...) + FSP + VBIOS
 ───────────────────────────────────── GPU HW ─────────────────────────────────────
  Daemons/tools: nvidia-persistenced, nvidia-smi, nvidia-fabricmanager (NVSwitch),
                 NVIDIA Container Toolkit (libnvidia-container, nvidia-ctk, OCI hooks/CDI)
```

---

## 1. The Resource Manager (RM) and its API

The RM is the heart of NVIDIA's driver. It allocates and manages everything on the GPU:
memory, channels, engines, VA spaces, events, display, power. It's the same core code across
OSes (Linux, Windows, and the GSP firmware build).

### 1.1 Object model
Everything is an **object** in a tree, named by client-chosen **handles**, with a **class** number:

```
client  (NV01_ROOT 0x0 / NV01_ROOT_NON_PRIV 0x1)
 └─ device     (NV01_DEVICE_0      0x0080)
     ├─ subdevice  (NV20_SUBDEVICE_0 0x2080)   ← most "GPU" controls live here
     ├─ memory     (NV01_MEMORY_SYSTEM 0x3e, NV01_MEMORY_LOCAL_USER 0x40, ...)
     ├─ VA space, channel group (TSG), channel (e.g. AMPERE_CHANNEL_GPFIFO_A 0xc56f)
     │    └─ engine object (e.g. AMPERE_COMPUTE_A 0xc6c0)
     └─ usermode doorbell (VOLTA_USERMODE_A 0xc361), events, ...
```

**Security property:** handles are scoped to a *client*. A process must not be able to name
or use another client's objects except through explicit, checked sharing paths
(`DUP_OBJECT`, `SHARE`, export/import to fd).

### 1.2 The ioctl ("escape") interface
User mode reaches RM through ioctls on `/dev/nvidiactl` and `/dev/nvidiaN`. The low byte of the
ioctl number is an **escape code** (`src/nvidia/arch/nvalloc/unix/include/nv_escape.h`):

| Escape | Code | Purpose |
|---|---|---|
| `NV_ESC_RM_ALLOC` | 0x2B | create an object (class + alloc params) |
| `NV_ESC_RM_FREE` | 0x29 | destroy an object |
| `NV_ESC_RM_CONTROL` | 0x2A | **run a control command on an object** |
| `NV_ESC_RM_MAP_MEMORY` / `UNMAP_MEMORY` | 0x4E / 0x4F | CPU mappings (then `mmap()` on the fd) |
| `NV_ESC_RM_MAP_MEMORY_DMA` | 0x57 | map memory into a GPU VA space |
| `NV_ESC_RM_DUP_OBJECT` / `SHARE` | 0x34 / 0x35 | cross-client object sharing |
| `NV_ESC_RM_VID_HEAP_CONTROL` | 0x4A | legacy video-memory heap ops |
| `NV_ESC_RM_EXPORT_OBJECT_TO_FD` / `IMPORT_..._FROM_FD` | 0x5C / 0x5D | fd-based sharing |

Dispatch path (open-gpu-kernel-modules):
`kernel-open/nvidia/nv.c: nvidia_ioctl()` → `src/nvidia/arch/nvalloc/unix/src/escape.c: RmIoctl()`.
`RmIoctl` keeps a **table of expected parameter sizes per escape** and rejects mismatches.
The control handler then calls into `src/nvidia/src/kernel/rmapi/control.c`.

### 1.3 Control calls: a two-level interface
```c
typedef struct {                     /* src/common/sdk/nvidia/inc/nvos.h */
    NvHandle hClient;
    NvHandle hObject;
    NvV32    cmd;                    /* e.g. 0x20800110 = NV2080_CTRL_CMD_GPU_GET_NAME_STRING */
    NvU32    flags;                  /*      class 0x2080 | category 0x01 | index 0x10       */
    NvP64    params NV_ALIGN_BYTES(8);   /* user pointer to a per-command struct */
    NvU32    paramsSize;
    NvV32    status;
} NVOS54_PARAMETERS;
```
- Level 1: the fixed-size `NVOS54_PARAMETERS` (size checked in `RmIoctl`).
- Level 2: the **per-command params blob**. RM finds the command in the class's
  **exported-method table** (NVOC-generated, e.g. `src/nvidia/generated/g_subdevice_nvoc.c`:
  `methodId`, `paramSize`, `flags`, `accessRight`, handler) and copies exactly `paramSize` bytes.
- Some param structs embed **further user pointers** (`NvP64`) that need nested copy-in.
  That deep-copy pattern is historically bug-prone.

**Privilege model (`rmControlValidateClientPrivilegeAccess` in `control.c`):**
- `RMCTRL_FLAGS_NON_PRIVILEGED` → any client
- `RMCTRL_FLAGS_PRIVILEGED` → requires `RS_PRIV_LEVEL_USER_ROOT` (admin) or kernel callers
- **no flag → kernel-only by default.** Deny by default: a new control is not reachable from
  user space unless someone explicitly marks it.
- Routing flags such as `RMCTRL_FLAGS_ROUTE_TO_PHYSICAL` mark controls forwarded to the
  physical RM (GSP-RM, or the vGPU host for a guest).

> **Interview gold:** "A per-release automated check I'd build: extract every control's flags
> from the generated export tables, and diff the set of `NON_PRIVILEGED` and `PRIVILEGED`
> controls against the last release. Any newly user-reachable control, or a param struct that
> grew an embedded pointer, gets routed to security review automatically."
> That's "security invariants → automated per-release checks" from the job description.

There are thousands of controls with different parameter layouts. That's why NVIDIA's ioctl
surface is huge, why gVisor's `nvproxy` must **allowlist** specific escapes, controls and
classes per driver version, and why `seccomp` alone can't filter it (the real command is
*inside* the struct, not in the ioctl number).

---

## 2. GSP-RM: moving the driver into firmware (Turing+)

Since Turing, a RISC-V **GSP (GPU System Processor)** can run most of RM as firmware
(**GSP-RM**). The kernel module becomes a thinner "kernel RM" that:
- handles OS integration (device nodes, mmap, DMA mappings, interrupts plumbing, PM)
- forwards many allocs and controls to GSP-RM as **RPCs** over message queues in shared sysmem
- ships and loads the firmware: `/lib/firmware/nvidia/<driver-version>/gsp_*.bin`. It must
  match the driver version exactly.

**Why it matters for security:**
1. **The attack surface moves.** Much logic now runs on the GPU, outside the kernel. A GSP-RM
   bug is a firmware bug: different mitigations, a different debugger, and its own DMA reach
   (so IOMMU configuration matters).
2. **A new trust boundary (the CPU↔GSP RPC).** With a trusted host kernel the CPU side is more
   privileged, but in **vGPU** (guest requests) and **Confidential Computing** (host
   untrusted) GSP-RM must treat RPC inputs as hostile and validate them independently.
   Defense in depth: validate in kernel RM *and* in GSP-RM.
3. **Open-sourcing became possible.** With the secret sauce in signed firmware, NVIDIA released
   the kernel modules as open source (MIT/GPLv2, May 2022, R515).
4. **New failure modes:** GSP RPC timeouts and GSP errors (**Xid 119/120**).

---

## 3. UVM (`nvidia-uvm.ko`)

- Implements CUDA **managed memory** (`cudaMallocManaged`): one pointer valid on CPU and GPU.
- GPU **replayable faults** land in a fault buffer. UVM services them (migrates pages
  CPU↔GPU, sets up mappings), then tells the GPU to replay. It also uses access counters for
  migration hints.
- Integrates with Linux **HMM** so the GPU can access ordinary `malloc` memory (open modules).
- Its own ioctl interface on `/dev/nvidia-uvm`, plus heavy interaction with the process's
  `mm` (MMU notifiers). It's concurrency-heavy, so lifetime races and UAFs are the risk class.

---

## 4. Display: `nvidia-modeset.ko` + `nvidia-drm.ko`

- NVKMS does modesetting. `nvidia-drm` exposes it through DRM/KMS (`modeset=1`), enabling
  Wayland compositors, PRIME offload, and dma-buf sharing.
- The DRM render node exists, but CUDA does **not** use DRM. It uses `/dev/nvidia*`.

---

## 5. Open vs. proprietary vs. community drivers

| Driver | What | Notes |
|---|---|---|
| Proprietary kernel modules | Closed RM binary + open "kernel interface layer" shim | Needed for pre-Turing GPUs |
| **Open GPU kernel modules** (`NVIDIA/open-gpu-kernel-modules`) | Same user-mode stack; kernel modules open (MIT/GPL) | Require GSP. NVIDIA announced (2024) they become the default from R560 where supported. Required for Grace Hopper / Blackwell. |
| Nouveau (+ NVK in Mesa) | Community, originally reverse-engineered | Uses NVIDIA's GSP-RM firmware on Turing+ in recent kernels |
| **Nova** (`nova-core`, `nova-drm`) | New upstream **Rust** driver for GSP-based GPUs | Its docs (`Documentation/gpu/nova/core/`) are the best public description of the GPU boot/firmware flow (see 04) |

---

## 6. Windows (WDDM) mapping

| Concept | Windows/WDDM |
|---|---|
| UMD | `nvd3dumx.dll`/`nvwgf2umx.dll` (D3D), `nvoglv64.dll` (OpenGL ICD), `nvcuda.dll` (CUDA) |
| Kernel | `dxgkrnl.sys` (Microsoft: VidMm memory manager, VidSch scheduler) + **`nvlddmkm.sys`** (NVIDIA KMD/miniport) |
| Private UMD→KMD channel | `D3DKMTEscape` → `DxgkDdiEscape(pPrivateDriverData, size)`. The analog of RM controls, and historically where many NVIDIA Windows kernel CVEs were ("improper validation in DxgkDdiEscape") |
| GPU VA | WDDM 2.x GpuMmu: per-process GPU VA spaces |
| Scheduling | Hardware-accelerated GPU scheduling (HAGS) moves scheduling into GPU firmware |
| Hang recovery | TDR (Timeout Detection & Recovery) |
| Platform security | Driver signing, HVCI (no RWX / executable pool), kernel CET shadow stacks, vulnerable-driver blocklist |

NVIDIA security bulletins usually split into "GPU Display Driver (Windows/Linux)" and
"vGPU software". Typical wording: *"contains a vulnerability in the kernel mode layer where an
unprivileged regular user can cause an out-of-bounds write / improper index validation ...
may lead to denial of service, escalation of privileges, information disclosure, data
tampering."* Read ten of them before the interview to absorb the vocabulary.

---

## 7. Virtualization and partitioning (security details in 05)

| Mode | How | Isolation |
|---|---|---|
| Passthrough (VFIO) | Whole GPU to one VM | IOMMU + reset between tenants; guest owns the device |
| vGPU (time-sliced) | Host "Virtual GPU Manager" mediates. Pre-Ampere: mediated devices; Ampere+: SR-IOV VFs | Guest→host attack surface in the vGPU manager (common bulletin item) |
| **MIG** (A100+) | Hardware partitions: SMs, L2 slices, memory controllers, copy engines | Strong QoS and fault isolation. Access gated via `/dev/nvidia-caps` |
| Containers | Container Toolkit injects device nodes + host driver libs into the container | **Shares the host kernel driver**: container isolation = driver security + toolkit correctness |
| **Confidential Computing** (H100+) | GPU joins the CVM's trust boundary: attestation, encrypted transfers, protected VRAM | Host/hypervisor untrusted |

---

## 8. End-to-end: what happens on a CUDA kernel launch

Know this cold. Mark the trust boundary at each step.

1. **Init (`cuInit`, context creation).** `libcuda` opens `/dev/nvidiactl`, `/dev/nvidia0`,
   `/dev/nvidia-uvm`. Via `NV_ESC_RM_ALLOC` it creates client → device → subdevice → VA space →
   TSG → channel (GPFIFO) → compute engine object, and maps USERD + the usermode doorbell page
   into the process (`NV_ESC_RM_MAP_MEMORY` + `mmap`).
   *Boundary: user→kernel ioctl/mmap validation, handle ownership, privilege flags.*
2. **Module load.** The cubin's SASS is loaded, or PTX is JIT-compiled by
   `libnvidia-ptxjitcompiler` (*a compiler parsing app-supplied code inside the app's process*).
   Code is copied to GPU memory.
3. **Memory.** `cudaMalloc` → RM allocates VRAM and maps it into the context's GPU VA space
   (RM/GSP-RM writes the PTEs). `cudaMallocManaged` → UVM-managed range.
   *Boundary: only the driver writes page tables, and new allocations must be scrubbed.*
4. **Launch (`cuLaunchKernel`).** `libcuda` writes a **QMD** + methods into a pushbuffer,
   appends a GPFIFO entry, bumps GP_PUT, and rings the **doorbell**. **No syscall.**
   *Boundary: hardware. GMMU limits addressable memory, privileged methods are blocked,
   scheduler/timeslice/preemption prevent DoS.*
5. **Execution.** Host/PBDMA fetches → compute engine → SMs run warps. Context switches are done
   by FECS firmware. Faults on managed memory go to UVM (replayable). Fatal faults → RC
   recovery kills only this channel/TSG (Xid 31/13).
6. **Completion.** The GPU releases a semaphore and/or raises a non-stall interrupt.
   `cudaStreamSynchronize` polls the semaphore or blocks in an ioctl until the event fires.
7. **Teardown / process exit.** Kernel RM frees objects in dependency order, invalidates GPU
   TLBs **before** freeing pages, unpins sysmem, and must handle a process killed mid-operation.
   *Lifetime bugs live here.*

---

## 9. Where to read real code (open-gpu-kernel-modules)

| Path | What to look at |
|---|---|
| `kernel-open/nvidia/nv.c` | `nvidia_ioctl()`, `file_operations`, open/close |
| `kernel-open/nvidia/nv-mmap.c` | `nvidia_mmap()`: how CPU mappings are validated |
| `src/nvidia/arch/nvalloc/unix/src/escape.c` | `RmIoctl()`: per-escape size table, dispatch |
| `src/nvidia/arch/nvalloc/unix/include/nv_escape.h` | Escape codes |
| `src/nvidia/src/kernel/rmapi/control.c` | Control dispatch + `rmControlValidateClientPrivilegeAccess()` |
| `src/nvidia/generated/g_subdevice_nvoc.c` | Exported-method table: `methodId`, `paramSize`, `flags` |
| `src/common/sdk/nvidia/inc/ctrl/` and `.../inc/class/` | Control param structs, class numbers |
| `src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c` | GSP boot + RPC transport |
| `kernel-open/nvidia-uvm/` | UVM (`uvm.c`, `uvm_ioctl.h`) |

Also: `NVIDIA/open-gpu-doc` (class headers, QMD layouts, register manuals) and gVisor's
`nvproxy` (a ready-made inventory of which ioctls/controls CUDA actually needs).

---

## 10. Diagnostics vocabulary

- `nvidia-smi` (`-q` full query, `-e 1` enable ECC, `mig -lgi`), `nvidia-bug-report.sh`,
  `/proc/driver/nvidia/{version,gpus/*}`, module params `NVreg_*` (e.g.
  `NVreg_RestrictProfilingToAdminUsers`, `NVreg_DeviceFileMode`).
- Xid codes: 13, 31, 43, 48, 79, 119, 120 (see 01).
- Security-relevant defaults to know: performance counters are restricted to admin users by
  default since the 2019 fix for CVE-2018-6260 (a side channel through GPU performance
  counters). Device files default to 0666.
