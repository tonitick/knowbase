# 05 — Security of GPU Drivers and Firmware

## 1. Trust boundaries (start every threat model here)

| # | Boundary | Attacker | Entry points | Typical impact |
|---|---|---|---|---|
| 1 | User process → kernel driver | Any local user (nodes are 0666), container, browser GPU process | ioctl/escape, mmap, read/write, sysfs/debugfs, module params | LPE, kernel info leak (KASLR bypass), DoS |
| 2 | GPU context ↔ GPU context | Another tenant's GPU work | Shared HW: memory, caches, perf counters, scheduler | Cross-tenant data leak, covert/side channels, DoS |
| 3 | Container → host | Malicious image / workload | Device nodes, OCI hooks (Container Toolkit), injected host libs | Container escape |
| 4 | Guest VM → host | Malicious guest | vGPU manager (host user+kernel), passthrough device | VM escape, host DoS |
| 5 | Host → Confidential VM | Cloud admin / hypervisor | DMA bounce buffers, GPU config, firmware, error logs | Confidentiality break |
| 6 | Kernel driver → GPU firmware | Compromised host or guest (vGPU/CC) | GSP RPC queues, falcon mailboxes, FSP messages | Firmware compromise → persistent, invisible |
| 7 | Device → host | Malicious/compromised device firmware | DMA, MSI, register values, ring contents | Host memory corruption (needs IOMMU) |
| 8 | Untrusted content → UMD/firmware | Web page (WebGL/WebGPU), media file, model file | Shader compilers, PTX JIT, NVDEC bitstream parsing | Code execution in GPU process / firmware |
| 9 | Release/supply chain | Insider, CI compromise, mistakes | Signing, build flags, third-party code | Unsigned/debug-signed/unhardened binaries ship |

---

## 2. Bug classes, with code (know one example of each)

### 2.1 Unchecked index / size (OOB, CWE-129/787)
```c
/* BAD */
bo = ctx->bos[args.handle];                         /* handle straight from user */
/* GOOD */
if (args.handle >= ARRAY_SIZE(ctx->bos))
	return -EINVAL;
bo = ctx->bos[array_index_nospec(args.handle, ARRAY_SIZE(ctx->bos))]; /* + Spectre-v1 */
```

### 2.2 Integer overflow / truncation in size math (CWE-190)
```c
/* BAD: result stored in u32 → 0x10000001 entries * 16 bytes truncates to 16 */
u32 bytes = args.count * sizeof(struct entry);
buf = kmalloc(bytes, GFP_KERNEL);
if (copy_from_user(buf, uptr, bytes)) ...
for (i = 0; i < args.count; i++) consume(&buf[i]);  /* walks far past 16 bytes */
/* GOOD */
if (args.count == 0 || args.count > MAX_ENTRIES)
	return -EINVAL;
buf = memdup_user(uptr, array_size(args.count, sizeof(*buf))); /* saturates on overflow */
```
Same pattern in firmware: `offset + size` checks that wrap (`if (off + len > limit)` with
32-bit `off` near `0xFFFFFFFF`). Overflow-safe form: `if (off > limit || len > limit - off)`.

### 2.3 Double fetch / TOCTOU (CWE-367)
```c
/* BAD */
get_user(n, &uhdr->count);                 /* fetch #1: validated */
if (n > MAX) return -EINVAL;
k = kmalloc(struct_size(k, ent, n), GFP_KERNEL);
copy_from_user(k, uhdr, struct_size(k, ent, n));
for (i = 0; i < k->count; i++)             /* fetch #2: attacker raced count upward */
	use(&k->ent[i]);
/* GOOD: use the validated local `n` (or require k->count == n) */
```
Applies equally to **shared memory with a device or firmware** (rings, RPC queues, bounce
buffers): read once into private memory, validate, use only the private copy. Container
Toolkit's CVE-2024-0132 was a TOCTOU in a different setting (filesystem paths); the class
is the same.

### 2.4 Information leaks (CWE-200/908)
```c
struct out { __u32 a; __u64 b; };   /* 4 bytes of implicit padding after a */
/* BAD */
struct out o; o.a = 1; o.b = 2;
copy_to_user(u, &o, sizeof(o));     /* leaks 4 bytes of kernel stack */
/* GOOD */
memset(&o, 0, sizeof(o)); ...       /* and design UAPI structs without implicit padding */
```
Also: kernel pointers used as "cookies" or handles (KASLR bypass), `%px` in logs, uninitialized
heap (`kmalloc` vs `kzalloc`), and **unscrubbed GPU memory** handed to the next allocation or
tenant (VRAM, sysmem pages, on-chip local memory).

### 2.5 Use-after-free from lifetime/race bugs (CWE-416/362)
```c
/* BAD: no reference taken; concurrent DESTROY ioctl frees bo */
mutex_lock(&ctx->lock); bo = xa_load(&ctx->bos, h); mutex_unlock(&ctx->lock);
fill(bo);                                   /* bo may already be freed */
/* GOOD: kref_get() under the lock; kref_put() when done (see 02 §8) */
```
Hot spots: destroy vs. use on two threads, close() vs. in-flight work, error paths that drop
a reference twice, callbacks (fences, interrupts, MMU notifiers) firing after the object is gone.

### 2.6 mmap lifetime and range bugs
- No check of `vm_pgoff`/length → maps memory beyond the object (adjacent kernel pages).
- Object freed while still mapped → the **user keeps access to a physical page the kernel
  reuses**. This is the dominant exploited GPU-driver bug class (many in-the-wild Android
  Mali/Adreno exploits, e.g. CVE-2023-4211).
- Fault-based mappings without `VM_DONTEXPAND` let `mremap()` grow the mapping past what
  `mmap` validated (`remap_pfn_range()` sets it for you). Also: mapping a register page that
  contains privileged registers next to the doorbell.
- **GPU-side equivalent:** unmapping from GPU page tables without a TLB invalidate before the
  pages are freed.

### 2.7 Missing authorization / confused deputy (CWE-862/863)
```c
/* BAD: privileged op reachable by anyone who can open a 0666 device node */
case TOY_IOCTL_SET_CLOCKS: return toy_set_clocks(ctx, &a);
/* GOOD */
if (!capable(CAP_SYS_ADMIN)) return -EPERM;      /* or object-ownership checks */
```
- Prefer checking the **opener's** credentials (`file->f_cred`) over `current`'s, so an fd
  passed to a privileged process can't be abused as a confused deputy.
- Cross-client object access: can client A name, dup or map client B's handle?
- NVIDIA RM's model: controls are kernel-only by default, `NON_PRIVILEGED`/`PRIVILEGED`
  opt-ins, plus capability device nodes (`/dev/nvidia-caps`) for MIG (see 03 §1.3).

### 2.8 Type confusion on handles (CWE-843)
A generic handle table returns "an object". The caller casts it to a buffer object while the
handle actually names a fence or a channel. Always check `obj->type` (or keep per-type tables).

### 2.9 Resource exhaustion (DoS)
Unbounded allocations per fd, kernel memory not charged to the cgroup (use
`GFP_KERNEL_ACCOUNT`), long loops while holding a lock, GPU work that never finishes (needs
timeslice/preemption/watchdog), log flooding.

### 2.10 Firmware-specific classes
- trusting length/offset fields in RPC messages (from kernel RM, guest, or another engine)
- **TOCTOU on shared queues**: re-reading a message header after validation
- **DMA target validation**: a message supplies an address and the firmware DMAs to it
  (could hit WPR, another tenant, or arbitrary host memory). Validate against owned ranges and
  configure IO-PMP.
- HS/LS "API" entry points called by lower-privileged code with unchecked arguments
- secrets left in DMEM/registers on error paths, timing side channels in crypto
- fault injection (voltage/clock glitch) skipping a signature check
- debug/test commands left enabled in production builds

### 2.11 Hardware-level / side channels
- **Performance counters** as a side channel (CVE-2018-6260 → profiling restricted to admin
  by default since 2019).
- **Uncleared local memory** (*LeftoverLocals*, CVE-2023-4969, Trail of Bits 2024: Apple, AMD,
  Qualcomm, Imagination GPUs affected; NVIDIA reported not affected).
- **Rowhammer on GDDR6** (*GPUHammer*, July 2025, RTX A6000). NVIDIA's guidance is to enable
  system-level ECC (`nvidia-smi -e 1`), which is off by default on those workstation parts.
  A 2026 follow-up paper claims to defeat ECC on GDDR6 workstation cards; I found only one
  report of it, so verify before citing.

---

## 3. Mitigations (layered)

### 3.1 Kernel (what reduces the blast radius of a driver bug)
| Mitigation | Config / mechanism | Defeats / hinders |
|---|---|---|
| SMEP / SMAP (x86), PXN/PAN (arm64) | CPU features | Executing/accessing user memory from kernel |
| KASLR | `CONFIG_RANDOMIZE_BASE` | Hard-coded addresses (needs info leak) |
| Stack protector | `CONFIG_STACKPROTECTOR_STRONG` | Linear stack overflows |
| FORTIFY_SOURCE | `CONFIG_FORTIFY_SOURCE` | Known-size `memcpy`/`strcpy` overflows |
| Hardened usercopy | `CONFIG_HARDENED_USERCOPY` | copy_to/from_user spanning objects |
| Auto-init stack | `CONFIG_INIT_STACK_ALL_ZERO` | Uninitialized-stack leaks |
| Init on alloc/free | `init_on_alloc=1`, `init_on_free=1` | Heap info leaks, stale data |
| Freelist hardening, random kmalloc caches | `SLAB_FREELIST_HARDENED`, `RANDOM_KMALLOC_CACHES` | Heap exploitation |
| CFI / IBT / shadow stacks | `CONFIG_CFI_CLANG`, `X86_KERNEL_IBT`, `SHADOW_CALL_STACK` (arm64) | Control-flow hijack |
| refcount_t | saturating counters | Refcount overflow → UAF |
| Strict RWX, module signing, lockdown | `STRICT_KERNEL_RWX`, `MODULE_SIG(_FORCE)`, lockdown LSM | Code injection, root→kernel |
| `array_index_nospec`, retpolines/return thunks | Spectre v1/v2 hardening | Speculative OOB |

(Ubuntu's 5.15 kernel on this server has STACKPROTECTOR_STRONG, FORTIFY_SOURCE,
HARDENED_USERCOPY and RETPOLINE enabled, but **not** INIT_STACK_ALL_ZERO, so the
padding-leak bug in Lab 2 really would leak here.)

### 3.2 User-mode components (driver libraries, daemons, tools)
Compiler/linker hardening: see the table in 06 §2. Plus **privilege separation** (no setuid
helpers, minimal root daemons), sandboxing of parsers/compilers, and environment
sanitization for privileged helpers (lesson of CVE-2025-23266).

### 3.3 Windows kernel driver
`/GS`, `/guard:cf` (CFG), `/CETCOMPAT`, `/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT`, **HVCI
compatibility** (no RWX sections, NX pool allocations), Driver Verifier in testing, signed
with attestation/WHQL, avoid `METHOD_NEITHER`, validate every `DxgkDdiEscape` blob.

### 3.4 Firmware
Memory-safe languages (SPARK, Rust), stack canaries, PMP/MPU W^X, minimal HS code,
signature-verified loading, anti-rollback fuses, debug lock, secret scrubbing, fault-injection
countermeasures, fuzzing message handlers in a host-compiled harness or emulator.

### 3.5 Design-level (cheapest and strongest)
- Shrink the surface: render nodes vs primary nodes; non-privileged root client class; deny
  by default (RM controls kernel-only unless flagged).
- **Centralize validation**: one generic copy-in/out with per-command size tables (DRM's
  `drm_ioctl`, RM's escape table + exported-method `paramSize`), so handlers never touch raw
  user pointers.
- Typed, refcounted handle tables. Explicit ownership and lifetime rules for mappings.
- Secure defaults: profiling admin-only, debugfs off in production, ECC on where it is a
  security control.

---

## 4. Isolation mechanisms (a "ways to stand out" item in the job description)

| Mechanism | What it isolates | Strength | Watch-outs |
|---|---|---|---|
| **Per-process GPU VA spaces + channels** | GPU memory between processes | HW-enforced by GMMU | Driver bugs in PTE management, TLB invalidation, scrubbing, BAR1 mappings |
| **Time-slicing / preemption** | GPU time | Medium | Side channels, DoS if preemption disabled |
| **MIG** (A100+) | SMs, L2, memory controllers/bandwidth, copy engines, decoders per instance | Strong (perf + fault isolation) | Shared kernel driver; `/dev/nvidia-caps` access control |
| **vGPU** (time-sliced or MIG-backed; SR-IOV on Ampere+) | VMs sharing a GPU | Medium–strong | Guest→host surface in vGPU manager; scheduling side channels |
| **Passthrough (VFIO)** | Whole GPU per VM | Strong | IOMMU groups/ACS; reset & scrub between tenants; guest must not persist malicious state (signed VBIOS/firmware, fuses) |
| **Containers** | Filesystem/process namespaces | **Weak for GPU**: shared host kernel driver | Device node exposure, OCI hooks run as root on host, host libraries injected |
| **Sandboxing**: gVisor `nvproxy`, seccomp, browser GPU-process sandbox | Kernel attack surface | Medium | `nvproxy` must allowlist ioctls/controls per driver version. seccomp can't see the control command inside the struct. |
| **Privilege separation** | Split UMD/KMD/firmware/daemons | Structural | Interfaces between parts become trust boundaries (e.g. CPU↔GSP RPC) |
| **Confidential Computing** (H100+) | Tenant vs. host/hypervisor/admin | Strong (HW + attestation) | Firmware in TCB, bounce-buffer handling, perf/debug lockdown |

Container-specific lessons (NVIDIA Container Toolkit):
- **CVE-2024-0132** (Sept 2024): TOCTOU with default configuration; a crafted container
  image could gain access to the host filesystem. Fixed in 1.16.2. The fix was incomplete:
  the **CVE-2025-23359** bypass (reported by Trend Micro) was fixed in 1.17.4. *Lesson:
  security fixes need regression tests and variant analysis.*
- **CVE-2025-23266 "NVIDIAScape"** (Wiz, reported at Pwn2Own Berlin 2025; bulletin July
  2025): the `createContainer` OCI hook (`nvidia-ctk ... enable-cuda-compat`) ran as root on
  the host and **inherited environment variables from the container image**, so
  `LD_PRELOAD` in a Dockerfile loaded the attacker's library into a privileged host process.
  Toolkit ≤ 1.17.7 affected, fixed in 1.17.8 (GPU Operator 25.3.1).
  *Lessons: privilege separation, environment sanitization, and an automated check that
  privileged hooks never consume image-controlled configuration.*
- **CVE-2021-1056**: `nvidia.ko` did not fully honor file-system permissions for GPU
  device-level isolation (relevant when a container is given only some GPUs).

---

## 5. Case studies: one-line lessons

| Case | Lesson to cite |
|---|---|
| CVE-2018-6260 (perf-counter side channel) | Secure-by-default: profiling admin-only |
| CVE-2021-1056 (device-level isolation) | Isolation must be enforced in the kernel, not assumed from device-node layout |
| CVE-2024-0132 → CVE-2025-23359 | TOCTOU class; incomplete fixes → regression tests + variant hunting |
| CVE-2025-23266 NVIDIAScape | Privileged helpers must not inherit attacker-controlled env/config |
| Windows escape-handler bug batches (e.g. Google Project Zero, 2016) | Centralize validation of private escape blobs; fuzz them |
| In-the-wild Mali/Adreno exploits (2023) | GPU drivers are prime LPE targets reachable from sandboxes; mapping lifetime bugs |
| Intel CVE-2019-0155 (blitter could write arbitrary memory) | When HW can't enforce isolation, SW (a command parser) has to |
| LeftoverLocals (2024) | Clear on-chip memory between kernels/tenants |
| GPUHammer (2025) | ECC is a security control; config baselines matter |

How to read an NVIDIA bulletin: component ("kernel mode layer", "user mode layer", "Virtual
GPU Manager", "Container Toolkit"), CWE, CVSS vector (AV:L/PR:L is the usual local
unprivileged case), affected **driver branches** (each supported branch gets its own fixed
version), impact list (DoS / info disclosure / data tampering / code execution / EoP).

---

## 6. Review checklists

### 6.1 ioctl / escape / control handler
1. Is the command reachable by unprivileged users? Should it be? (default deny)
2. Is user input **copied exactly once** into kernel memory, with a size from a trusted table?
3. Are **unknown flags and non-zero reserved fields** rejected?
4. Every index bounds-checked (and `array_index_nospec` where it gates a load)?
5. Every size computation overflow-safe (`array_size`, `struct_size`, `check_*_overflow`)?
6. Embedded user pointers (nested structs) handled with the same rigor?
7. Handles: owned by this client? Right type? Reference taken under the right lock?
8. Output fully initialized (padding, error paths)? No kernel pointers returned?
9. Concurrent calls on the same object: locking correct, no check-then-act gaps?
10. Error paths: every resource released exactly once?
11. Resource limits per client (memory, objects, outstanding work)?

### 6.2 mmap path
Offset/length validated overflow-safely; the right `pgprot` (UC for registers, WC for
apertures); `VM_DONTEXPAND|VM_DONTDUMP`; register pages contain only user-safe registers;
lifetime: VMA holds a reference or mappings are zapped before free; fork/`mremap`/`munmap`
behavior considered.

### 6.3 Firmware message handler
Message size bounded before any parse; header copied once from the shared queue; all
offsets/lengths overflow-safe; DMA addresses validated against owned regions (and IO-PMP
configured); the sender's privilege checked per command; secrets never echoed in responses or
logs; error path returns cleanly without leaving state half-updated; fuzzed.
