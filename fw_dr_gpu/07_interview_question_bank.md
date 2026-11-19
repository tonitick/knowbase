# 07 — Interview Question Bank

Answer out loud first, then open the sketch. Section numbers point back into the notes.
VS Code's Markdown preview (Ctrl+Shift+V) renders the collapsible answers.

---

## A. GPU and PCIe fundamentals

**A1. Walk me through how the CPU talks to a GPU.**
<details><summary>sketch</summary>

Enumeration → config space → BARs mapped into CPU physical space. CPU→GPU control is **MMIO**
(UC loads/stores to BAR0 registers: posted writes, non-posted reads). Bulk data and commands
move by **DMA** initiated by the GPU (needs Bus Master Enable), translated by the IOMMU.
GPU→CPU notification is by **MSI/MSI-X** (a memory write) or memory semaphores/polling.
User-mode work submission bypasses the kernel via pushbuffer + GPFIFO + doorbell (01 §1–6).
</details>

**A2. What's in each NVIDIA BAR, and which one matters most for security?**
<details><summary>sketch</summary>

BAR0 registers (16 MB+), BAR1 VRAM aperture *through the GPU MMU*, BAR2/3 instance-memory
aperture, I/O for VGA, ROM = VBIOS. BAR0 exposure = full device control (root/kernel only).
BAR1 mappings decide which VRAM the CPU can see, so bugs there leak other contexts' memory.
In CC mode both are firewalled (01 §1).
</details>

**A3. Why can user space submit GPU work without a syscall, and what keeps it safe?**
<details><summary>sketch</summary>

The kernel pre-creates the channel, VA space, and pushbuffer/USERD/doorbell mappings. After
that, user mode writes commands and rings the doorbell. Safety comes from hardware and
firmware: per-channel GMMU page tables written only by the driver, privileged methods
blocked, context-switch save/restore isolation, timeslice/preemption/watchdog, and RC
recovery confining faults (01 §6).
</details>

**A4. What is an IOMMU? What happens without one? What are ATS and "lazy" invalidation?**
<details><summary>sketch</summary>

Per-device DMA address translation and protection (plus interrupt remapping). Without one, a
device can DMA anywhere (this lab server has zero IOMMU groups). ATS lets a device cache
translations, and "translated" requests skip the IOMMU check, so only trusted devices should
get it. Lazy (non-strict) IOTLB flushing leaves a window where freed pages are still
reachable (01 §3).
</details>

**A5. Replayable vs non-replayable GPU faults?**
<details><summary>sketch</summary>

Replayable (Pascal+): the fault goes to a buffer, UVM fixes the mapping or migrates the
page, then the access is replayed (managed memory). Non-replayable/fatal: the channel/TSG is
torn down, Xid 31 (01 §5).
</details>

**A6. What's MIG and how does it differ from time-sliced vGPU?**
<details><summary>sketch</summary>

MIG partitions the hardware (SMs, L2 slices, memory controllers, copy engines) into
instances with their own QoS and fault isolation. Time-slicing shares all hardware in turn,
so the isolation is only temporal: side channels, and noisy-neighbor DoS. Both still share
one kernel driver/firmware TCB (03 §7, 05 §4).
</details>

**A7. What's a channel, TSG, runlist, QMD, USERD?** — see 01 §6 glossary.

**A8. What does "unmap → TLB invalidate → free" protect against?**
<details><summary>sketch</summary>

A GPU-side use-after-free. If pages are freed or reused before stale GPU TLB entries are
invalidated, a context can keep accessing memory that now belongs to someone else. It's the
same rule as IOMMU IOTLB flushing (01 §5).
</details>

---

## B. Linux driver internals

**B1. What happens between `insmod` and your `probe()` running?**
<details><summary>sketch</summary>

Module loaded (signature checked if enforced) → `module_init` → `pci_register_driver` → the
driver core matches the `id_table` against devices without a driver → `probe(pdev, id)`.
Autoloading works through `MODULE_DEVICE_TABLE` aliases and udev/modalias.
</details>

**B2. Coherent vs streaming DMA? Why does direction matter?**
<details><summary>sketch</summary>

Coherent = long-lived shared memory both can access (rings). Streaming = per-transfer mapping
with ownership handoff and `dma_sync_*`. Direction lets the IOMMU enforce read-only/write-only
and drives cache maintenance. Map minimal ranges and unmap promptly (02 §3).
</details>

**B3. Why can't you sleep in an interrupt handler? How do you defer work?**
<details><summary>sketch</summary>

There's no process context to reschedule and you may hold spinlocks with IRQs disabled. Use
threaded IRQs, workqueues, or (legacy) tasklets. Use `GFP_ATOMIC` in atomic context (02 §4).
</details>

**B4. What does `copy_from_user` do that `memcpy` doesn't?**
<details><summary>sketch</summary>

Checks the address range (`access_ok`), handles faults safely (returns bytes not copied),
toggles SMAP, may sleep, and with hardened usercopy checks the kernel-side object bounds
(02 §5.2).
</details>

**B5. Explain a double fetch, with an example and a fix.** — 05 §2.3, Lab 2 BUG 4.

**B6. How do you implement mmap of a driver buffer safely?**
<details><summary>sketch</summary>

Overflow-safe offset/length validation; correct `pgprot` (UC registers / WC apertures);
`VM_DONTEXPAND` for fault-based mappings; tie the backing object's lifetime to the VMA
(`vm_ops` open/close refcount) or zap mappings before freeing; never expose privileged
registers in a mapped page; consider rejecting `VM_EXEC` (02 §5.3, 05 §2.6).
</details>

**B7. How do you manage object lifetime across concurrent ioctls?**
<details><summary>sketch</summary>

Refcounted objects (`kref`/`refcount_t`); take the reference under the lock that protects the
lookup table; remove from the table before dropping the table's ref; document lock ordering;
test with lockdep, KCSAN, KASAN (02 §8).
</details>

**B8. A driver loads firmware with `request_firmware`. Who checks it's authentic?**
<details><summary>sketch</summary>

Not the kernel (module signing doesn't cover firmware). The device must verify it (NVIDIA's
BROM/HS chain), or IMA appraisal. The driver must still parse the file defensively, because
under lockdown root→kernel is a security boundary (02 §9).
</details>

**B9. How would you debug a kernel oops in a GPU driver?**
<details><summary>sketch</summary>

`dmesg` → decode with `faddr2line`/`decode_stacktrace.sh` → reproduce under
KASAN/lockdep → ftrace/bpftrace around the ioctl → kdump + `crash` for post-mortem → QEMU+gdb
(`lx-symbols`) for interactive debugging (02 §11).
</details>

**B10. Linux ↔ Windows driver mapping?** — 02 §12 table (IRP_MJ_DEVICE_CONTROL, METHOD_NEITHER, IRQL, Driver Verifier, DxgkDdiEscape).

---

## C. NVIDIA stack

**C1. Trace `cuLaunchKernel` from the app to the SMs.** — 03 §8 (know all 7 steps and each step's trust boundary).

**C2. What is the RM, and what does a control call look like?**
<details><summary>sketch</summary>

Resource Manager: an object tree (client → device → subdevice → ...). The ioctl escape
`NV_ESC_RM_CONTROL` carries `NVOS54_PARAMETERS {hClient, hObject, cmd, params, paramsSize}`.
The size is checked per escape in `RmIoctl`, then the command is looked up in the NVOC
export table (`paramSize`, flags). Controls are **kernel-only unless flagged
`NON_PRIVILEGED` or `PRIVILEGED`** (root) (03 §1).
</details>

**C3. What changed with GSP-RM? Security pros and cons?**
<details><summary>sketch</summary>

RM logic moved into signed RISC-V firmware, and the kernel module is a thinner RPC shim.
Pros: less kernel code, open-source kernel modules, a firmware-enforced root of trust.
Cons/shifts: a firmware attack surface with different tooling, the CPU↔GSP RPC becomes a
trust boundary (hostile in vGPU/CC), driver and firmware versions are lockstepped, and new
failure modes (Xid 119/120) (03 §2).
</details>

**C4. Why is filtering NVIDIA ioctls with seccomp hard? What does gVisor do?**
<details><summary>sketch</summary>

The real operation (control command id, class) is inside the ioctl's argument struct, which
seccomp can't dereference. gVisor `nvproxy` proxies the ioctls and allowlists specific
escapes, controls, and classes per driver version (03 §1.3, 05 §4).
</details>

**C5. Open kernel modules vs nouveau vs nova?** — 03 §5.

**C6. Name the device nodes and who can open them.** — `/dev/nvidiactl`, `/dev/nvidia0..N`, `/dev/nvidia-uvm`, `/dev/nvidia-modeset`, `/dev/nvidia-caps/*`, DRM nodes. Default mode 0666, so every ioctl is unprivileged attack surface.

---

## D. Firmware and secure boot

**D1. Describe NVIDIA GPU secure boot on Ampere and on Hopper.**
<details><summary>sketch</summary>

Ampere: BROM verifies HS ucode. FWSEC (from VBIOS, HS on GSP) does SB/devinit/scrub and,
when the driver triggers it, FRTS → WPR2. Booter (HS on SEC2) authenticates GSP-RM and runs
it LS on GSP. Hopper/Blackwell: FSP = internal root of trust. The driver sends one
Chain-of-Trust message (FMC location + SHA-384 hash + RSA-3K key + signature) → FSP verifies
and boots FMC → FMC loads GSP-RM. No SEC2/Booter/FRTS (04 §3).
</details>

**D2. NS / LS / HS: who verifies what?**
<details><summary>sketch</summary>

HS (PL3) is verified by hardware/BROM. LS (PL2) and NS (PL0) are verified by HS ucode. Chain:
BROM → HS → LS/NS (04 §2).
</details>

**D3. How does anti-rollback work, and what's the operational risk?**
<details><summary>sketch</summary>

Per-engine/ucode fuse versions (FPF; version = highest burned bit, monotonic). Images carry
signatures per version, and older images can't validate once the fuse moves. Burning is
irreversible: stage the firmware first, burn later, keep the field update path working, and
reserve bumps for security fixes (04 §4).
</details>

**D4. Verified vs measured boot vs attestation?** — 04 §8.

**D5. What is a WPR and why can't the CPU set it up?**
<details><summary>sketch</summary>

A write-protected VRAM region only secure ucode can access, holding secure firmware and
data. Programming its boundaries is a PL3 (HS) privilege, so neither the CPU nor LS code can
do it. That's what makes it trustworthy (04 §3.2, §5).
</details>

**D6. What would you check automatically in every firmware release?**
<details><summary>sketch</summary>

Production-key signature (debug key = hard fail), security version ≥ minimum and consistent
with the fuse plan, no debug commands, stack protector and W^X/PMP config versus the
baseline, no embedded secrets, SBOM/CVE status of third-party code, and size/layout
invariants (04 §9).
</details>

**D7. Explain Hopper Confidential Computing in 60 seconds.**
<details><summary>sketch</summary>

CPU TEE (SEV-SNP/TDX) CVM + GPU in CC mode. SPDM attestation of GPU firmware/config
measurements signed by a device key chained to NVIDIA. AES-GCM encrypted bounce buffers in
shared memory, decrypted inside the GPU by the copy engine. Protected VRAM, BAR firewalls,
debug/profiling locked. Blackwell adds TEE-IO (PCIe IDE + TDISP) (04 §6).
</details>

---

## E. Driver and firmware security

**E1. Top kernel driver bug classes and the tool that catches each?**
<details><summary>sketch</summary>

OOB index (KASAN, CodeQL taint), integer overflow in size math (Coccinelle/CodeQL, KASAN),
double fetch (review, race fuzzing), info leak (KMSAN, init-on-alloc), UAF/races
(KASAN/KCSAN/syzkaller), mmap range/lifetime (invariant tests: **sanitizers miss
out-of-range mappings**), missing authorization (review, interface diffs), type confusion
(typed handle tables) (05 §2, Lab 2).
</details>

**E2. Threat-model a new GPU feature that lets containers share one GPU via time-slicing.**
<details><summary>sketch</summary>

Assets: tenant data in VRAM/caches, model weights, availability. Boundaries: container→driver
ioctls, tenant↔tenant on shared hardware, container→host via the toolkit/hooks. Threats:
residual data (scrubbing), cross-context reads (MMU bugs), perf-counter side channels
(profiling restricted), DoS (timeslice/watchdog/limits), escape via OCI hooks
(CVE-2024-0132, CVE-2025-23266), device-level isolation (CVE-2021-1056). Mitigations:
MIG where isolation matters, gVisor/nvproxy for untrusted code, admin-only profiling,
hardened hooks with a sanitized environment, per-tenant memory limits (05 §1, §4).
</details>

**E3. What did NVIDIAScape (CVE-2025-23266) teach?**
<details><summary>sketch</summary>

A privileged OCI hook (`createContainer`, enable-cuda-compat) running on the host inherited
the image's environment, so `LD_PRELOAD` gave root on the host. Lessons: privilege separation,
sanitize the environment, treat image config as hostile, and an automated invariant check
that privileged hooks never consume image-controlled input (05 §4).
</details>

**E4. Why are GPU drivers such popular LPE targets?**
<details><summary>sketch</summary>

They're huge, complex, performance-tuned, reachable by unprivileged/sandboxed code
(world-accessible nodes, browser GPU processes), manage physical memory and mappings, and
are full of lifetime and concurrency logic. Android Mali/Adreno bugs have been exploited in
the wild (05 §5).
</details>

### Code review exercises (find every issue; answers below each)

**CR1 — register-read ioctl**
```c
struct get_regs { u32 count; u32 offsets[64]; u32 values[64]; };

static long gpu_get_regs(struct gpu *g, void __user *uarg)
{
	struct get_regs p;
	u32 i;

	if (copy_from_user(&p, uarg, sizeof(p)))
		return -EFAULT;
	for (i = 0; i < p.count; i++)
		p.values[i] = readl(g->bar0 + p.offsets[i]);
	return copy_to_user(uarg, &p, sizeof(p));
}
```
<details><summary>issues</summary>

1. `count` unbounded → stack OOB read of `offsets[]` and **stack OOB write** of `values[]`.
2. `offsets[i]` unvalidated → reads any BAR0 register (privileged/secret state, read-to-clear
   side effects) or past the 16 MB mapping. Needs an allowlist + alignment check.
3. No privilege check. Raw register access should be root/kernel-only (default deny).
4. Returns `copy_to_user`'s *bytes-not-copied* as a positive value instead of `-EFAULT`.
5. Spectre-v1 gadget on the user-controlled index (`array_index_nospec`).
6. Hung-device behavior: `0xFFFFFFFF` reads aren't detected.
</details>

**CR2 — firmware RPC handler (runs on a GPU microcontroller; `msg` is in shared memory)**
```c
struct rpc_hdr { u32 func; u32 len; };
struct rpc_dma { u64 dst_sysmem; u32 src_fb_offset; u32 size; };
extern char g_engine_name[32];

void rpc_dispatch(volatile struct rpc_hdr *msg)
{
	u8 buf[256];

	if (msg->len > sizeof(buf))
		return;
	memcpy(buf, (const void *)(msg + 1), msg->len);
	switch (msg->func) {
	case RPC_SET_NAME:
		strcpy(g_engine_name, (const char *)buf);
		break;
	case RPC_DMA_TO_SYSMEM: {
		struct rpc_dma *p = (void *)buf;
		dma_copy(p->dst_sysmem, p->src_fb_offset, p->size);
		break;
	}
	}
}
```
<details><summary>issues</summary>

1. **Double fetch** of `msg->len` from shared memory (check, then use): the CPU side changes it
   in between and overflows `buf`. Copy the header once into a local.
2. `strcpy` into a 32-byte global from a buffer of up to 256 bytes that isn't guaranteed
   NUL-terminated → overflow. Use a bounded copy, require termination, check `len` against
   the expected struct size.
3. No per-function minimum-length check: `RPC_DMA_TO_SYSMEM` with `len < sizeof(struct rpc_dma)`
   uses uninitialized stack bytes.
4. **DMA target/source validation missing**: `src_fb_offset + size` can cover WPR or other
   tenants' VRAM (with integer overflow), and `dst_sysmem` can be any host physical address.
   Validate against owned ranges and configure IO-PMP. On the host side, rely on the IOMMU.
5. No caller authorization: which client/privilege level may request DMA? In vGPU/CC the
   sender is untrusted.
6. Unknown `func` is silently ignored, and there's no error/status reporting.
</details>

**CR3 — mmap + free**
```c
static int gpu_mmap(struct file *f, struct vm_area_struct *vma)
{
	struct client *c = f->private_data;
	struct buffer *b = idr_find(&c->buffers, vma->vm_pgoff);

	if (!b)
		return -EINVAL;
	return remap_pfn_range(vma, vma->vm_start, b->pfn,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static long gpu_free_buffer(struct client *c, u32 id)
{
	struct buffer *b = idr_remove(&c->buffers, id);

	if (b) {
		__free_pages(b->pages, b->order);
		kfree(b);
	}
	return 0;
}
```
<details><summary>issues</summary>

1. No lock around `idr_find` versus `idr_remove`: a race gives a UAF on `b`.
2. Length not validated against the buffer size → maps adjacent physical pages.
3. The mapping holds no reference: free while mapped → **the user keeps access to freed,
   reused pages** (the classic exploited GPU bug).
4. No `vm_ops` open/close for fork/split. No `pgprot` choice (WC/UC for device memory). No
   `VM_EXEC` rejection.
5. `vm_pgoff` used directly as an id (truncation to int on 64-bit).
6. Free path: it should return `-ENOENT` for an unknown id, and must zap or wait for
   mappings and in-flight GPU work before freeing (GPU TLB invalidate!).
</details>

---

## F. Release security automation and tooling

**F1. Design the per-release security scanning pipeline for GPU software from firmware to user mode.** — 06 §3 (draw it; mention SARIF, fingerprints, baseline/ratchet, waivers-as-code, ownership, metrics, two speeds).

**F2. How do you verify hardening flags were actually applied?**
<details><summary>sketch</summary>

Check the shipped artifact (ELF/PE/firmware) rather than trusting the build. Some properties
aren't visible in the binary, so record flags with `-frecord-gcc-switches`/annobin and
verify with annocheck, or check build logs. Watch the asm/prebuilt "AND" effect on CET and
NX. Lab 3 demonstrates it (06 §2).
</details>

**F3. Your checker reports 2,000 findings on day one. Now what?**
<details><summary>sketch</summary>

Don't block anything yet. Baseline everything. Cluster by root cause (one toolchain fix may
clear 1,000). Fix the defaults. Enforce "no new findings" immediately. Burn down the rest with
owners, dates, and waivers. Publish the trend. Tune or remove noisy rules (06 §3, §5).
</details>

**F4. How do you handle a team that says "this finding isn't exploitable, waive it"?**
<details><summary>sketch</summary>

Ask for evidence (reachability, attacker model). Offer a time-boxed waiver with an owner and
a ticket. Escalate by risk, not by opinion. Capture the decision as code. If they're right,
fix the rule (FP feedback).
</details>

**F5. Static analysis vs fuzzing vs binary analysis: where does each fit for drivers/firmware?** — 06 §3 (+ "sanitizers can't see out-of-range mmap": Lab 2 BUG 7).

**F6. What's SARIF, and why do you care?** — a standard results format: one triage pipeline, fingerprints for tracking, suppressions/baselineState.

**F7. How do you write a check for a security *invariant* rather than a flag?**
<details><summary>sketch</summary>

Make the invariant explicit ("no new user-reachable RM controls without review", "privileged
OCI hooks don't read image environment", "no 0666 device nodes except X"). Extract the facts
deterministically (generated tables, manifests, installers). Diff against the approved
baseline. Route any delta to review automatically (03 §1.3, 06 §1).
</details>

**F8. Policy-as-code: what and why?** — versioned, reviewed, testable rules (JSON/Rego/Semgrep), waivers with expiry, fail closed on policy errors (Lab 3).

---

## G. AI agents in security

**G1. Where would you *not* use an LLM in this pipeline?**
<details><summary>sketch</summary>

Not as the sole detector or the release gate, and not for anything needing determinism or
audit-grade reproducibility (pass/fail of hardening checks, signature verification). Use it
where output is verifiable, or where it saves expert time with a human in the loop (06 §4).
</details>

**G2. Design an agent that triages static-analysis findings for driver code.** — 06 §4.1–4.2 (inputs, tools, structured output with evidence, verifier, human queue, budgets).

**G3. How do you evaluate it before you trust it?**
<details><summary>sketch</summary>

Golden sets (labeled history, reverted CVE fixes, injected bugs like Lab 2), precision/recall
against experts, severity agreement, fix acceptance, cost/latency, regression suites in CI for
prompt/model changes, shadow mode → assist → partial automation with audit sampling (06 §4.3).
</details>

**G4. How do you protect the agent from prompt injection in code it reads?**
<details><summary>sketch</summary>

Treat repo content as data; keep instructions separate; least-privilege tools (read-only,
no egress); drafts rather than merges; deterministic re-verification of claims; audit logs;
red-team with tools like garak (06 §4.4).
</details>

**G5. Describe an agentic workflow you've built end to end.** — prepare your own story: goal, tools, failure modes, eval, adoption numbers.

**G6. Take a proven agentic workflow from prototype to production. What changes?**
<details><summary>sketch</summary>

Reliability (retries, timeouts, idempotency), observability (traces per tool call), cost
controls, eval gates in CI, access control and data governance, on-call ownership,
versioning of prompts, tools, and models, a rollback plan, documentation, and support
channels for users.
</details>

**G7. What has NVIDIA published on agentic security?** — the "Vulnerability Analysis for Container Security" AI Blueprint (agentic CVE triage → VEX), garak, NeMo Guardrails (06 §4).

---

## H. Behavioral (prepare STAR stories; the job description explicitly asks for these)

| Prompt | Maps to |
|---|---|
| A tool you took from prototype to broad adoption **without authority** | "Track record ... without direct authority" |
| A manual security workflow you automated (what, how much time saved) | "finding manual workflows and reinventing them" |
| A disagreement with a product team over a finding's severity | "prioritize its findings with product teams" |
| A false-positive problem you fixed in a tool you owned | owning the scanning pipeline |
| A time you integrated a check into CI/CD or a release process | CI/CD requirement |
| A vulnerability you found in drivers/kernel/firmware: root cause, fix, systemic follow-up | 5+ years in driver/kernel/fw security |

STAR skeleton: **S**ituation (1 line) → **T**ask (your goal and the constraint, e.g. "no
authority over 12 teams") → **A**ction (3–4 concrete steps, with *your* decisions) →
**R**esult (numbers: adoption %, findings fixed, hours saved, regressions blocked) →
lesson learned.

---

## I. Questions to ask them

1. How is the release security bar defined today: documents, checklists, or code? What fraction is automated?
2. Which agentic workflows are already in production, and what's the approved model/infra for proprietary source (on-prem / NIM)?
3. Where does triage time go today: noise, ownership routing, or fix verification?
4. How do firmware, kernel driver, and user-mode teams differ in tooling and release cadence?
5. What would make this hire's first 6 months a clear success?
