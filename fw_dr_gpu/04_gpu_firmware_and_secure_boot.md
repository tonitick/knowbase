# 04 — GPU Firmware, Microcontrollers and Secure Boot

Primary public source: the Linux kernel's nova-core docs
(`Documentation/gpu/nova/core/{falcon,fwsec,fsp,vbios,devinit}.rst`, at
docs.kernel.org/gpu/nova/). They're written by NVIDIA and Red Hat engineers and are the
clearest public description of how NVIDIA GPUs boot. Read them.

---

## 1. What "firmware" means on a GPU

| Piece | Where it lives | Role |
|---|---|---|
| **VBIOS** | SPI flash on the board (PCI expansion ROM) | Legacy x86 VGA BIOS image, UEFI GOP driver, NVIDIA tables (BIT), devinit scripts, and **ucode partitions**: e.g. **FWSEC** (image type 0xE0) |
| **Engine microcode ("ucode")** | Shipped with the driver (`/lib/firmware/nvidia/...`) or in VBIOS | Runs on the on-chip microcontrollers: PMU, SEC2, FECS/GPCCS, NVDEC/NVENC, **GSP-RM** (big), Booter, FMC |
| **Boot ROM (BROM)** | Mask ROM in silicon | Immutable. Verifies the first signed stage. **The root of trust.** |
| **Fuses** | One-time programmable | Chip identity, key hashes, **revocation/version counters**, production vs debug mode |
| **InfoROM** | Persistent storage on the board | Config (ECC mode, persistent "knobs" such as CC mode and vGPU mode), error logs |
| Board/system firmware (DGX/HGX) | BMC, NVSwitch, CPLDs | Out of scope here, but part of "firmware → user mode" product coverage |

---

## 2. The microcontrollers

**Falcon** (NVIDIA's own small RISC ISA), and newer NVIDIA **RISC-V** cores (a Falcon-style
RISC-V core can run both RISC-V and Falcon code):

- separate **IMEM** (code) and **DMEM** (data) SRAMs: Harvard-style, so data can't simply be
  executed
- **FBDMA via FBIF** (framebuffer interface) to load code/data from VRAM or sysmem, with
  apertures picked by the driver. An **IO-PMP** unit limits what external memory the
  falcon's DMA may touch.
- the host driver controls it via MMIO: reset, configure, DMA firmware in, program **BROM**
  registers (where the signature is), start the CPU
- instances: **GSP** (GPU System Processor, runs GSP-RM), **SEC2** (security engine), **PMU**
  (power), **FECS/GPCCS** (graphics context switching), NVDEC/NVENC, and on Hopper+ **FSP**

### Security modes (privilege levels)

| Mode | Privilege level | Who verifies the code | Typical use |
|---|---|---|---|
| **NS** non-secure | PL0 | (nobody / HS loader) | Legacy, low-trust tasks |
| **LS** light-secure | PL2 | **HS ucode** checks the signature | Runtime firmware: GSP-RM, PMU, SEC2-RTOS, FECS |
| **HS** heavy-secure | PL3 (highest) | **Hardware: the Boot ROM** checks the signature | Short-lived security-critical loaders: FWSEC, Booter, ACR |

Registers and memory regions are gated by privilege level, so only PL3 can, say, program the
WPR boundaries. The resulting chain of trust:

```
   Hardware (Boot ROM on the falcon)  ──verifies──►  HS ucode  ──verifies──►  LS / NS ucode
```

---

## 3. Boot flows by generation

### 3.1 Maxwell 2 → Volta (pre-GSP): "ACR / secure boot"
- From the second-generation Maxwell parts on, several falcons only accept **NVIDIA-signed**
  firmware. (That's why nouveau long struggled with reclocking: PMU firmware had to be signed.)
- The driver loads the HS **ACR** (Access Control Region) ucode. ACR carves out a **WPR**
  (write-protected region) in VRAM, verifies the LS images (FECS, GPCCS, PMU, SEC2) and boots
  those falcons in LS mode from the WPR.

### 3.2 Ampere (GSP-RM era; per nova-core docs)
Before the driver loads:
- The **FWSEC** application from VBIOS runs on the **GSP in HS mode**. It performs secure boot
  ("SB") of other microcontrollers (e.g. loads devinit onto the PMU in LS mode) and scrubs VRAM
  (ECC init; consumer parts scrub partially, then asynchronously).

What the driver does:
1. **FWSEC-FRTS:** extract FWSEC from VBIOS, patch in the right signature, run it in HS on
   GSP. FRTS carves out **WPR2** (holds data needed for power management). After that **only HS
   ucode can access WPR2**. Neither the host CPU nor LS ucode can do this step.
2. **Booter:** run the **Booter** ucode in **HS mode on SEC2**. It authenticates GSP-RM and
   starts it in **LS mode on the GSP**.
3. **GSP-RM** comes up and talks to the kernel driver through RPC message queues.

```
 BROM(SEC2) ─► Booter (HS, SEC2) ─► GSP-RM (LS, GSP RISC-V)
 BROM(GSP)  ─► FWSEC (HS, GSP): SB + devinit + scrub [pre-driver]; FRTS → WPR2 [driver-triggered]
```

### 3.3 Hopper / Blackwell: FSP chain of trust
- **FSP (Foundation Security Processor)** is the GPU's **Internal Root of Trust (IROT)**. It
  boots from its own immutable Boot ROM when the GPU powers on and finishes its own secure boot
  before any driver runs.
- The driver:
  1. polls a scratch register until FSP reports boot complete
  2. sends one **Chain-of-Trust (COT) message**, an MCTP + NVIDIA-NVDM-framed message
     (vendor 0x10de, NVDM type 0x14) over the falcon message queue, carrying:
     - sysmem address of the **FMC** firmware image
     - its **SHA-384 hash, RSA-3K public key and RSA-3K signature**
     - FRTS region info and the address of the GSP boot arguments
  3. FSP verifies the signature → boots FMC → **FMC authenticates and loads GSP-RM**
- **No SEC2, no Booter, no FWSEC-FRTS.** One message-driven interface replaces the
  multi-stage dance.
- FSP also exposes **PRC (Product Reconfiguration Control)** "knobs": vGPU mode, ECC enable,
  **Confidential-Computing mode**, NVLink config. Each knob has an *active* value (this boot)
  and a *persistent* value (InfoROM).

```
 BROM(FSP) ─► FSP firmware ─(COT msg from driver: hash+key+sig)─► FMC ─► GSP-RM
```

> **Interview framing:** the trend is to *shrink and centralize the root of trust* (one
> dedicated security processor, one verification interface, strong crypto: RSA-3K +
> SHA-384) and *move the driver's brain into signed, authenticated firmware*.

---

## 4. Anti-rollback: fuse-based versions

Problem: an attacker (root on the host, or anyone with an SPI programmer) feeds the GPU an
**older, validly signed** firmware with a known bug.

Mechanism (visible in nova-core `falcon/hal/ga102.rs` and the firmware descriptor format):
- each HS ucode descriptor (`FalconUCodeDescV3`) carries **several signatures**
  (`signature_count`, `signature_versions`)
- the chip has **FPF fuses** per engine and ucode (`FUSE_OPT_FPF_<ENGINE>_UCODE<n>_VERSION`,
  16 bits). The driver computes the version as the **position of the highest set bit**.
  Fuses can only be *burned*, so the counter is **monotonic and irreversible**.
- the driver selects the signature matching the fused version. An image whose version is
  below the fuse can't be validated, so **downgrades fail**.

Release-engineering consequences (good discussion material):
- Bumping the fused version is **irreversible**, so it's reserved for security fixes. Ship
  the new firmware to the field first, then burn fuses.
- Per-release check: *"every HS image's security version ≥ the minimum required for this
  release; signatures exist for all supported fuse versions."*

---

## 5. Memory protection for firmware

- **WPR / WPR2**: VRAM carve-outs accessible only to secure (HS/LS) microcode. Not reachable
  from the CPU (BAR1), user channels, or copy engines.
- **IO-PMP** in each falcon restricts its DMA targets. A misconfigured IO-PMP or MPU means a
  compromised low-privilege firmware can read secrets or attack the host.
- **Privilege-level gating** on registers: only PL3 can program security-critical registers.
- **Confidential Computing:** VRAM holding CVM data is in a protected region the host can't
  read through BARs.

---

## 6. Confidential Computing on H100+ (the high-level story)

- **Threat model:** the host OS, hypervisor and cloud admin are untrusted. The tenant's
  **Confidential VM (CVM)** runs under a CPU TEE (AMD SEV-SNP or Intel TDX). The GPU in
  **CC mode** joins the CVM's trust boundary.
- **Attestation:** the in-CVM driver talks **SPDM** (DMTF Security Protocol and Data Model)
  with the GPU. The GPU returns firmware/config **measurements** signed by a per-device
  identity key whose certificate chains to NVIDIA. The tenant verifies them, locally or with
  NVIDIA's remote attestation service, *before* sending secrets. GPU firmware therefore
  becomes part of the tenant's TCB.
- **Data path:** a CVM's private memory is encrypted, so the GPU can't DMA it directly. Data
  goes through **bounce buffers in shared memory, encrypted (AES-GCM) by the CPU-side driver
  and decrypted inside the GPU by the copy engine** (and the reverse on the way out). The keys
  come from the SPDM session.
- **On-GPU protection:** protected VRAM regions, BAR access firewalls, debug and profiling
  interfaces locked in CC mode.
- **Blackwell** extends this to **TEE-I/O** (PCIe IDE link encryption + TDISP) and protected
  multi-GPU.
- Security engineer questions: Which firmware versions are measured? What happens on
  downgrade? Are perf counters/debug disabled in CC mode? Are error messages and Xid logs
  leaking data to the host?

---

## 7. Jetson/Tegra (SoC) secure boot (in case it comes up)

BootROM verifies **MB1** using a **public-key hash burned in fuses** (optional encryption with
an SBK key) → MB1 → MB2 → UEFI → OS kernel, with a TEE (OP-TEE) alongside. A production fuse
locks the configuration. The concepts are identical: immutable ROM, fused key hash, chain of
signed stages, version fuses, debug lock.

---

## 8. Concepts to keep straight

| Term | Meaning |
|---|---|
| Root of trust | Immutable code + fused keys that verify the first mutable stage (BROM + fuses) |
| Verified/secure boot | Each stage **verifies** the next before running it (stop on failure) |
| Measured boot | Each stage **records** a hash of the next (TPM PCRs / SPDM measurements) for later attestation. It doesn't block. |
| Attestation | Proving measurements to a remote verifier with a device key (SPDM) |
| Anti-rollback | Monotonic version (fuses / RPMB) that rejects older signed images |
| Debug lock | Production fuse disables JTAG/debug or requires authenticated debug |
| Key hierarchy | Prod vs debug signing keys. **A debug-signed image in a prod release is a classic release failure.** |

---

## 9. Firmware security engineering: what to require and check per release

**Design / code (review time):**
- Memory-safe languages where possible: NVIDIA has publicly discussed adopting **SPARK/Ada**
  for security-critical firmware with AdaCore, and **Rust** is the language of the upstream
  Nova driver. Formal proofs for critical parsers.
- Every message from a less-trusted side (CPU RPC, guest VM, other engine) is
  length-checked, **copied once out of shared memory** (no TOCTOU on queues), and validated.
- Least privilege between firmware partitions (FSP exposes a separate *Management Partition*),
  PMP/MPU W^X, separate stacks, minimal HS code size.
- Secrets scrubbed from IMEM/DMEM and registers before mode exit. Constant-time crypto.
  Fault-injection hardening (redundant checks, verified branches) for HS code.
- Debug commands and test hooks compiled out of production builds.

**Automated per-release checks (what this job builds):**
- Signed with the **production** key, and the signature verifies. Debug key = hard fail.
- Security version ≥ policy minimum. Rollback table consistent with fuse versions.
- ELF checks on firmware images: stack protector present (canary symbol/`__stack_chk_fail`),
  no RWX segments, PMP/MPU configuration table matches the approved baseline, stripped of
  debug info in release builds.
- No embedded secrets (private keys, test credentials), no forbidden strings (debug banners).
- SBOM for third-party code in firmware (crypto libs, RTOS) checked against known CVEs.
- Size/layout invariants (e.g. IMEM/DMEM limits) so overflow-by-growth is caught before it ships.
