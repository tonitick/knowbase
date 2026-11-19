# GPU Driver and Firmware Security: Interview Prep

Target role: **NVIDIA GPU Software, Security Engineer**: automate the security bar per
release (hardening flags, isolation mechanisms, security invariants) from firmware to
user-mode, own the release scanning pipeline, and lead AI-agent adoption in security.

## Map

| # | File | What you get | Time |
|---|---|---|---|
| 1 | [01_gpu_hardware_model.md](01_gpu_hardware_model.md) | How a GPU looks to software: PCIe, BARs, MMIO, DMA, IOMMU, interrupts, GPU page tables, channels/doorbells, engines, microcontrollers | 2 h |
| 2 | [02_linux_driver_essentials.md](02_linux_driver_essentials.md) | Kernel driver building blocks with code: probe/remove, MMIO, DMA API, IRQs, ioctl/mmap, DRM, lifetime, firmware loading, toolchain; Windows mapping | 3 h |
| 3 | [03_nvidia_gpu_software_stack.md](03_nvidia_gpu_software_stack.md) | NVIDIA's stack: UMD/KMD, RM object model + escape/control API + privilege flags, GSP-RM, UVM, WDDM; **CUDA launch trace** | 2 h |
| 4 | [04_gpu_firmware_and_secure_boot.md](04_gpu_firmware_and_secure_boot.md) | Falcon/RISC-V, NS/LS/HS, Ampere FWSEC/Booter flow, Hopper FSP chain of trust, fuse anti-rollback, WPR, Confidential Computing | 2 h |
| 5 | [05_security_of_drivers_and_firmware.md](05_security_of_drivers_and_firmware.md) | Trust boundaries, bug classes with code, mitigations, isolation (MIG/vGPU/containers/sandboxing/CC), real CVEs, review checklists | 3 h |
| 6 | [06_release_security_automation_and_agents.md](06_release_security_automation_and_agents.md) | Hardening baseline + binary evidence, pipeline design, policy-as-code, SAST/fuzzing, **agent patterns, evaluation, safety**, adoption playbook | 2 h |
| 7 | [07_interview_question_bank.md](07_interview_question_bank.md) | ~50 questions with hidden answer sketches, 3 code-review exercises, STAR prompts, questions to ask | ongoing |
| L1 | [labs/lab1_explore_pci_device/](labs/lab1_explore_pci_device/) | Read-only tour of this server's real PCI display device (ASPEED, `ast` DRM driver) | 45 min |
| L2 | [labs/lab2_toy_gpu_driver/](labs/lab2_toy_gpu_driver/) | Toy GPU-like kernel driver: fixed vs `VULN=1` build with 8 classic bugs; spot-the-bug + answer key | 2 h |
| L3 | [labs/lab3_hardening_checker/](labs/lab3_hardening_checker/) | Working policy-as-code ELF/kernel-module hardening checker: waivers, baselines, SARIF, tests | 2 h |

## Suggested order
- **2-day crunch:** 01 → 03 → 05 → 06, run Lab 3, then drill 07.
- **1 week:** everything in order. Do Lab 2's review exercise on paper before reading its answer key. Ten questions from 07 out loud every evening.

## Five things to be able to whiteboard
1. A CUDA kernel launch from `cuLaunchKernel` to the SMs, and the trust boundary at each step (03 §8).
2. Why user mode submits GPU work without syscalls, and what isolates processes (01 §6).
3. GPU secure boot: BROM → HS → LS (Ampere), FSP → FMC → GSP-RM (Hopper+), and fuse anti-rollback (04).
4. Five driver bug classes with code, plus the check or tool that catches each (05 §2, Lab 2).
5. A per-release scanning pipeline that uses deterministic checks for detection and agents for triage and fixes, and how you'd drive adoption (06).

## Primary sources worth reading
- NVIDIA open GPU kernel modules: github.com/NVIDIA/open-gpu-kernel-modules (`kernel-open/nvidia/nv.c`, `src/nvidia/arch/nvalloc/unix/src/escape.c`, `src/nvidia/src/kernel/rmapi/control.c`)
- Linux nova-core firmware docs: docs.kernel.org/gpu/nova/ (`falcon`, `fwsec`, `fsp`, `vbios`)
- NVIDIA Product Security bulletins: nvidia.com/en-us/security (read ~10 recent ones)
- OpenSSF *Compiler Options Hardening Guide for C and C++*
- Linux docs: `Documentation/core-api/dma-api-howto.rst`, `Documentation/gpu/drm-uapi.rst`, `Documentation/driver-api/pci/`
- NVIDIA AI Blueprint *Vulnerability Analysis for Container Security* (agentic CVE triage)
- Wiz write-ups on CVE-2024-0132 and CVE-2025-23266; Trail of Bits *LeftoverLocals*; gVisor `nvproxy` docs; NVIDIA/open-gpu-doc

## Caveats
NVIDIA internals here come from public sources: open-source code, kernel docs, and bulletins.
Things that change often (version numbers, flag names, boot-flow details for the newest
GPUs) are worth re-checking against the source before quoting them in an interview.
