# Lab 2 — Toy GPU Driver: Find the 8 Bugs

`toygpu` is a ~380-line misc character driver shaped like a (very) simplified GPU driver:
per-open **clients**, **buffer objects** (BOs) with handles, **mmap** of BOs, and a
**SUBMIT** ioctl that points at a **command buffer in user memory** which the "GPU" executes
(WRITE32 into a BO). The device node is mode 0666, like `/dev/nvidia*`.

- `make` → **fixed** build (what you'd ship)
- `make VULN=1` → **vulnerable** build with 8 classic bugs, each marked `BUG(n)` in `toygpu.c`

> **Never load this on the shared server.** Use a throwaway VM (instructions below).
> Building is harmless and works here.

## Files
```
toygpu_uapi.h   ioctl ABI shared with user space
toygpu.c        the driver (#ifdef TOYGPU_VULNERABLE selects the buggy branches)
toygpu_test.c   test program: functional, --negative, --race modes
Makefile        Kbuild + test build (+ `make check` runs sparse if installed)
```

## Exercise 1: review (do this first, on paper, 45 minutes)
Read `toygpu.c` and **only** the vulnerable branches plus the shared code. For each `BUG(n)`
marker, write down: the bug class, how an unprivileged user triggers it, the impact, and the
fix. Use the checklist in `05_security_of_drivers_and_firmware.md` §6. Then open the
answer key.

<details>
<summary><b>Answer key (click to open after you've tried)</b></summary>

| Bug | Where | Class | Trigger → impact | Fix (see the non-VULN branch) | What catches it |
|---|---|---|---|---|---|
| 1 | `toygpu_get_info` | Uninitialized padding copied to user (CWE-908/200) | Call GET_INFO → 7 padding bytes of kernel stack per call (can leak pointers, defeating KASLR) | `memset` the struct. Better: no implicit padding in UAPI structs | KMSAN; mitigated by `CONFIG_INIT_STACK_ALL_ZERO` (**not** enabled on this server's Ubuntu 5.15 kernel); `pahole` in UAPI review |
| 2 | `toygpu_bo_get` | Unchecked user-controlled index (CWE-129) | SUBMIT/mmap with handle ≥ 64 → reads a pointer past `bos[]` → `kref_get` + use on an attacker-influenced address | Range check + `array_index_nospec()` | KASAN, syzkaller, CodeQL taint query |
| 3 | `toygpu_submit` | Integer truncation in size math (CWE-190/681) | `num_cmds = 0x10000000` → `16 * n` wraps to 0 in `u32` → 8-byte allocation, loop over 268M commands → heap OOB read, garbage commands executed | Bound `n`, then `struct_size()` + `memdup_user()` | KASAN, Coccinelle/CodeQL (size math stored in a narrow type) |
| 4 | `toygpu_submit` loop | **Double fetch** (CWE-367) | Thread A submits with `num_cmds = 1`, thread B flips it to 4096 between fetch #1 (sizing) and fetch #2 (copy) → loop bound from the 2nd fetch → heap OOB | Use only the validated `n` | KASAN under a race (`--race`), syzkaller, static double-fetch detectors, review |
| 5 | `toygpu_exec` | Off-by-N bounds check, no alignment check (CWE-193/787) | WRITE32 at `offset = size - 1` writes 3 bytes past the BO | `offset <= size - 4 && IS_ALIGNED(offset, 4)` | Boundary-value tests, KASAN (only if the next page is poisoned) |
| 6 | `toygpu_bo_destroy` | Use-after-free: frees without refcounting, leaves a dangling table pointer (CWE-416) | Destroy, then SUBMIT/mmap the same handle → UAF. Destroy while mapped → **user keeps R/W access to freed pages that the kernel reuses** (the in-the-wild Mali/Adreno pattern). close() → double free | Remove from the table under the lock, drop the table's ref. The VMA holds its own ref (`vm_ops` open/close) | KASAN (use-after-free/double-free), syzkaller |
| 7 | `toygpu_mmap` | mmap length not validated (CWE-787/119) | `mmap(2 pages)` on a 1-page BO → user maps the **physically adjacent page** (someone else's kernel memory) read/write | `len <= bo->size`, validate `vm_pgoff` | **No sanitizer catches this** (the kernel never touches the memory). Only invariant tests/review. A good interview point. |
| 8 | `toygpu_bo_create` | Resource not scrubbed before reuse (CWE-226) | New BO contains the previous owner's data → cross-process leak (the GPU "VRAM scrubbing" problem) | `__GFP_ZERO` | `init_on_alloc=1` mitigates; tests that read fresh BOs |

Things the fixed version still lacks (production discussion): per-client limits plus memcg
accounting (`GFP_KERNEL_ACCOUNT`) against memory DoS, an xarray handle table, fault-based
mappings (`vmf_insert_pfn`) so BOs can be evicted/migrated, capability checks for any
privileged ioctl, lockdep-annotated lock ordering once there are more locks, and a syzkaller
description for continuous fuzzing.
</details>

## Exercise 2: build both variants (safe here)
```bash
cd labs/lab2_toy_gpu_driver
make                         # fixed module + test program
make clean && make VULN=1    # vulnerable module
make clean && make           # back to fixed
python3 ../lab3_hardening_checker/hardening_check.py toygpu.ko   # unsigned module → gate fails
```

## Exercise 3: run it in a VM
Any disposable Linux VM with matching kernel headers works, e.g. Ubuntu 22.04 under
QEMU/virt-manager/multipass:
```bash
sudo apt install build-essential linux-headers-$(uname -r)
make && sudo insmod toygpu.ko && ls -l /dev/toygpu
./toygpu_test                # fixed build: ALL PASSED
./toygpu_test --negative     # fixed build: ALL PASSED
./toygpu_test --race         # fixed build: only ok / EINVAL results
sudo rmmod toygpu

make clean && make VULN=1 && sudo insmod toygpu.ko
./toygpu_test                # shows the BUG 1 / BUG 8 / BUG 6 FAILs (leaks, stale mapping)
./toygpu_test --negative     # corrupts kernel memory: expect oopses/KASAN reports in dmesg
```
For clean diagnostics, boot a kernel built with `CONFIG_KASAN=y` (and `CONFIG_KASAN_INLINE`,
`CONFIG_DEBUG_KMEMLEAK`, `CONFIG_PROVE_LOCKING`). `virtme-ng` makes booting a custom kernel in
QEMU quick. Then read the KASAN report: it names the bug class, the access, and the
allocation/free stacks, which is exactly what you triage in a real fuzzing pipeline.

## Exercise 4: automate the detection (ties into 06)
1. Write a **syzlang** description for the four ioctls (start from the snippet in 06 §3) and
   let syzkaller find bugs 2–6 on a KASAN kernel.
2. Write a **Semgrep** rule for the BUG(4) pattern (`get_user(x, &p->f)` … `copy_from_user(…, p, …)`)
   and a **Coccinelle** rule for BUG(3) (size arithmetic assigned to a `u32` before `kmalloc`).
3. Ask an LLM agent to review `toygpu.c` (VULN branches) against the §6 checklist, and score
   it against the answer key: precision, recall, and whether it cites lines. That's a mini
   version of the agent evaluation story in 06 §4.3.
