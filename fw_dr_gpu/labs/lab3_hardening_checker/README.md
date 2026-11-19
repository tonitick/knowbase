# Lab 3 — Policy-as-Code Binary Hardening Checker

A working, small version of "translate hardening requirements into automated per-release
checks" from the job description. Read the code (~750 lines, no magic), run it, then be
ready to discuss how you'd scale it.

```
hardening_check.py        the checker (pyelftools; parallel; text / JSON / SARIF 2.1.0)
policy.json               the baseline: per-kind check severities + time-boxed waivers
test_hardening_check.py   fixture tests (good + bad artifact per check)
samples/                  demo sources + Makefile producing good and bad binaries
```

## Run it

```bash
cd labs/lab3_hardening_checker
make -C samples                                   # builds samples/build/*
python3 hardening_check.py samples/build          # text report, exit 1 = gate failed
python3 hardening_check.py --list-checks          # check catalog
python3 -m unittest -v test_hardening_check.py    # 12 tests

# Release-pipeline style: JSON evidence for release N-1, then gate release N on regressions only
python3 hardening_check.py -f json  -o rel_N-1.json samples/build
python3 hardening_check.py --baseline rel_N-1.json samples/build      # PASSED: nothing new
python3 hardening_check.py -f sarif -o hardening.sarif samples/build  # for code-scanning UIs

# Real-world data
python3 hardening_check.py /usr/bin                                   # ~2,200 binaries, ~8 s with -j 8
python3 hardening_check.py /lib/modules/$(uname -r)/kernel/drivers/gpu
python3 hardening_check.py ../lab2_toy_gpu_driver/toygpu.ko            # unsigned → module_signed fails
```

## What the samples demonstrate

| Artifact | Built with | Checker says | Lesson |
|---|---|---|---|
| `demo_hardened` | full hardening flags | PASS | baseline works |
| `demo_weak` | everything disabled | FAIL: nx, pie, relro, runpath (+ warns: canary, fortify, CET) and an **expired waiver** | expired waivers block the gate |
| `demo_asm` | **hardened flags** + one hand-written `.S` file | FAIL: executable stack, **CET IBT/SHSTK dropped** | the linker ANDs GNU properties across *all* inputs, so one unmarked asm/prebuilt object silently un-hardens the binary |
| `legacy_asm.o` | the culprit object | WARN: no `.note.GNU-stack`, no CET property | check objects *before* link to point at the root cause |
| `libdemo.so` | lazy binding, `RPATH=$ORIGIN/../lib:plugins` | partial RELRO (**waived** until 2027-06-30), relative RPATH entry = error | waivers carry owner, ticket and expiry |

## Things I verified while building it (good interview anecdotes)

1. **Empty RUNPATH semantics** (glibc 2.35, tested here): a *wholly empty* `DT_RUNPATH`
   (`""`) is ignored, but an empty *element* inside a non-empty list (`/opt/x:` or
   `/a::/b`) means **the current working directory**, a library-hijack vector. The first
   version of this checker flagged `guestfish` etc. (empty RUNPATH) as insecure. A quick
   experiment showed that was a **false positive**, so the rule was refined and a regression
   test added. *That's the workflow: every rule needs ground truth, and FP reports drive
   rule fixes.*
2. Real `/usr/bin` numbers on this Ubuntu 22.04 server: PIE 92.6%, CET 93.2%, canary 86.8%,
   FORTIFY 94.1%. Most non-PIE binaries are the `arm-linux-gnueabi*` cross-toolchain
   packages. These are exactly the per-release **coverage metrics** to put on a dashboard.
3. All 45 in-tree GPU/DRM kernel modules are signed, `retpoline=Y`, and have no W+X
   sections. Two report "no canary", which is a known false-positive class: a module with no
   protected frames never references `__stack_chk_fail`. That's why the canary check is
   `warn`, not `error`.

## Design choices to talk about

- **Check the shipped artifact**, not the build logs: catches prebuilts, asm, odd build paths.
- **Fail closed on policy errors**: an unknown check name or level, a malformed waiver, or a
  bad date exits 2. A typo must never silently disable a rule.
- **Severity per artifact kind** (executable / shared_lib / kernel_module / object) is
  policy, not code.
- **Waivers are code**: path glob + check + owner + reason + ticket + expiry, reviewed by PR.
  An expired waiver is itself a blocking finding.
- **Baseline / ratchet**: fingerprints (check + relative path) let release N gate only on
  findings that are *new* relative to N-1. Legacy debt doesn't block shipping, regressions do.
- **SARIF 2.1.0 output** with `partialFingerprints`, `baselineState`, and `suppressions` for
  waivers, so results flow into the same triage UI as SAST findings.
- **Coverage metrics** per check: the number leadership actually wants per release.
- **Parallel parsing**, and one malformed file is reported as `UNPARSEABLE` instead of
  crashing the scan.

## Limits (be upfront about these in an interview)

- Canary/FORTIFY are heuristics (imports present ≠ every function protected). For
  certainty, record flags in the binary at build time (`-frecord-gcc-switches`, or **annobin**
  notes checked by `annocheck`).
- Stack-clash protection, `-ftrivial-auto-var-init`, `-fstrict-flex-arrays` aren't visible in
  a plain ELF. They need annobin or build-log analysis.
- No PE (Windows) support: use BinSkim for that. Firmware images need format-specific checks
  (signature/key ID, security version vs. fuse policy, PMP tables).
- Fingerprints keyed on path change if files move. A production version would key on
  package + component name.

## Wiring into CI (GitHub Actions example)

```yaml
- name: Binary hardening gate
  run: python3 tools/hardening_check.py -p security/policy.json --baseline last_release.json -f sarif -o hardening.sarif dist/
- name: Upload results
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: hardening.sarif
```

## Extensions to try (each is a good "how would you…" answer)
1. Add an annobin/`annocheck` backend for flags invisible in plain ELF.
2. Add a Windows PE backend (DllCharacteristics: DYNAMIC_BASE, NX_COMPAT, GUARD_CF,
   HIGH_ENTROPY_VA; CET-compat flag in the debug directory).
3. A "root cause" pass: when a binary lacks CET, list which input objects lacked the property
   (needs a linker map file or build graph). That's an ideal job for an **agent with tools**:
   read the map file, find the `.S` file, draft the patch, re-run the checker to verify.
4. An OPA/Rego version of the policy evaluated over the JSON report.
