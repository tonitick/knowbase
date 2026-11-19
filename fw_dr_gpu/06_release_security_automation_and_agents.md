# 06 — Release Security Automation, Policy-as-Code and AI Agents

The job in one sentence: **turn the security bar (hardening flags, isolation mechanisms,
security invariants) into automated per-release checks from firmware to user mode, run the
scanning pipeline, and use AI agents to remove the manual work around it.**

```
 requirement (prose) ──► check (code) ──► run per build/release ──► finding ──► triage/prioritize
        ▲                                                                       │
        └──── waivers (owner, reason, expiry) ◄──── fix / accept-risk ◄─────────┘
                                         evidence ──► release sign-off
```

---

## 1. From requirement to check: where to look

| Requirement type | Example | Best evidence | Tooling |
|---|---|---|---|
| Hardening flags | "All user-mode ELF executables are PIE with full RELRO and CET" | **The shipped binary** (ELF/PE/firmware) | readelf/pyelftools, checksec, `annocheck` (annobin), BinSkim (PE), custom (Lab 3) |
| Build configuration | "Built with `-D_FORTIFY_SOURCE=3`" | Build logs / `compile_commands.json`, `-frecord-gcc-switches`, annobin notes | Log parsers, annocheck |
| Code invariants | "No ioctl handler dereferences user pointers directly" | Source | sparse (`__user`), CodeQL, Semgrep, Coccinelle, clang-tidy, Coverity |
| Interface invariants | "No new `NON_PRIVILEGED` RM controls without review" | Generated tables (`g_*_nvoc.c`), headers | Custom extractor + diff vs last release |
| Isolation config | "Device nodes 0666 only for X; profiling admin-only; ECC default on for SKU Y" | Installer, udev rules, registry/module defaults | Config checks / OPA |
| Firmware | "Prod-signed, version ≥ min, PMP table == baseline, no debug cmds" | Firmware images + manifests | Custom verifiers |
| Dependencies | "No known-exploitable CVEs in third-party code" | SBOM (SPDX/CycloneDX) | Syft/Grype, OSV, VEX statements |
| Secrets | "No private keys/tokens in artifacts" | Artifacts + repos | gitleaks/trufflehog-style scanners |

**Prefer checking the artifact you ship over trusting the build system.** Prebuilt
third-party libraries, assembly files and odd build paths all slip past flag-based checks.

---

## 2. Hardening baseline for Linux user-mode ELF (and how to verify it in the binary)

| Requirement | Compiler/linker flags | Evidence in the ELF | Gotchas |
|---|---|---|---|
| Stack canaries | `-fstack-protector-strong` | imports `__stack_chk_fail` | No import may just mean no eligible frames (report "not found", not "fail", for tiny binaries) |
| FORTIFY | `-D_FORTIFY_SOURCE=3` (GCC 12+/recent Clang; else `=2`), needs `-O1+` | imports `__*_chk` (`__memcpy_chk`, `__printf_chk`) | Measure the fortified/fortifiable ratio. Silently a no-op at `-O0`. |
| PIE (ASLR) | `-fPIE -pie` | `ET_DYN` + `DF_1_PIE` | Old linkers don't set `DF_1_PIE`; use `PT_INTERP` + no `DT_SONAME` |
| Full RELRO | `-Wl,-z,relro,-z,now` | `PT_GNU_RELRO` + `DF_BIND_NOW`/`DF_1_NOW` | Partial RELRO leaves the GOT writable |
| NX stack | `-Wl,-z,noexecstack` | `PT_GNU_STACK` without `PF_X` | **One `.S` file without `.note.GNU-stack` makes the whole binary execstack** |
| No RWX segments | default | no `PT_LOAD` with W+X | Custom linker scripts |
| CET (x86) | `-fcf-protection=full` | `.note.gnu.property` X86_FEATURE_1_AND: IBT=0x1, SHSTK=0x2 | **The linker ANDs the property over all inputs**: one unmarked asm or prebuilt object drops it for the whole binary |
| BTI/PAC (arm64) | `-mbranch-protection=standard` | AARCH64_FEATURE_1_AND: BTI=0x1, PAC=0x2 | Same AND semantics |
| Stack clash | `-fstack-clash-protection` | annobin notes only | Not inferable from plain ELF |
| Auto-init | `-ftrivial-auto-var-init=zero` | annobin / build logs | GCC 12+, Clang 16+ |
| Safer semantics | `-fno-strict-overflow -fno-delete-null-pointer-checks -fstrict-flex-arrays=3` | build logs | |
| Format strings | `-Wformat -Wformat-security -Werror=format-security` | build logs | |
| C++ | `-D_GLIBCXX_ASSERTIONS` | assertion-failure symbol imports | |
| Library hygiene | no `-rpath` to relative/world-writable dirs; `-fPIC` | no `DT_RPATH`/insecure `DT_RUNPATH`; no `DT_TEXTREL` | `$ORIGIN` is OK when intentional |
| Release hygiene | strip; ship debuginfo separately | no `.debug_*`/`.symtab` in shipped files | Keep symbols internally for crash triage |

Reference: **OpenSSF "Compiler Options Hardening Guide for C and C++"**. Read it; it's the
closest thing to an industry baseline.

**Kernel modules (`.ko`):** appended signature present (`~Module signature appended~\n`),
`vermagic` matches the target kernel, `retpoline=Y` in `.modinfo` on x86, `__stack_chk_fail`
referenced, no section both writable and executable, built by Kbuild so the kernel's
hardening CFLAGS apply.

**Windows PE (KMD/UMD):** `/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /GUARD:CF /CETCOMPAT /GS`,
Spectre mitigations, Authenticode signature, HVCI compatibility (no RWX sections), checked by
**BinSkim** or winchecksec.

**Firmware:** see 04 §9.

---

## 3. The release security scanning pipeline

```
 build ─► artifacts (ELF / PE / .ko / firmware) + build logs + compile_commands.json + SBOM
   │
   ├─► binary hardening checks (policy-as-code)        ─┐
   ├─► SAST: Coverity / CodeQL / Semgrep / sparse/smatch ─┤
   ├─► SCA: SBOM → CVE match → VEX                       ─┼─► normalize to SARIF
   ├─► secrets, signature & version verification         ─┤   ► fingerprint + dedupe
   └─► fuzzing / sanitizer results (syzkaller, libFuzzer) ─┘   ► diff vs. baseline (last release)
                                                              ► policy gate: block / warn / info
                                                              ► route to owners (CODEOWNERS → Jira)
                                                              ► dashboard + release evidence
```

**Design principles to say out loud:**
1. **Two speeds.** A fast, diff-aware PR check (seconds to minutes, only on changed
   components) plus a full per-release scan with complete evidence.
2. **Deterministic and reproducible.** Same input → same findings. Pin tool versions; the
   checker's own version is part of the evidence.
3. **One interchange format: SARIF 2.1.0.** Every tool → SARIF → one triage system. Stable
   **fingerprints** (rule + artifact + location-independent key) track a finding across
   releases.
4. **Baseline and ratchet.** Don't block a release on years of legacy debt. Block
   **regressions** (new findings vs. the last release) and burn the debt down with targets.
5. **Waivers as code.** Each waiver has scope (artifact glob + rule), justification, owner,
   approver, **expiry date** and a ticket. It's reviewed via PR, and an expired waiver fails
   the gate.
6. **Severity in context.** CVSS alone isn't enough. Ask whether the code is reachable from
   untrusted input (an ioctl from a 0666 node is worse than a root-only tool), what the product
   exposure is, and whether a mitigation exists.
7. **Ownership and SLAs.** Auto-route to owning teams; SLA by severity; escalation path.
8. **Measure.** % components compliant per requirement, new vs. fixed findings per release,
   MTTR, false-positive rate (by rule), waiver count/age, scan duration.

### Policy-as-code examples
Policy file (what Lab 3 implements, simplified):
```json
{
  "profiles": {
    "executable":    {"pie": "error", "nx": "error", "relro_full": "error",
                      "canary": "warn", "fortify": "warn", "cet_ibt": "warn", "cet_shstk": "warn"},
    "shared_lib":    {"nx": "error", "relro_full": "warn", "no_textrel": "error"},
    "kernel_module": {"signed": "error", "no_wx_sections": "error", "retpoline": "warn"}
  },
  "waivers": [
    {"path": "*/legacy/libfoo.so*", "check": "relro_full", "owner": "team-media",
     "reason": "vendor prebuilt, replacement tracked", "ticket": "SEC-1234", "expires": "2027-03-31"}
  ]
}
```
Same rule in OPA/Rego over the checker's JSON (if the org standardizes on OPA/Conftest):
```rego
package release.hardening
import rego.v1

deny contains msg if {
	some b in input.binaries
	b.kind == "executable"
	not b.checks.pie.ok
	not waived(b.path, "pie")
	msg := sprintf("%s: executable is not PIE", [b.path])
}
```

### Static-analysis rule sketches you can talk through
Semgrep (sketch; real rules need `pattern-either` for `if (get_user(...))` forms):
```yaml
rules:
  - id: kernel-double-fetch
    languages: [c]
    severity: WARNING
    message: $PTR->$F is fetched by get_user() and again by copy_from_user(); use one copy
    patterns:
      - pattern: |
          get_user($X, &$PTR->$F);
          ...
          copy_from_user($DST, $PTR, ...);
```
Coccinelle (this one really is used in the kernel tree):
```
@@
expression N, S, F;
@@
- kmalloc(N * S, F)
+ kmalloc_array(N, S, F)
```
CodeQL is the tool for *variant analysis*: model `copy_from_user`/RM param copy-in as taint
sources and `memcpy` lengths / array indices as sinks, then query "tainted size reaches a sink
without passing a bounds check."

### Fuzzing in the pipeline
- **syzkaller**: describe the driver's ioctls in syzlang. Coverage via KCOV; run on
  KASAN/KCSAN kernels.
  ```
  resource fd_toy[fd]
  openat$toygpu(fd const[AT_FDCWD], file ptr[in, string["/dev/toygpu"]], flags const[O_RDWR], mode const[0]) fd_toy
  ioctl$TOYGPU_BO_CREATE(fd fd_toy, cmd const[TOYGPU_IOCTL_BO_CREATE], arg ptr[inout, toygpu_bo_create])
  ```
- **libFuzzer/AFL++** for parsers: firmware message handlers compiled for the host with
  hardware stubs, VBIOS/firmware-header parsers, shader/PTX front ends.
- Gate on **new crashes in changed code**. Track coverage of security-critical handlers.

---

## 4. AI agents for security work: patterns that actually work

**Core principle:** *deterministic tools detect; agents triage, explain, generate and fix;
humans approve.* Use LLMs where outputs are **verifiable** (a patch that rebuilds and passes
the checker, a query that compiles and finds the known bug, a harness that reaches new
coverage) or where false negatives are cheap. Never make an LLM the sole gate.

### 4.1 Workflows to propose (each with a built-in verifier)

| Workflow | Inputs | Agent does | Verification |
|---|---|---|---|
| **Finding triage** | SARIF finding + code + build graph | Reads context, judges TP/FP, reachability from untrusted input, proposes severity, owner, fix | Must cite file:line evidence. Calibrated on historically labeled findings. Human confirms high-severity results. |
| **Hardening-regression fixer** | Checker failure (e.g. lost CET) | Maps binary → build target via logs, finds the culprit (e.g. an `.S` file missing the GNU property note), drafts a build-system patch | CI rebuild + checker re-run proves the fix. PR to owners. |
| **Requirement → check generator** | Prose requirement from the security baseline | Drafts the policy rule/query + tests (positive/negative samples) | Tests must pass. Security review of the rule. |
| **Variant analysis** | A fixed CVE's patch | Writes a CodeQL/Semgrep query for the pattern, runs it across repos, triages hits | The query must flag the pre-fix code and not the post-fix code |
| **Fuzz harness generation** | ioctl/control/firmware message handler | Writes syzlang descriptions or libFuzzer harnesses (cf. Google's OSS-Fuzz-gen) | Compiles, runs, increases coverage |
| **Interface-diff reviewer** | Release N vs N-1 control tables, UAPI headers | Explains what became user-reachable or changed shape, drafts review questions | Deterministic diff underneath; the agent only explains |
| **Threat-model drafting** | Design doc | Lists trust boundaries, data flows, STRIDE threats, questions | Human-led review. The agent is the scribe. |
| **Release evidence summarizer** | All scan results, waivers | Release-readiness report: blockers, expiring waivers, risk deltas | Numbers come from the pipeline DB, not the LLM |

NVIDIA's public example of this pattern: the **"Vulnerability Analysis for Container
Security" AI Blueprint** (Morpheus/NIM, newer versions on NeMo Agent Toolkit). Agents take
scanner CVEs + a container image, research, check exploitability in context, and output a
**VEX** classification. Read it before the interview.

### 4.2 Architecture sketch
```
 trigger (CI event / new findings) ─► orchestrator (plan → act → verify loop)
     tools (MCP servers or function calls):
       code_search, read_file, git_blame, build_graph_lookup, run_checker,
       run_codeql_query, compile_and_test (sandboxed), ticketing (draft-only)
     structured output: JSON schema {verdict, confidence, evidence[], severity, owner, patch?}
 ─► verifier (deterministic re-check / second model / tests) ─► human review queue ─► action
```
- Context engineering: give the agent the *security baseline* and *component ownership*,
  plus retrieval over past triage decisions (consistency).
- Budgets: max tool calls, tokens and wall time per finding. Cache shared context.
- Prefer small, composable agents with narrow tools over one mega-agent.

### 4.3 Evaluating agents (interviewers will push here)
- **Golden sets:** historical findings with expert verdicts. Reverted CVE fixes ("does it find
  the bug when the fix is removed?"). Synthetic bugs injected into real handlers (Lab 2
  style).
- **Metrics:** precision/recall vs. experts, agreement on severity, fix acceptance rate,
  time saved per finding, cost per finding, **regression tests in CI** for prompts, tools and
  model upgrades.
- **Rollout:** shadow mode (agent runs, humans decide, compare) → assistive (suggestions in
  the ticket) → partial automation (auto-close only high-confidence FPs on low-risk rules,
  with audit sampling).

### 4.4 Securing the agents themselves
- **Prompt injection:** code comments, commit messages, issue text and third-party code
  are *untrusted data*. Don't let them steer tool use. Keep instructions separate from
  retrieved content.
- **Least privilege:** read-only repo tokens, no network egress from sandboxes, drafts
  instead of merges/pushes, secrets never in context.
- **Sandbox execution** of anything the agent builds or runs (containers/VMs, gVisor).
- **Audit logs** of every tool call. Deterministic re-checks of every claim that gates a release.
- **Data governance:** proprietary driver/firmware source only goes to approved models and
  endpoints (on-prem / NIM).
- Red-team the agents (NVIDIA maintains **garak**, an LLM vulnerability scanner). Guardrails
  (e.g. NeMo Guardrails) for policy.

---

## 5. Driving adoption without authority (a "what we need to see" item; prepare a STAR story)

1. **Start with pain, not policy.** Pick the most manual, hated workflow (e.g. per-release
   hardening triage done in spreadsheets). Measure the baseline (hours/release).
2. **One friendly pilot team.** Ship an MVP in weeks, make them successful, quote them.
3. **Low noise first.** Launch only high-confidence rules. Every false positive costs trust.
   Fix FP reports within days.
4. **Meet engineers where they are.** PR comments, existing CI, existing ticket queues, a
   one-line include. No new portal to log into.
5. **Make the secure path the default path.** Shared toolchain files / CMake presets that
   carry the hardening flags. Teams inherit compliance by doing nothing.
6. **Warn → enforce on new code → enforce everywhere**, with dates announced early and
   waivers available.
7. **Visibility:** per-team scorecards, release-over-release trends, celebrate teams that hit 100%.
8. **Champions and office hours.** A security champion per team, docs with copy-paste fixes.
9. **Executive sponsor** for the "enforce" step, backed by data, not opinion.

---

## 6. Worked answer: "How would you roll out CET (`-fcf-protection`) across all user-mode components?"

1. **Inventory:** run the binary checker over the last release → which binaries lack
   IBT/SHSTK, and why (missing flag vs. unmarked asm vs. prebuilt third-party).
2. **Default it:** add the flag to the shared toolchain configuration. Most components flip
   for free.
3. **Fix the long tail:** hand-written assembly needs `endbr64` and the
   `.note.gnu.property` section; prebuilt vendor libraries get waivers with owners and expiry
   dates. An agent can draft the asm/build fixes, and CI + the checker verify them.
4. **Test runtime compatibility:** JITs and code generators (PTX/shader JIT!) must emit
   `endbr64` at indirect-branch targets and handle shadow stacks; test with SHSTK enforcement
   enabled (glibc tunables / kernel support).
5. **Gate:** warn for one release, then block regressions; track the burn-down to 100%.
6. **Evidence:** per-release report of CET coverage, kept for audits/customers.
