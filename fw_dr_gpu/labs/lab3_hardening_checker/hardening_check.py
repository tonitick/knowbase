#!/usr/bin/env python3
"""
hardening_check.py - a policy-as-code ELF hardening checker (interview-prep lab).

Scans ELF executables, shared libraries, relocatable objects and Linux kernel
modules (.ko, .ko.xz, .ko.gz), evaluates them against a JSON policy (per-kind
check severities + time-boxed waivers + optional baseline from a previous
release) and reports as text, JSON or SARIF 2.1.0.

Exit status: 0 = gate passed, 1 = gate failed, 2 = usage / policy / I/O error.

Requires pyelftools (pip install pyelftools).
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import gzip
import hashlib
import io
import json
import lzma
import os
import sys

try:
    from elftools.common.exceptions import ELFError
    from elftools.elf.dynamic import DynamicSection, DynamicSegment
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import NoteSection, SymbolTableSection
except ImportError:  # pragma: no cover
    sys.exit("error: pyelftools is required (pip install pyelftools)")

TOOL_NAME = "hardening-check-lab"
TOOL_VERSION = "0.1.0"

# ELF constants (elf.h)
PF_X, PF_W = 0x1, 0x2
SHF_WRITE, SHF_EXECINSTR = 0x1, 0x4
DF_TEXTREL, DF_BIND_NOW = 0x4, 0x8
DF_1_NOW, DF_1_PIE = 0x1, 0x08000000
X86_IBT, X86_SHSTK = 0x1, 0x2
AARCH64_BTI, AARCH64_PAC = 0x1, 0x2
MODULE_SIG_MAGIC = b"~Module signature appended~\n"
ELF_MAGIC = b"\x7fELF"

KINDS = ("executable", "shared_lib", "kernel_module", "object")
LEVELS = ("error", "warn", "info", "off")
SARIF_LEVEL = {"error": "error", "warn": "warning", "info": "note"}

# libc functions that _FORTIFY_SOURCE can redirect to __<name>_chk variants
FORTIFIABLE = {
    "memcpy", "memmove", "mempcpy", "memset", "strcpy", "stpcpy", "strncpy",
    "stpncpy", "strcat", "strncat", "sprintf", "snprintf", "vsprintf",
    "vsnprintf", "printf", "fprintf", "vprintf", "vfprintf", "dprintf",
    "read", "pread", "pread64", "recv", "recvfrom", "fgets", "getcwd",
    "realpath", "readlink", "gets", "wcscpy", "wmemcpy", "syslog", "vsyslog",
    "confstr", "getgroups", "ttyname_r", "ptsname_r", "wctomb", "mbstowcs",
    "wcstombs", "poll", "ppoll", "fread", "fread_unlocked",
}
WORLD_WRITABLE_DIRS = ("/tmp", "/var/tmp", "/dev/shm")

# check id -> (title, remediation)
CHECKS = {
    "nx_stack": ("Non-executable stack",
                 "Link with -Wl,-z,noexecstack and give every assembly file a .note.GNU-stack section."),
    "no_rwx_segments": ("No loadable segment is both writable and executable",
                        "Fix linker scripts / section flags so code and data live in separate segments."),
    "pie": ("Executable is position independent (full ASLR)",
            "Compile with -fPIE and link with -pie."),
    "relro_full": ("Full RELRO (PT_GNU_RELRO + BIND_NOW)",
                   "Link with -Wl,-z,relro -Wl,-z,now."),
    "canary": ("Stack protector in use (__stack_chk_fail referenced)",
               "Compile with -fstack-protector-strong."),
    "fortify": ("_FORTIFY_SOURCE in use (__*_chk functions imported)",
                "Compile with -O2 -D_FORTIFY_SOURCE=3 (=2 on older toolchains)."),
    "cet_ibt": ("x86 CET indirect-branch tracking (IBT) marked",
                "Compile with -fcf-protection=full; add endbr64 + a GNU property note to assembly."),
    "cet_shstk": ("x86 CET shadow-stack (SHSTK) compatible",
                  "Compile with -fcf-protection=full; every input object (asm, prebuilts) must carry the property."),
    "bti": ("AArch64 BTI marked", "Compile with -mbranch-protection=standard."),
    "pac": ("AArch64 PAC marked", "Compile with -mbranch-protection=standard."),
    "no_insecure_runpath": ("No relative or world-writable RPATH/RUNPATH entries",
                            "Drop -Wl,-rpath or use absolute / $ORIGIN-based paths."),
    "no_textrel": ("No text relocations", "Build position-independent code (-fPIC)."),
    "stripped": ("No symbol table / debug info in the shipped file",
                 "strip the release artifact; ship debug info separately."),
    "module_signed": ("Kernel module carries an appended signature",
                      "Sign with scripts/sign-file (or the distro DKMS/MOK flow)."),
    "module_no_wx_sections": ("Kernel module has no section that is both writable and executable",
                              "Fix section attributes in the module source."),
    "module_retpoline": ("Kernel module built with retpoline (x86)",
                         "Build through the kernel's Kbuild with a retpoline-capable compiler."),
    "waiver_expired": ("A waiver for this artifact has expired",
                       "Renew the waiver with a fresh justification, or fix the underlying finding."),
}


class PolicyError(Exception):
    pass


# ----------------------------------------------------------------------------
# ELF fact extraction
# ----------------------------------------------------------------------------

def _open_artifact(path):
    """Return (stream, tail_bytes). Decompresses .xz/.gz kernel modules in memory."""
    if path.endswith(".xz"):
        with lzma.open(path) as f:
            data = f.read()
        return io.BytesIO(data), data[-len(MODULE_SIG_MAGIC):]
    if path.endswith(".gz"):
        with gzip.open(path) as f:
            data = f.read()
        return io.BytesIO(data), data[-len(MODULE_SIG_MAGIC):]
    f = open(path, "rb")
    f.seek(0, os.SEEK_END)
    size = f.tell()
    tail = b""
    if size >= len(MODULE_SIG_MAGIC):
        f.seek(-len(MODULE_SIG_MAGIC), os.SEEK_END)
        tail = f.read()
    f.seek(0)
    return f, tail


def _dynamic_tags(elf):
    sec = elf.get_section_by_name(".dynamic")
    if isinstance(sec, DynamicSection):
        return list(sec.iter_tags())
    for seg in elf.iter_segments():  # section headers stripped: fall back to PT_DYNAMIC
        if isinstance(seg, DynamicSegment):
            return list(seg.iter_tags())
    return []


def _symbols(elf, section_name):
    """Return (undefined_names, defined_names) for a symbol table section."""
    sec = elf.get_section_by_name(section_name)
    if not isinstance(sec, SymbolTableSection):
        return None, None
    undef, defined = set(), set()
    for sym in sec.iter_symbols():
        if not sym.name:
            continue
        (undef if sym["st_shndx"] == "SHN_UNDEF" else defined).add(sym.name)
    return undef, defined


def _gnu_properties(elf):
    """Return {pr_type: pr_data} from NT_GNU_PROPERTY_TYPE_0 notes (None if no note)."""
    props, found = {}, False
    sources = [s for s in elf.iter_sections() if isinstance(s, NoteSection)]
    if not sources:  # no section headers: use PT_NOTE / PT_GNU_PROPERTY segments
        sources = [s for s in elf.iter_segments() if s["p_type"] in ("PT_NOTE", "PT_GNU_PROPERTY")
                   and hasattr(s, "iter_notes")]
    for src in sources:
        for note in src.iter_notes():
            if note["n_type"] != "NT_GNU_PROPERTY_TYPE_0":
                continue
            found = True
            for prop in note["n_desc"]:
                props[prop["pr_type"]] = prop["pr_data"]
    return props if found else None


def gather_facts(path):
    stream, tail = _open_artifact(path)
    try:
        elf = ELFFile(stream)
        facts = {
            "e_type": elf["e_type"],
            "machine": elf["e_machine"],
            "tail": tail,
        }
        segs = list(elf.iter_segments())
        facts["has_interp"] = any(s["p_type"] == "PT_INTERP" for s in segs)
        facts["has_dynamic"] = any(s["p_type"] == "PT_DYNAMIC" for s in segs)
        gnu_stack = [s["p_flags"] for s in segs if s["p_type"] == "PT_GNU_STACK"]
        facts["gnu_stack_flags"] = gnu_stack[0] if gnu_stack else None
        facts["has_relro"] = any(s["p_type"] == "PT_GNU_RELRO" for s in segs)
        facts["rwx_load"] = any(s["p_type"] == "PT_LOAD" and s["p_flags"] & PF_W and s["p_flags"] & PF_X
                                for s in segs)

        flags = flags_1 = 0
        bind_now_tag = textrel_tag = False
        soname, rpath, runpath = None, [], []
        for tag in _dynamic_tags(elf):
            t = tag.entry.d_tag
            if t == "DT_FLAGS":
                flags = tag.entry.d_val
            elif t == "DT_FLAGS_1":
                flags_1 = tag.entry.d_val
            elif t == "DT_BIND_NOW":
                bind_now_tag = True
            elif t == "DT_TEXTREL":
                textrel_tag = True
            elif t == "DT_SONAME":
                soname = tag.soname
            elif t == "DT_RPATH":
                rpath.append(tag.rpath)          # keep raw strings: "" != "a:" (see check_runpath)
            elif t == "DT_RUNPATH":
                runpath.append(tag.runpath)
        facts.update(flags=flags, flags_1=flags_1, soname=soname, rpath=rpath, runpath=runpath,
                     bind_now=bind_now_tag or bool(flags & DF_BIND_NOW) or bool(flags_1 & DF_1_NOW),
                     textrel=textrel_tag or bool(flags & DF_TEXTREL))

        facts["dyn_undef"], _ = _symbols(elf, ".dynsym")
        facts["sym_undef"], facts["sym_defined"] = _symbols(elf, ".symtab")
        sections = {s.name: s for s in elf.iter_sections()}
        facts["section_names"] = set(sections)
        facts["wx_sections"] = sorted(n for n, s in sections.items()
                                      if s["sh_flags"] & SHF_WRITE and s["sh_flags"] & SHF_EXECINSTR)
        gnu_stack_sec = sections.get(".note.GNU-stack")
        facts["note_gnu_stack"] = None if gnu_stack_sec is None else bool(gnu_stack_sec["sh_flags"] & SHF_EXECINSTR)
        facts["gnu_props"] = _gnu_properties(elf)

        modinfo = {}
        mi = sections.get(".modinfo")
        if mi is not None:
            for entry in mi.data().split(b"\0"):
                if b"=" in entry:
                    k, v = entry.split(b"=", 1)
                    modinfo.setdefault(k.decode(errors="replace"), v.decode(errors="replace"))
        facts["modinfo"] = modinfo
        return facts
    finally:
        stream.close()


def classify(facts):
    t = facts["e_type"]
    if t == "ET_REL":
        return "kernel_module" if facts["modinfo"] else "object"
    if t == "ET_EXEC":
        return "executable"
    if t == "ET_DYN":
        if facts["flags_1"] & DF_1_PIE:
            return "executable"
        if facts["soname"]:
            return "shared_lib"
        return "executable" if facts["has_interp"] else "shared_lib"
    return "other"


# ----------------------------------------------------------------------------
# Checks: each returns (ok, detail) with ok in {True, False, None (n/a)}
# ----------------------------------------------------------------------------

def _imports(facts):
    """Undefined symbols the binary pulls in, or None if unknown (stripped static)."""
    if facts["dyn_undef"] is not None:
        return facts["dyn_undef"]
    if facts["sym_undef"] is not None:
        return facts["sym_undef"] | (facts["sym_defined"] or set())  # static: heuristic
    return None


def check_nx_stack(facts, kind):
    if kind == "object":
        if facts["note_gnu_stack"] is None:
            return False, "no .note.GNU-stack section: the linker will assume an executable stack"
        return (not facts["note_gnu_stack"]), (".note.GNU-stack requests an executable stack"
                                               if facts["note_gnu_stack"] else "ok")
    flags = facts["gnu_stack_flags"]
    if flags is None:
        return False, "no PT_GNU_STACK header (loader may default to an executable stack)"
    if flags & PF_X:
        return False, "PT_GNU_STACK is executable (RWX)"
    return True, "ok"


def check_rwx(facts, kind):
    return (not facts["rwx_load"]), ("a PT_LOAD segment is W+X" if facts["rwx_load"] else "ok")


def check_pie(facts, kind):
    if kind != "executable":
        return None, "n/a"
    if facts["e_type"] == "ET_DYN":
        return True, "ET_DYN" + (" + DF_1_PIE" if facts["flags_1"] & DF_1_PIE else "")
    return False, "ET_EXEC (fixed load address)"


def check_relro(facts, kind):
    if not facts["has_relro"]:
        return False, "none (no PT_GNU_RELRO)"
    if facts["bind_now"] or not facts["has_dynamic"]:
        return True, "full"
    return False, "partial (PT_GNU_RELRO without BIND_NOW: GOT stays writable)"


def check_canary(facts, kind):
    syms = facts["sym_undef"] if kind in ("kernel_module", "object") else _imports(facts)
    if syms is None:
        return None, "unknown (no symbol table)"
    if "__stack_chk_fail" in syms or "__stack_chk_guard" in syms:
        return True, "ok"
    return False, "__stack_chk_fail not referenced (no protected frames, or built without -fstack-protector)"


def check_fortify(facts, kind):
    syms = _imports(facts)
    if syms is None:
        return None, "unknown (no symbol table)"
    fortified = sorted(s for s in syms if s.startswith("__") and s.endswith("_chk"))
    plain = sorted(s for s in syms if s in FORTIFIABLE)
    if fortified:
        return True, f"{len(fortified)} fortified, {len(plain)} unfortified fortifiable"
    if plain:
        return False, "imports " + ", ".join(plain[:4]) + (" ..." if len(plain) > 4 else "") + " but no __*_chk"
    return None, "no fortifiable libc calls"


def _feature_check(machines, pr_type, bit, name):
    def check(facts, kind):
        if facts["machine"] not in machines:
            return None, f"n/a ({facts['machine']})"
        props = facts["gnu_props"]
        if props is None:
            return False, "no GNU property note (built without the flag, or not marked)"
        if pr_type not in props:
            return False, (f"no {pr_type.replace('GNU_PROPERTY_', '')} property: the linker drops it "
                           "when ANY input object (asm, prebuilt, unhardened TU) lacks it")
        bits = props[pr_type]
        return bool(bits & bit), ("ok" if bits & bit else f"{name} bit not set ({bits:#x})")
    return check


def _x86_check(bit, name):
    return _feature_check(("EM_X86_64", "EM_386"), "GNU_PROPERTY_X86_FEATURE_1_AND", bit, name)


def _arm_check(bit, name):
    return _feature_check(("EM_AARCH64",), "GNU_PROPERTY_AARCH64_FEATURE_1_AND", bit, name)


def check_runpath(facts, kind):
    """Flag search-path entries an attacker could plant libraries in.

    Verified with glibc 2.35: a wholly empty DT_RUNPATH ("") is ignored, but an empty
    *element* inside a non-empty list ("/opt/x:" or "/a::/b") means the current working
    directory, so is a library-hijack risk, as are relative and world-writable entries.
    """
    raw = [("RPATH", r) for r in facts["rpath"]] + [("RUNPATH", r) for r in facts["runpath"]]
    if not raw:
        return True, "none"
    bad, notes, good = [], [], []
    for tag, value in raw:
        if value == "":
            notes.append(f"empty {tag} string (ignored by glibc)")
            continue
        for e in value.split(":"):
            if e == "":
                bad.append(f"{tag} '{value}' has an empty element (= current working directory)")
            elif not (e.startswith("/") or e.startswith("$ORIGIN") or e.startswith("${ORIGIN}")):
                bad.append(f"{tag} entry '{e}' is relative to the working directory")
            elif any(e == d or e.startswith(d + "/") for d in WORLD_WRITABLE_DIRS):
                bad.append(f"{tag} entry '{e}' is in a world-writable directory")
            else:
                good.append(e)
    if bad:
        return False, "; ".join(bad + notes)
    return True, "; ".join(notes + (["absolute/$ORIGIN entries: " + ":".join(good)] if good else [])) or "ok"


def check_textrel(facts, kind):
    return (not facts["textrel"]), ("has DT_TEXTREL" if facts["textrel"] else "ok")


def check_stripped(facts, kind):
    present = [n for n in (".symtab", ".debug_info", ".debug_line") if n in facts["section_names"]]
    return (not present), ("present: " + ", ".join(present) if present else "ok")


def check_module_signed(facts, kind):
    signed = facts["tail"] == MODULE_SIG_MAGIC
    return signed, ("ok" if signed else "no appended module signature")


def check_module_wx(facts, kind):
    wx = facts["wx_sections"]
    return (not wx), ("W+X sections: " + ", ".join(wx) if wx else "ok")


def check_module_retpoline(facts, kind):
    if facts["machine"] != "EM_X86_64":
        return None, "n/a (not x86_64)"
    val = facts["modinfo"].get("retpoline")
    return val == "Y", ("ok" if val == "Y" else "no 'retpoline=Y' in .modinfo")


CHECKS_BY_KIND = {
    "executable": {
        "nx_stack": check_nx_stack, "no_rwx_segments": check_rwx, "pie": check_pie,
        "relro_full": check_relro, "canary": check_canary, "fortify": check_fortify,
        "cet_ibt": _x86_check(X86_IBT, "IBT"), "cet_shstk": _x86_check(X86_SHSTK, "SHSTK"),
        "bti": _arm_check(AARCH64_BTI, "BTI"), "pac": _arm_check(AARCH64_PAC, "PAC"),
        "no_insecure_runpath": check_runpath, "no_textrel": check_textrel, "stripped": check_stripped,
    },
    "shared_lib": {
        "nx_stack": check_nx_stack, "no_rwx_segments": check_rwx, "relro_full": check_relro,
        "canary": check_canary, "fortify": check_fortify,
        "cet_ibt": _x86_check(X86_IBT, "IBT"), "cet_shstk": _x86_check(X86_SHSTK, "SHSTK"),
        "bti": _arm_check(AARCH64_BTI, "BTI"), "pac": _arm_check(AARCH64_PAC, "PAC"),
        "no_insecure_runpath": check_runpath, "no_textrel": check_textrel, "stripped": check_stripped,
    },
    "kernel_module": {
        "module_signed": check_module_signed, "module_no_wx_sections": check_module_wx,
        "module_retpoline": check_module_retpoline, "canary": check_canary,
    },
    "object": {
        "nx_stack": check_nx_stack, "cet_ibt": _x86_check(X86_IBT, "IBT"),
        "cet_shstk": _x86_check(X86_SHSTK, "SHSTK"),
    },
}


# ----------------------------------------------------------------------------
# Policy, waivers, baseline
# ----------------------------------------------------------------------------

def load_policy(path):
    try:
        with open(path) as f:
            pol = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise PolicyError(f"cannot load policy {path}: {e}") from e
    profiles = pol.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise PolicyError("policy needs a non-empty 'profiles' object")
    for kind, checks in profiles.items():
        if kind.startswith("_"):
            continue
        if kind not in KINDS:
            raise PolicyError(f"unknown artifact kind '{kind}' (known: {', '.join(KINDS)})")
        if not isinstance(checks, dict):
            raise PolicyError(f"profile '{kind}' must be an object")
        for cid, level in checks.items():
            if cid.startswith("_"):
                continue
            if cid not in CHECKS_BY_KIND[kind]:
                raise PolicyError(f"profile '{kind}': check '{cid}' does not exist for this kind")
            if level not in LEVELS:
                raise PolicyError(f"profile '{kind}': check '{cid}' has invalid level '{level}'")
    waivers = pol.get("waivers", [])
    if not isinstance(waivers, list):
        raise PolicyError("'waivers' must be a list")
    for i, w in enumerate(waivers):
        for key in ("path", "check", "owner", "reason", "expires"):
            if not w.get(key):
                raise PolicyError(f"waiver #{i}: missing '{key}'")
        if w["check"] != "*" and w["check"] not in CHECKS:
            raise PolicyError(f"waiver #{i}: unknown check '{w['check']}'")
        try:
            w["_expires"] = dt.date.fromisoformat(w["expires"])
        except ValueError as e:
            raise PolicyError(f"waiver #{i}: expires must be YYYY-MM-DD") from e
    return pol


def match_waiver(waivers, relpath, abspath, check):
    for idx, w in enumerate(waivers):
        if w["check"] not in ("*", check):
            continue
        if fnmatch.fnmatch(relpath, w["path"]) or fnmatch.fnmatch(abspath, w["path"]):
            return idx, w
    return None, None


def fingerprint(check, relpath):
    return hashlib.sha256(f"{check}\0{relpath}".encode()).hexdigest()[:16]


def load_baseline(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise PolicyError(f"cannot load baseline {path}: {e}") from e
    return {f["fingerprint"] for f in data.get("findings", []) if f.get("status") in ("new", "existing")}


# ----------------------------------------------------------------------------
# Scanning
# ----------------------------------------------------------------------------

def _is_candidate(path):
    if path.endswith((".ko.xz", ".ko.gz")):
        return True
    try:
        with open(path, "rb") as f:
            return f.read(4) == ELF_MAGIC
    except OSError:
        return False


def iter_artifacts(roots):
    for root in roots:
        if os.path.isfile(root):
            yield root, os.path.basename(root)
            continue
        if not os.path.isdir(root):
            raise PolicyError(f"no such file or directory: {root}")
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            for name in sorted(filenames):
                p = os.path.join(dirpath, name)
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                yield p, os.path.relpath(p, root)


def _gather_safe(abspath):
    """Worker entry point: never raises, so one malformed file can't kill the scan."""
    try:
        return gather_facts(abspath), None
    except (ELFError, OSError, EOFError, lzma.LZMAError, ValueError, KeyError, AttributeError) as e:
        return None, f"{type(e).__name__}: {e}"


def _gather_all(candidates, jobs):
    paths = [a for a, _ in candidates]
    if jobs <= 1 or len(paths) < 32:
        return [_gather_safe(p) for p in paths]
    from concurrent.futures import ProcessPoolExecutor
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        return list(pool.map(_gather_safe, paths, chunksize=16))


def scan(roots, policy, baseline, today, max_files, jobs=1):
    profiles = policy["profiles"]
    waivers = policy.get("waivers", [])
    artifacts, findings, errors = [], [], []
    expired_seen = set()
    candidates = [(a, r) for a, r in iter_artifacts(roots) if _is_candidate(a)]
    if max_files:
        candidates = candidates[:max_files]
    for (abspath, relpath), (facts, err) in zip(candidates, _gather_all(candidates, jobs)):
        if err is not None:
            errors.append({"path": relpath, "error": err})
            continue
        kind = classify(facts)
        if kind not in CHECKS_BY_KIND:
            continue
        profile = profiles.get(kind, {})
        results = {}
        for cid, fn in CHECKS_BY_KIND[kind].items():
            ok, detail = fn(facts, kind)
            level = profile.get(cid, "off")
            results[cid] = {"ok": ok, "detail": detail, "level": level}
            if level == "off" or ok is not False:
                continue
            f = {
                "fingerprint": fingerprint(cid, relpath), "path": relpath, "kind": kind,
                "check": cid, "title": CHECKS[cid][0], "detail": detail, "level": level,
                "remediation": CHECKS[cid][1], "status": "new",
            }
            widx, w = match_waiver(waivers, relpath, abspath, cid)
            if w is not None and w["_expires"] >= today:
                f["status"] = "waived"
                f["waiver"] = {k: w.get(k) for k in ("owner", "reason", "ticket", "expires")}
            elif w is not None and (relpath, widx) not in expired_seen:
                expired_seen.add((relpath, widx))
                efp = fingerprint(f"waiver_expired:{widx}", relpath)
                findings.append({
                    "fingerprint": efp, "path": relpath, "kind": kind, "check": "waiver_expired",
                    "title": CHECKS["waiver_expired"][0],
                    "detail": f"waiver for '{w['check']}' (owner {w['owner']}, ticket {w.get('ticket') or '-'})"
                              f" expired on {w['expires']}",
                    "level": "error", "remediation": CHECKS["waiver_expired"][1],
                    "status": "existing" if efp in baseline else "new",
                })
            if f["status"] == "new" and f["fingerprint"] in baseline:
                f["status"] = "existing"
            findings.append(f)
        artifacts.append({"path": relpath, "kind": kind, "machine": facts["machine"], "checks": results})
    return artifacts, findings, errors


def coverage(artifacts):
    """Per-check compliance across all applicable, enabled artifacts (a release metric)."""
    cov = {}
    for a in artifacts:
        for cid, r in a["checks"].items():
            if r["level"] == "off" or r["ok"] is None:
                continue
            c = cov.setdefault(cid, {"applicable": 0, "passing": 0})
            c["applicable"] += 1
            c["passing"] += bool(r["ok"])
    for c in cov.values():
        c["percent"] = round(100.0 * c["passing"] / c["applicable"], 1)
    return dict(sorted(cov.items()))


# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------

def build_report(args, artifacts, findings, errors, gate_levels):
    blocking = [f for f in findings if f["status"] == "new" and f["level"] in gate_levels]
    by_status = {}
    for f in findings:
        by_status[f["status"]] = by_status.get(f["status"], 0) + 1
    return {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "policy": args.policy, "baseline": args.baseline, "roots": args.paths,
        "artifacts": artifacts, "findings": findings, "errors": errors,
        "summary": {
            "artifacts": len(artifacts), "findings_by_status": by_status,
            "blocking": len(blocking), "gate": "FAILED" if blocking else "PASSED",
            "gate_levels": sorted(gate_levels), "coverage": coverage(artifacts),
        },
    }


def render_text(report):
    out = []
    s = report["summary"]
    out.append(f"{TOOL_NAME} {TOOL_VERSION}  policy={report['policy']}  artifacts={s['artifacts']}"
               + (f"  baseline={report['baseline']}" if report["baseline"] else ""))
    out.append("")
    out.append("ARTIFACTS")
    per_path = {}
    for f in report["findings"]:
        per_path.setdefault(f["path"], []).append(f)
    for a in report["artifacts"]:
        fs = per_path.get(a["path"], [])
        live = [f for f in fs if f["status"] != "waived"]
        if any(f["level"] == "error" for f in live):
            status = "FAIL"
        elif any(f["level"] == "warn" for f in live):
            status = "WARN"
        else:
            status = "PASS"
        notes = []
        for f in fs:
            tag = {"waived": " [waived]", "existing": " [baseline]"}.get(f["status"], "")
            notes.append(f"{f['check']}{tag}")
        out.append(f"  {status:4}  {a['kind']:13} {a['path']}" + (f"   ({', '.join(notes)})" if notes else ""))
    out.append("")
    if report["findings"]:
        out.append("FINDINGS")
        order = {"error": 0, "warn": 1, "info": 2}
        for f in sorted(report["findings"], key=lambda f: (f["status"] != "new", order[f["level"]], f["path"])):
            out.append(f"  {f['level'].upper():5} {f['status']:8} {f['path']}: {f['check']} - {f['detail']}")
            if f["status"] == "waived":
                w = f["waiver"]
                out.append(f"        waived until {w['expires']} by {w['owner']} ({w.get('ticket') or '-'}): {w['reason']}")
            elif f["status"] == "new":
                out.append(f"        fix: {f['remediation']}")
        out.append("")
    if report["errors"]:
        out.append(f"UNPARSEABLE ({len(report['errors'])})")
        for e in report["errors"][:10]:
            out.append(f"  {e['path']}: {e['error']}")
        out.append("")
    out.append("COVERAGE (passing / applicable artifacts, enabled checks only)")
    for cid, c in s["coverage"].items():
        out.append(f"  {cid:22} {c['passing']:5} / {c['applicable']:<5} {c['percent']:5.1f}%")
    out.append("")
    out.append(f"GATE: {s['gate']}  ({s['blocking']} new finding(s) at level {'/'.join(s['gate_levels'])}; "
               f"status counts {s['findings_by_status']})")
    return "\n".join(out) + "\n"


def render_sarif(report):
    used_baseline = bool(report["baseline"])
    rules = [{"id": cid, "name": cid, "shortDescription": {"text": t}, "help": {"text": fix}}
             for cid, (t, fix) in CHECKS.items()]
    results = []
    for f in report["findings"]:
        r = {
            "ruleId": f["check"],
            "level": SARIF_LEVEL[f["level"]],
            "message": {"text": f"{f['title']}: {f['detail']} ({f['kind']})"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"].replace(os.sep, "/")}}}],
            "partialFingerprints": {"hardeningCheck/v1": f["fingerprint"]},
        }
        if used_baseline:
            r["baselineState"] = "unchanged" if f["status"] == "existing" else "new"
        if f["status"] == "waived":
            w = f["waiver"]
            r["suppressions"] = [{"kind": "external", "status": "accepted",
                                  "justification": f"{w['reason']} (owner {w['owner']}, "
                                                   f"ticket {w.get('ticket') or '-'}, expires {w['expires']})"}]
        results.append(r)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": TOOL_NAME, "version": TOOL_VERSION, "rules": rules}},
                  "results": results}],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Policy-as-code ELF hardening checker (lab).")
    ap.add_argument("paths", nargs="*", help="files or directories to scan")
    ap.add_argument("-p", "--policy", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy.json"))
    ap.add_argument("-f", "--format", choices=("text", "json", "sarif"), default="text")
    ap.add_argument("-o", "--output", help="write the report here (default: stdout)")
    ap.add_argument("--baseline", help="JSON report from the previous release: only NEW findings gate")
    ap.add_argument("--fail-on", choices=("error", "warn"), default="error",
                    help="lowest finding level that fails the gate (default: error)")
    ap.add_argument("--today", help="override today's date (YYYY-MM-DD) for waiver expiry; for tests")
    ap.add_argument("--max-files", type=int, default=0, help="stop after N artifacts (0 = no limit)")
    ap.add_argument("-j", "--jobs", type=int, default=min(8, os.cpu_count() or 1),
                    help="parallel parser processes (default: min(8, CPUs))")
    ap.add_argument("--list-checks", action="store_true", help="print the check catalog and exit")
    args = ap.parse_args(argv)

    if args.list_checks:
        for cid, (title, fix) in CHECKS.items():
            kinds = [k for k, cs in CHECKS_BY_KIND.items() if cid in cs]
            print(f"{cid:22} {title}\n{'':22} kinds: {', '.join(kinds) or '(meta)'}\n{'':22} fix: {fix}")
        return 0
    if not args.paths:
        ap.error("give at least one file or directory to scan")

    try:
        policy = load_policy(args.policy)
        baseline = load_baseline(args.baseline) if args.baseline else set()
        today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
        artifacts, findings, errors = scan(args.paths, policy, baseline, today, args.max_files, args.jobs)
    except (PolicyError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    gate_levels = {"error"} if args.fail_on == "error" else {"error", "warn"}
    report = build_report(args, artifacts, findings, errors, gate_levels)
    if args.format == "text":
        text = render_text(report)
    elif args.format == "json":
        text = json.dumps(report, indent=2) + "\n"
    else:
        text = json.dumps(render_sarif(report), indent=2) + "\n"

    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
        print(f"{report['summary']['gate']}: wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 1 if report["summary"]["gate"] == "FAILED" else 0


if __name__ == "__main__":
    sys.exit(main())
