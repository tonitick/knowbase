#!/usr/bin/env python3
"""Fixture tests: every check needs a known-good and a known-bad artifact.

Run:  python3 -m unittest -v test_hardening_check.py     (builds samples/ with make + gcc)
"""
import json
import os
import platform
import shutil
import subprocess
import tempfile
import unittest

import hardening_check as hc

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(HERE, "samples", "build")
POLICY = os.path.join(HERE, "policy.json")
X86 = platform.machine() == "x86_64"


def checks_for(name):
    facts = hc.gather_facts(os.path.join(BUILD, name))
    kind = hc.classify(facts)
    return kind, {cid: fn(facts, kind)[0] for cid, fn in hc.CHECKS_BY_KIND[kind].items()}


@unittest.skipUnless(shutil.which("gcc") and shutil.which("make"), "needs gcc + make")
class SampleBinaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(["make", "-s", "-C", os.path.join(HERE, "samples")], check=True)

    def test_hardened_passes_everything_relevant(self):
        kind, r = checks_for("demo_hardened")
        self.assertEqual(kind, "executable")
        for cid in ("nx_stack", "no_rwx_segments", "pie", "relro_full", "canary", "fortify",
                    "no_insecure_runpath", "no_textrel"):
            self.assertIs(r[cid], True, cid)
        if X86:
            self.assertIs(r["cet_ibt"], True)
            self.assertIs(r["cet_shstk"], True)

    def test_weak_fails(self):
        _, r = checks_for("demo_weak")
        for cid in ("nx_stack", "pie", "relro_full", "canary", "fortify", "no_insecure_runpath"):
            self.assertIs(r[cid], False, cid)

    @unittest.skipUnless(X86, "x86-only sample")
    def test_one_unmarked_asm_file_drops_cet_and_nx(self):
        _, r = checks_for("demo_asm")
        self.assertIs(r["cet_ibt"], False)
        self.assertIs(r["cet_shstk"], False)
        self.assertIs(r["nx_stack"], False)
        kind, o = checks_for("legacy_asm.o")
        self.assertEqual(kind, "object")
        self.assertIs(o["nx_stack"], False)

    def test_shared_lib_partial_relro_and_relative_runpath(self):
        kind, r = checks_for("libdemo.so")
        self.assertEqual(kind, "shared_lib")
        self.assertIs(r["relro_full"], False)
        self.assertIs(r["no_insecure_runpath"], False)

    def test_waivers_baseline_and_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            prev = os.path.join(tmp, "prev.json")
            rc = hc.main(["-p", POLICY, "-f", "json", "-o", prev, "--today", "2026-06-01", BUILD])
            self.assertEqual(rc, 1)                       # errors present -> gate fails
            with open(prev) as f:
                rep = json.load(f)
            waived = [f for f in rep["findings"] if f["status"] == "waived"]
            self.assertEqual([(f["path"], f["check"]) for f in waived], [("libdemo.so", "relro_full")])
            self.assertTrue(any(f["check"] == "waiver_expired" for f in rep["findings"]))
            # Same artifacts against their own baseline: nothing new -> gate passes
            rc = hc.main(["-p", POLICY, "-f", "json", "-o", os.path.join(tmp, "cur.json"),
                          "--today", "2026-06-01", "--baseline", prev, BUILD])
            self.assertEqual(rc, 0)
            # After the waiver's expiry date the waived finding becomes blocking again
            rc = hc.main(["-p", POLICY, "-f", "json", "-o", os.path.join(tmp, "late.json"),
                          "--today", "2027-07-01", "--baseline", prev, BUILD])
            self.assertEqual(rc, 1)


class RunpathSemantics(unittest.TestCase):
    """Behavior verified against glibc 2.35 (see README)."""

    def run_check(self, runpath):
        return hc.check_runpath({"rpath": [], "runpath": [runpath]}, "executable")[0]

    def test_empty_string_is_ignored_by_glibc(self):
        self.assertIs(self.run_check(""), True)

    def test_empty_element_means_cwd(self):
        self.assertIs(self.run_check("/opt/x:"), False)
        self.assertIs(self.run_check("/a::/b"), False)

    def test_relative_and_world_writable(self):
        self.assertIs(self.run_check("plugins"), False)
        self.assertIs(self.run_check("/tmp/libs"), False)

    def test_origin_and_absolute_ok(self):
        self.assertIs(self.run_check("$ORIGIN/../lib:/opt/vendor/lib"), True)


class PolicyValidation(unittest.TestCase):
    def write(self, obj):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f)
        self.addCleanup(os.unlink, path)
        return path

    def test_typo_in_level_fails_closed(self):
        with self.assertRaises(hc.PolicyError):
            hc.load_policy(self.write({"profiles": {"executable": {"pie": "eror"}}}))

    def test_check_not_valid_for_kind(self):
        with self.assertRaises(hc.PolicyError):
            hc.load_policy(self.write({"profiles": {"executable": {"module_signed": "error"}}}))

    def test_waiver_requires_owner_and_expiry(self):
        with self.assertRaises(hc.PolicyError):
            hc.load_policy(self.write({"profiles": {"executable": {"pie": "error"}},
                                       "waivers": [{"path": "*", "check": "pie", "reason": "x"}]}))


if __name__ == "__main__":
    unittest.main()
