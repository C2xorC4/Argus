"""Unit tests for analysis/sddl.py — SDDL classifier.

Coverage:
  Fix 2.7 — _classify_ace() overbroad-principal read-only carve-out:
    WD/BU with read-only rights (GR, KR) → neutral (was FP before fix)
    WD/BU with write rights (CC, GW, SD) → permissive (still detected)
    AU with read-only rights → neutral (original AU behaviour preserved)
    AU with write rights → permissive
  parse_sddl integration — full SDDL strings containing read-only WD ACEs
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).parent.parent / "scripts"
if str(_SCRIPTS.parent) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS.parent))

from scripts.analysis.sddl import _classify_ace, parse_sddl


# ---------------------------------------------------------------------------
# _classify_ace — read-only grants on overbroad principals (Fix 2.7)
# ---------------------------------------------------------------------------

class TestClassifyAceReadOnly(unittest.TestCase):

    def test_wd_gr_is_neutral(self):
        """World/Everyone with generic-read only must NOT fire — public resources."""
        ace = _classify_ace("A", "GR", "WD")
        self.assertEqual(ace.severity_class, "neutral")

    def test_wd_kr_is_neutral(self):
        """World/Everyone with key-read only must NOT fire."""
        ace = _classify_ace("A", "KR", "WD")
        self.assertEqual(ace.severity_class, "neutral")

    def test_wd_gr_kr_is_neutral(self):
        """World/Everyone with GR+KR combined must NOT fire."""
        ace = _classify_ace("A", "GRKR", "WD")
        self.assertEqual(ace.severity_class, "neutral")

    def test_bu_gr_is_neutral(self):
        """Built-in Users with generic-read only must NOT fire."""
        ace = _classify_ace("A", "GR", "BU")
        self.assertEqual(ace.severity_class, "neutral")

    def test_bu_kr_is_neutral(self):
        """Built-in Users with key-read only must NOT fire."""
        ace = _classify_ace("A", "KR", "BU")
        self.assertEqual(ace.severity_class, "neutral")

    def test_au_gr_is_neutral(self):
        """Authenticated Users with generic-read only — original behaviour preserved."""
        ace = _classify_ace("A", "GR", "AU")
        self.assertEqual(ace.severity_class, "neutral")

    def test_au_kr_is_neutral(self):
        ace = _classify_ace("A", "KR", "AU")
        self.assertEqual(ace.severity_class, "neutral")


# ---------------------------------------------------------------------------
# _classify_ace — write/create/execute rights still fire (regression guard)
# ---------------------------------------------------------------------------

class TestClassifyAceWriteStillDetected(unittest.TestCase):

    def test_wd_cc_is_permissive(self):
        """World/Everyone with create-child must still fire."""
        ace = _classify_ace("A", "CC", "WD")
        self.assertEqual(ace.severity_class, "permissive")

    def test_wd_gw_is_permissive(self):
        ace = _classify_ace("A", "GW", "WD")
        self.assertEqual(ace.severity_class, "permissive")

    def test_bu_sd_is_permissive(self):
        ace = _classify_ace("A", "SD", "BU")
        self.assertEqual(ace.severity_class, "permissive")

    def test_au_cc_is_permissive(self):
        ace = _classify_ace("A", "CC", "AU")
        self.assertEqual(ace.severity_class, "permissive")

    def test_wd_full_rights_is_permissive(self):
        """D:(A;;CC;;;WD) — BlueHammer SDDL shape must still fire."""
        ace = _classify_ace("A", "CC", "WD")
        self.assertEqual(ace.severity_class, "permissive")

    def test_bluehammer_sddl_still_fires(self):
        """Full SDDL D:(A;;CC;;;WD) parses to a permissive finding."""
        findings = parse_sddl("D:(A;;CC;;;WD)")
        permissive = [f for f in findings if f.severity_class == "permissive"]
        self.assertTrue(len(permissive) >= 1)


# ---------------------------------------------------------------------------
# _classify_ace — deny ACEs are still neutral regardless
# ---------------------------------------------------------------------------

class TestClassifyAceDeny(unittest.TestCase):

    def test_deny_ace_is_deny_class(self):
        ace = _classify_ace("D", "GR", "WD")
        self.assertEqual(ace.severity_class, "deny")

    def test_deny_write_not_permissive(self):
        ace = _classify_ace("D", "CC", "WD")
        self.assertEqual(ace.severity_class, "deny")


# ---------------------------------------------------------------------------
# parse_sddl integration — read-only WD ACE produces no permissive findings
# ---------------------------------------------------------------------------

class TestParseSddlReadOnly(unittest.TestCase):

    def test_wd_read_only_sddl_no_permissive(self):
        """SDDL with only WD:GR must not produce permissive findings."""
        findings = parse_sddl("D:(A;;GR;;;WD)")
        permissive = [f for f in findings if f.severity_class == "permissive"]
        self.assertEqual(permissive, [])

    def test_mixed_sddl_only_write_is_permissive(self):
        """SDDL with WD:GR and a separate write ACE — only write fires."""
        findings = parse_sddl("D:(A;;GR;;;WD)(A;;CC;;;WD)")
        permissive = [f for f in findings if f.severity_class == "permissive"]
        self.assertEqual(len(permissive), 1)
        self.assertIn("CC", permissive[0].rights)


if __name__ == "__main__":
    unittest.main()
