"""Unit tests for analysis/crypto.py — weak PRNG detector helpers.

Coverage:
  Fix 2.4 — _KEY_UI_DENYLIST suppression in _security_named_context():
    UI/keyboard functions that happen to contain 'key' in their name
    must NOT match as a security-named context.
    Genuine crypto-key functions must still match.
  _user_facing_identifier — MSVC mangling demangling (spot-checks)
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).parent.parent / "scripts"
if str(_SCRIPTS.parent) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS.parent))

from scripts.analysis.crypto import (
    _security_named_context,
    _user_facing_identifier,
    _KEY_UI_DENYLIST,
)


# ---------------------------------------------------------------------------
# Minimal function stub
# ---------------------------------------------------------------------------

class _Fn:
    def __init__(self, name: str):
        self.name = name
        self.source_function = None
        self.callers = []


# ---------------------------------------------------------------------------
# _KEY_UI_DENYLIST sanity
# ---------------------------------------------------------------------------

class TestKeyUiDenylist(unittest.TestCase):

    def test_denylist_nonempty(self):
        self.assertTrue(len(_KEY_UI_DENYLIST) > 0)

    def test_expected_terms_present(self):
        for term in ("keyboard", "keyfocus", "accesskey", "keymessage", "keyhandl"):
            self.assertIn(term, _KEY_UI_DENYLIST, f"{term!r} missing from denylist")


# ---------------------------------------------------------------------------
# _security_named_context — UI/keyboard suppression (Fix 2.4)
# ---------------------------------------------------------------------------

class TestSecurityNamedContextKeyUiSuppression(unittest.TestCase):

    def test_isitemkeyfocused_suppressed(self):
        """IsItemKeyFocused contains 'keyfocus' — must not fire."""
        result = _security_named_context(_Fn("IsItemKeyFocused"))
        self.assertIsNone(result)

    def test_handleaccesskeymessages_suppressed(self):
        """HandleAccessKeyMessages contains 'keymessage' — must not fire."""
        result = _security_named_context(_Fn("HandleAccessKeyMessages"))
        self.assertIsNone(result)

    def test_processaccesskey_suppressed(self):
        """ProcessAccessKey contains 'accesskey' — must not fire."""
        result = _security_named_context(_Fn("ProcessAccessKey"))
        self.assertIsNone(result)

    def test_hotkeybind_suppressed(self):
        """HotKeyBind contains 'hotkey' — must not fire."""
        result = _security_named_context(_Fn("HotKeyBind"))
        self.assertIsNone(result)

    def test_onkeydown_suppressed(self):
        """OnKeyDown contains 'keydown' — must not fire."""
        result = _security_named_context(_Fn("OnKeyDown"))
        self.assertIsNone(result)

    def test_keyboard_handler_suppressed(self):
        """KeyboardHandler contains 'keyboard' — must not fire."""
        result = _security_named_context(_Fn("KeyboardHandler"))
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# _security_named_context — genuine crypto keys must still match
# ---------------------------------------------------------------------------

class TestSecurityNamedContextCryptoKeyPreserved(unittest.TestCase):

    def test_generatekey_matches(self):
        """GenerateKey is a crypto function — must match with 'key' token."""
        result = _security_named_context(_Fn("GenerateKey"))
        self.assertIsNotNone(result)
        self.assertIn("key", result)

    def test_initkey_matches(self):
        result = _security_named_context(_Fn("InitKey"))
        self.assertIsNotNone(result)

    def test_derivekey_matches(self):
        result = _security_named_context(_Fn("DeriveKey"))
        self.assertIsNotNone(result)

    def test_session_key_matches(self):
        """SessionKey — 'session' token should match regardless of 'key' in name."""
        result = _security_named_context(_Fn("SessionKey"))
        self.assertIsNotNone(result)

    def test_masterkey_matches(self):
        result = _security_named_context(_Fn("MasterKey"))
        self.assertIsNotNone(result)


# ---------------------------------------------------------------------------
# Other security tokens — unaffected by key suppression
# ---------------------------------------------------------------------------

class TestSecurityNamedContextOtherTokens(unittest.TestCase):

    def test_issue_token_matches(self):
        result = _security_named_context(_Fn("IssueToken"))
        self.assertIsNotNone(result)
        self.assertIn("token", result)

    def test_update_secret_matches(self):
        result = _security_named_context(_Fn("UpdateSecret"))
        self.assertIsNotNone(result)
        self.assertIn("secret", result)

    def test_make_nonce_matches(self):
        result = _security_named_context(_Fn("MakeNonce"))
        self.assertIsNotNone(result)

    def test_unrelated_function_returns_none(self):
        result = _security_named_context(_Fn("ProcessMouseClick"))
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# _user_facing_identifier — basic MSVC mangling
# ---------------------------------------------------------------------------

class TestUserFacingIdentifier(unittest.TestCase):

    def test_plain_name(self):
        self.assertEqual(_user_facing_identifier("GenerateKey"), "GenerateKey")

    def test_jump_thunk_stripped(self):
        self.assertEqual(_user_facing_identifier("j_GenerateKey"), "GenerateKey")

    def test_compiler_intrinsic_rejected(self):
        self.assertIsNone(_user_facing_identifier("__memcpy"))

    def test_msvc_free_function(self):
        self.assertEqual(_user_facing_identifier("?GenerateKey@@YAHXZ"), "GenerateKey")

    def test_msvc_class_method(self):
        self.assertEqual(
            _user_facing_identifier("?GenerateKey@CryptoHelper@@YAHXZ"),
            "GenerateKey",
        )

    def test_msvc_special_name_rejected(self):
        self.assertIsNone(_user_facing_identifier("??0Foo@@QEAA@XZ"))


if __name__ == "__main__":
    unittest.main()
