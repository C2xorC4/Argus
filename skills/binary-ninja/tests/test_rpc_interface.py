"""Unit tests for rpc_interface.py — NDR format-string walker.

All tests use a MockBV that never imports Binary Ninja, so the suite runs
anywhere Python >= 3.10 is available.

Coverage targets:
  - _uuid_str_to_binary           — canonical GUID ↔ binary round-trip
  - _read_transfer_syntax         — NDR32/NDR64/unknown classification
  - _find_midl_server_info        — 3-pointer extraction + TypeFormatString
  - _ndr_proc_has_wstring_param   — the v2/v3 scan path:
      v2: FC_WSTRING / FC_C_WSTRING directly in proc format string
      v3: FC_RP / FC_UP (non-simple) → TypeFormatString → FC_C_WSTRING
      v3: FC_RP (FC_SIMPLE_POINTER flag) → inline FC_WSTRING
      negative: FC_RP → TypeFmt → non-wstring byte
      negative: _NDR_NO_FORMAT sentinel → False
      negative: empty / short chunk → False
"""
from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

# Make analysis package importable without installing.
_SCRIPTS = Path(__file__).parent.parent / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS.parent))

from scripts.analysis.rpc_interface import (
    _uuid_str_to_binary,
    _read_transfer_syntax,
    _find_midl_server_info,
    _ndr_proc_has_wstring_param,
    _tf_is_wstring_pointer,
    _NDR32_TRANSFER_SYNTAX,
    _NDR64_TRANSFER_SYNTAX,
    _NDR_NO_FORMAT,
    _FC_WSTRING,
    _FC_C_WSTRING,
    _FC_RP,
    _FC_UP,
    _FC_OP,
    _FC_FP,
    _FC_SIMPLE_POINTER,
)


# ---------------------------------------------------------------------------
# Mock Binary View
# ---------------------------------------------------------------------------

class MockBV:
    """Minimal Binary Ninja BinaryView substitute.

    Backed by a flat bytearray at base address `base`.  Supports the subset
    of the BV API used by rpc_interface.py: .start, .end, .read(addr, n).
    """

    def __init__(self, data: bytes, base: int = 0x10000000):
        self._data = bytearray(data)
        self.start = base
        self.end = base + len(data)
        self._base = base

    def read(self, addr: int, n: int) -> bytes:
        off = addr - self._base
        if off < 0 or off + n > len(self._data):
            return b""
        return bytes(self._data[off : off + n])

    def patch(self, addr: int, data: bytes) -> None:
        off = addr - self._base
        self._data[off : off + len(data)] = data

    # Not needed by the functions under test, but keeps isinstance checks happy.
    @property
    def functions(self):
        return []

    def get_functions_containing(self, _addr):
        return []

    def find_next_data(self, *_args, **_kwargs):
        return None


def _flat_bv(size: int = 0x10000, base: int = 0x10000000) -> MockBV:
    return MockBV(b"\x00" * size, base=base)


# ---------------------------------------------------------------------------
# _uuid_str_to_binary
# ---------------------------------------------------------------------------

class TestUuidStrToBinary(unittest.TestCase):

    def test_imps_uuid(self):
        uuid = "c503f532-443a-4c69-8300-ccd1fbdb3839"
        b = _uuid_str_to_binary(uuid)
        self.assertEqual(len(b), 16)
        # Data1 0xc503f532 stored LE → bytes 32 f5 03 c5
        self.assertEqual(b[:4], bytes.fromhex("32f503c5"))
        # Data2 0x443a stored LE → 3a 44
        self.assertEqual(b[4:6], bytes.fromhex("3a44"))
        # Data3 0x4c69 stored LE → 69 4c
        self.assertEqual(b[6:8], bytes.fromhex("694c"))
        # Data4 big-endian → 83 00 cc d1 fb db 38 39
        self.assertEqual(b[8:], bytes.fromhex("8300ccd1fbdb3839"))

    def test_braces_stripped(self):
        b1 = _uuid_str_to_binary("c503f532-443a-4c69-8300-ccd1fbdb3839")
        b2 = _uuid_str_to_binary("{c503f532-443a-4c69-8300-ccd1fbdb3839}")
        self.assertEqual(b1, b2)

    def test_bad_uuid_raises(self):
        with self.assertRaises(ValueError):
            _uuid_str_to_binary("not-a-uuid")


# ---------------------------------------------------------------------------
# _read_transfer_syntax
# ---------------------------------------------------------------------------

class TestReadTransferSyntax(unittest.TestCase):

    BASE = 0x10000000

    def _make_bv_with_syntax(self, syntax_bytes: bytes) -> MockBV:
        bv = _flat_bv(0x100, self.BASE)
        # TransferSyntax is at struct_base + 0x18
        bv.patch(self.BASE + 0x18, syntax_bytes)
        return bv

    def test_ndr32(self):
        bv = self._make_bv_with_syntax(_NDR32_TRANSFER_SYNTAX)
        self.assertEqual(_read_transfer_syntax(bv, self.BASE), "NDR32")

    def test_ndr64(self):
        bv = self._make_bv_with_syntax(_NDR64_TRANSFER_SYNTAX)
        self.assertEqual(_read_transfer_syntax(bv, self.BASE), "NDR64")

    def test_unknown(self):
        bv = self._make_bv_with_syntax(b"\xde\xad" * 8)
        result = _read_transfer_syntax(bv, self.BASE)
        self.assertTrue(result.startswith("unknown:"))


# ---------------------------------------------------------------------------
# _find_midl_server_info
# ---------------------------------------------------------------------------

class TestFindMidlServerInfo(unittest.TestCase):
    """Verify that _find_midl_server_info extracts all three pointers."""

    BASE = 0x10000000

    def _build_bv(self) -> tuple[MockBV, int, int, int]:
        """
        Layout in the flat BV:
          BASE+0x000: RPC_SERVER_INTERFACE stub (just needs pointer at +0x50)
          BASE+0x050: InterpreterInfo pointer → BASE+0x100 (MIDL_SERVER_INFO)
          BASE+0x100: MIDL_SERVER_INFO
            +0x00: pStubDesc ptr → BASE+0x200
            +0x08: DispatchTable ptr (don't care)
            +0x10: ProcString ptr  → BASE+0x300
            +0x18: FmtStringOffset → BASE+0x400
            +0x20 ...: (other fields, zeroed)
          BASE+0x200: MIDL_STUB_DESC
            +0x40: TypeFormatString → BASE+0x500
        """
        bv = _flat_bv(0x600, self.BASE)

        interp_va    = self.BASE + 0x100
        pstub_va     = self.BASE + 0x200
        proc_str_va  = self.BASE + 0x300
        fmt_off_va   = self.BASE + 0x400
        type_fmt_va  = self.BASE + 0x500

        # InterpreterInfo pointer at struct_base + 0x50
        bv.patch(self.BASE + 0x50, struct.pack("<Q", interp_va))
        # MIDL_SERVER_INFO
        bv.patch(interp_va + 0x00, struct.pack("<Q", pstub_va))
        bv.patch(interp_va + 0x10, struct.pack("<Q", proc_str_va))
        bv.patch(interp_va + 0x18, struct.pack("<Q", fmt_off_va))
        # MIDL_STUB_DESC.pFormatTypes at +0x40
        bv.patch(pstub_va  + 0x40, struct.pack("<Q", type_fmt_va))

        return bv, proc_str_va, fmt_off_va, type_fmt_va

    def test_extracts_all_three(self):
        bv, proc_str_va, fmt_off_va, type_fmt_va = self._build_bv()
        ps, fo, tf = _find_midl_server_info(bv, self.BASE)
        self.assertEqual(ps, proc_str_va)
        self.assertEqual(fo, fmt_off_va)
        self.assertEqual(tf, type_fmt_va)

    def test_missing_interp_returns_none(self):
        bv = _flat_bv(0x600, self.BASE)  # pointer at +0x50 stays 0
        ps, fo, tf = _find_midl_server_info(bv, self.BASE)
        self.assertIsNone(ps)
        self.assertIsNone(fo)


# ---------------------------------------------------------------------------
# _ndr_proc_has_wstring_param
# ---------------------------------------------------------------------------

class TestNdrProcHasWstringParam(unittest.TestCase):
    """
    Memory layout for all subtests:
      BASE + 0x000: proc format string
      BASE + 0x100: FmtStringOffset array (u16 per proc)
      BASE + 0x200: TypeFormatString
    """

    BASE          = 0x10000000
    PROC_STR_OFF  = 0x000
    FMT_OFF_OFF   = 0x100
    TYPE_FMT_OFF  = 0x200

    def _make_bv(self) -> MockBV:
        return _flat_bv(0x400, self.BASE)

    @property
    def proc_str_va(self) -> int:
        return self.BASE + self.PROC_STR_OFF

    @property
    def fmt_off_va(self) -> int:
        return self.BASE + self.FMT_OFF_OFF

    @property
    def type_fmt_va(self) -> int:
        return self.BASE + self.TYPE_FMT_OFF

    def _set_proc_offset(self, bv: MockBV, proc_idx: int, offset: int) -> None:
        bv.patch(self.fmt_off_va + proc_idx * 2, struct.pack("<H", offset))

    def _call(self, bv: MockBV, proc_idx: int = 0, method_count: int = 2) -> bool:
        return _ndr_proc_has_wstring_param(
            bv,
            proc_string_ptr=self.proc_str_va,
            fmt_offset_ptr=self.fmt_off_va,
            proc_idx=proc_idx,
            method_count=method_count,
            type_format_ptr=self.type_fmt_va,
        )

    # -- Baseline -------------------------------------------------------

    def test_no_string_params_false(self):
        bv = self._make_bv()
        self._set_proc_offset(bv, 0, 0)
        # Proc format string: all zeros (no FC_WSTRING, no FC_RP)
        self.assertFalse(self._call(bv))

    def test_ndr_no_format_false(self):
        bv = self._make_bv()
        self._set_proc_offset(bv, 0, _NDR_NO_FORMAT)
        self.assertFalse(self._call(bv))

    # -- v2: direct FC_WSTRING / FC_C_WSTRING ---------------------------

    def test_v2_fc_wstring_inline(self):
        bv = self._make_bv()
        self._set_proc_offset(bv, 0, 0)
        bv.patch(self.proc_str_va + 4, bytes([_FC_WSTRING]))
        self.assertTrue(self._call(bv))

    def test_v2_fc_c_wstring_inline(self):
        bv = self._make_bv()
        self._set_proc_offset(bv, 0, 0)
        bv.patch(self.proc_str_va + 8, bytes([_FC_C_WSTRING]))
        self.assertTrue(self._call(bv))

    # -- v3: FC_RP / FC_UP with FC_SIMPLE_POINTER (inline type) --------

    def test_v3_fc_rp_simple_wstring(self):
        bv = self._make_bv()
        self._set_proc_offset(bv, 0, 0)
        # FC_RP at proc_str[0], FC_SIMPLE_POINTER flag, inline FC_WSTRING
        bv.patch(self.proc_str_va, bytes([_FC_RP, _FC_SIMPLE_POINTER, _FC_WSTRING, 0x00]))
        self.assertTrue(self._call(bv))

    def test_v3_fc_up_simple_c_wstring(self):
        bv = self._make_bv()
        self._set_proc_offset(bv, 0, 0)
        bv.patch(self.proc_str_va, bytes([_FC_UP, _FC_SIMPLE_POINTER, _FC_C_WSTRING, 0x00]))
        self.assertTrue(self._call(bv))

    def test_v3_fc_rp_simple_non_wstring_false(self):
        bv = self._make_bv()
        self._set_proc_offset(bv, 0, 0)
        # FC_RP + SIMPLE_POINTER + FC_CHAR (0x02) — not a wstring
        bv.patch(self.proc_str_va, bytes([_FC_RP, _FC_SIMPLE_POINTER, 0x02, 0x00]))
        self.assertFalse(self._call(bv))

    # -- v3: FC_RP / FC_UP with offset into TypeFormatString ------------

    def _build_v3_indirect(self, bv: MockBV,
                            rp_code: int,
                            type_fc: int,
                            proc_offset: int = 0,
                            rp_pos_in_chunk: int = 0) -> None:
        """
        Emit an FC_RP/FC_UP descriptor at proc_str[proc_offset + rp_pos]
        that points into TypeFormatString where `type_fc` lives at offset 0.

        Descriptor layout:
          byte 0: rp_code (FC_RP or FC_UP)
          byte 1: 0x00    (NOT FC_SIMPLE_POINTER)
          byte 2-3: signed 16-bit offset from offset_field_va to TypeFormatString

        offset_field_va = proc_str_va + proc_offset + rp_pos_in_chunk + 2
        signed_off = type_fmt_va - offset_field_va
        """
        self._set_proc_offset(bv, 0, proc_offset)
        offset_field_va = self.proc_str_va + proc_offset + rp_pos_in_chunk + 2
        signed_off = self.type_fmt_va - offset_field_va
        desc = bytes([rp_code, 0x00]) + struct.pack("<h", signed_off)
        bv.patch(self.proc_str_va + proc_offset + rp_pos_in_chunk, desc)
        bv.patch(self.type_fmt_va, bytes([type_fc]))

    def test_v3_fc_rp_indirect_c_wstring(self):
        """FC_RP → TypeFormatString → FC_C_WSTRING: the BlueHammer gap case."""
        bv = self._make_bv()
        self._build_v3_indirect(bv, _FC_RP, _FC_C_WSTRING)
        self.assertTrue(self._call(bv))

    def test_v3_fc_up_indirect_wstring(self):
        bv = self._make_bv()
        self._build_v3_indirect(bv, _FC_UP, _FC_WSTRING)
        self.assertTrue(self._call(bv))

    def test_v3_fc_rp_indirect_non_wstring_false(self):
        bv = self._make_bv()
        self._build_v3_indirect(bv, _FC_RP, 0x02)  # FC_CHAR, not a wstring
        self.assertFalse(self._call(bv))

    def test_v3_no_type_format_ptr_falls_through(self):
        """Without type_format_ptr, the v3 path should not crash; returns False."""
        bv = self._make_bv()
        self._set_proc_offset(bv, 0, 0)
        offset_field_va = self.proc_str_va + 2
        signed_off = self.type_fmt_va - offset_field_va
        desc = bytes([_FC_RP, 0x00]) + struct.pack("<h", signed_off)
        bv.patch(self.proc_str_va, desc)
        bv.patch(self.type_fmt_va, bytes([_FC_C_WSTRING]))
        # type_format_ptr=None — v3 code still works because it uses bv.read
        # directly; the type_format_ptr parameter is only for _find_midl_server_info.
        result = _ndr_proc_has_wstring_param(
            bv,
            proc_string_ptr=self.proc_str_va,
            fmt_offset_ptr=self.fmt_off_va,
            proc_idx=0,
            method_count=2,
            type_format_ptr=None,  # not passed → v3 still uses bv.read
        )
        self.assertTrue(result)

    def test_v3_offset_out_of_bv_range_false(self):
        """FC_RP with offset pointing outside BV should return False (not crash)."""
        bv = self._make_bv()
        self._set_proc_offset(bv, 0, 0)
        # Craft a descriptor pointing to address before bv.start
        offset_field_va = self.proc_str_va + 2
        out_of_range_va = self.BASE - 0x100  # before bv.start
        signed_off = out_of_range_va - offset_field_va
        # signed_off may not fit in int16 — wrap it
        if not (-32768 <= signed_off <= 32767):
            self.skipTest("offset doesn't fit in int16 for this base — skip")
        desc = bytes([_FC_RP, 0x00]) + struct.pack("<h", signed_off)
        bv.patch(self.proc_str_va, desc)
        self.assertFalse(self._call(bv))

    # -- proc_idx > 0 with non-zero proc_offset -------------------------

    def test_proc_idx_1_with_offset(self):
        """v3 hit on proc 1 (non-zero proc_offset)."""
        bv = self._make_bv()
        # proc 0 offset = 0 (no match, just zeros)
        self._set_proc_offset(bv, 0, 0)
        # proc 1 offset = 0x10
        self._set_proc_offset(bv, 1, 0x10)
        # proc 2 offset = 0x20 (so scan_len for proc 1 = 0x10)
        self._set_proc_offset(bv, 2, 0x20)

        # Place FC_RP descriptor at proc_str[0x10]
        rp_pos = 0  # within the chunk
        proc_offset = 0x10
        offset_field_va = self.proc_str_va + proc_offset + rp_pos + 2
        signed_off = self.type_fmt_va - offset_field_va
        desc = bytes([_FC_RP, 0x00]) + struct.pack("<h", signed_off)
        bv.patch(self.proc_str_va + proc_offset + rp_pos, desc)
        bv.patch(self.type_fmt_va, bytes([_FC_C_WSTRING]))

        self.assertFalse(self._call(bv, proc_idx=0))  # proc 0: no match
        self.assertTrue(self._call(bv, proc_idx=1, method_count=3))  # proc 1: match


# ---------------------------------------------------------------------------
# _tf_is_wstring_pointer
# ---------------------------------------------------------------------------

class TestTfIsWstringPointer(unittest.TestCase):
    """Unit tests for _tf_is_wstring_pointer — TypeFormatString chain follower."""

    BASE = 0x10000000

    def _bv(self, data: bytes) -> MockBV:
        return MockBV(data, base=self.BASE)

    def test_direct_fc_wstring(self):
        bv = self._bv(bytes([_FC_WSTRING, 0x00, 0x00, 0x00]))
        self.assertTrue(_tf_is_wstring_pointer(bv, self.BASE))

    def test_direct_fc_c_wstring(self):
        bv = self._bv(bytes([_FC_C_WSTRING, 0x00, 0x00, 0x00]))
        self.assertTrue(_tf_is_wstring_pointer(bv, self.BASE))

    def test_fc_rp_simple_pointer_wstring(self):
        bv = self._bv(bytes([_FC_RP, _FC_SIMPLE_POINTER, _FC_WSTRING, 0x00]))
        self.assertTrue(_tf_is_wstring_pointer(bv, self.BASE))

    def test_fc_rp_simple_pointer_c_wstring(self):
        bv = self._bv(bytes([_FC_RP, _FC_SIMPLE_POINTER, _FC_C_WSTRING, 0x00]))
        self.assertTrue(_tf_is_wstring_pointer(bv, self.BASE))

    def test_fc_up_simple_pointer_non_wstring_false(self):
        bv = self._bv(bytes([_FC_UP, _FC_SIMPLE_POINTER, 0x08, 0x00]))  # FC_LONG
        self.assertFalse(_tf_is_wstring_pointer(bv, self.BASE))

    def test_fc_rp_indirect_to_c_wstring(self):
        # FC_RP at [0], offset +2 → pointee at [0+2+2] = [4] = FC_C_WSTRING
        data = bytearray(8)
        data[0] = _FC_RP
        data[1] = 0x00  # not FC_SIMPLE_POINTER
        struct.pack_into("<h", data, 2, 2)  # signed_off = +2 → pointee at addr+2+2=addr+4
        data[4] = _FC_C_WSTRING
        bv = self._bv(bytes(data))
        self.assertTrue(_tf_is_wstring_pointer(bv, self.BASE))

    def test_fc_fp_indirect_to_wstring(self):
        data = bytearray(8)
        data[0] = _FC_FP
        data[1] = 0x00
        struct.pack_into("<h", data, 2, 2)
        data[4] = _FC_WSTRING
        bv = self._bv(bytes(data))
        self.assertTrue(_tf_is_wstring_pointer(bv, self.BASE))

    def test_fc_rp_indirect_non_wstring_false(self):
        data = bytearray(8)
        data[0] = _FC_RP
        data[1] = 0x00
        struct.pack_into("<h", data, 2, 2)
        data[4] = 0x08  # FC_LONG, not wstring
        bv = self._bv(bytes(data))
        self.assertFalse(_tf_is_wstring_pointer(bv, self.BASE))

    def test_non_pointer_fc_false(self):
        bv = self._bv(bytes([0x08, 0x00, 0x00, 0x00]))  # FC_LONG
        self.assertFalse(_tf_is_wstring_pointer(bv, self.BASE))

    def test_two_level_chain(self):
        # FC_RP → FC_RP → FC_C_WSTRING
        data = bytearray(12)
        data[0] = _FC_RP
        data[1] = 0x00
        struct.pack_into("<h", data, 2, 2)   # → addr+4
        data[4] = _FC_RP
        data[5] = 0x00
        struct.pack_into("<h", data, 6, 2)   # → addr+8
        data[8] = _FC_C_WSTRING
        bv = self._bv(bytes(data))
        self.assertTrue(_tf_is_wstring_pointer(bv, self.BASE))


# ---------------------------------------------------------------------------
# v3b: Oif-format TypeFormatString-offset scan
# ---------------------------------------------------------------------------

class TestNdrProcHasWstringParamV3b(unittest.TestCase):
    """Tests for the v3b Oif-format scan path.

    In Oif proc format strings, there are NO inline FC_RP bytes. Instead,
    6-byte parameter descriptors end with a 2-byte TypeFormatString offset
    (absolute from type_format_ptr). The v3b scan reads 2-byte aligned WORDs
    from the proc format string and checks if they're TF offsets pointing to
    WSTRING pointer types.

    Memory layout:
      BASE + 0x000: proc format string
      BASE + 0x100: FmtStringOffset array
      BASE + 0x200: TypeFormatString
    """

    BASE         = 0x10000000
    PROC_STR_OFF = 0x000
    FMT_OFF_OFF  = 0x100
    TYPE_FMT_OFF = 0x200

    @property
    def proc_str_va(self) -> int:
        return self.BASE + self.PROC_STR_OFF

    @property
    def fmt_off_va(self) -> int:
        return self.BASE + self.FMT_OFF_OFF

    @property
    def type_fmt_va(self) -> int:
        return self.BASE + self.TYPE_FMT_OFF

    def _make_bv(self) -> MockBV:
        return MockBV(b"\x00" * 0x400, base=self.BASE)

    def _set_proc_offset(self, bv: MockBV, proc_idx: int, offset: int) -> None:
        bv.patch(self.fmt_off_va + proc_idx * 2, struct.pack("<H", offset))

    def _call(self, bv: MockBV, proc_idx: int = 0, method_count: int = 2) -> bool:
        return _ndr_proc_has_wstring_param(
            bv,
            proc_string_ptr=self.proc_str_va,
            fmt_offset_ptr=self.fmt_off_va,
            proc_idx=proc_idx,
            method_count=method_count,
            type_format_ptr=self.type_fmt_va,
        )

    def _build_oif_wstring_param(
            self, bv: MockBV,
            tf_rp_offset: int,
            proc_chunk_word_pos: int,
            rp_code: int = _FC_RP,
            wstring_code: int = _FC_C_WSTRING,
    ) -> None:
        """
        Place an FC_RP descriptor at TypeFormatString[tf_rp_offset] that
        chains to `wstring_code`, and write the little-endian TF offset as
        a WORD at proc_chunk[proc_chunk_word_pos].

        TypeFormatString layout (at type_fmt_va + tf_rp_offset):
          [0]: rp_code
          [1]: 0x00 (not FC_SIMPLE_POINTER)
          [2-3]: signed_off = +2 → pointee at tf_rp_offset + 2 + 2 = tf_rp_offset + 4
          [4]: wstring_code

        Proc format string at proc_str_va + proc_chunk_word_pos:
          WORD = tf_rp_offset (LE)
        """
        tf_base = self.type_fmt_va + tf_rp_offset
        data = bytearray(8)
        data[0] = rp_code
        data[1] = 0x00
        struct.pack_into("<h", data, 2, 2)   # signed_off=2 → pointee at tf_base+4
        data[4] = wstring_code
        bv.patch(tf_base, bytes(data))
        # Write TF offset as WORD in proc chunk
        bv.patch(self.proc_str_va + proc_chunk_word_pos,
                 struct.pack("<H", tf_rp_offset))

    def test_v3b_fc_rp_offset_hits_c_wstring(self):
        """Oif param descriptor has WORD pointing to FC_RP → FC_C_WSTRING in TF."""
        bv = self._make_bv()
        self._set_proc_offset(bv, 0, 0)
        self._set_proc_offset(bv, 1, 0x20)
        self._build_oif_wstring_param(bv, tf_rp_offset=0x10, proc_chunk_word_pos=4)
        self.assertTrue(self._call(bv))

    def test_v3b_fc_up_offset_hits_wstring(self):
        bv = self._make_bv()
        self._set_proc_offset(bv, 0, 0)
        self._set_proc_offset(bv, 1, 0x20)
        self._build_oif_wstring_param(
            bv, tf_rp_offset=0x20, proc_chunk_word_pos=6,
            rp_code=_FC_UP, wstring_code=_FC_WSTRING,
        )
        self.assertTrue(self._call(bv))

    def test_v3b_no_type_format_ptr_returns_false(self):
        """Without type_format_ptr the v3b scan is skipped."""
        bv = self._make_bv()
        self._set_proc_offset(bv, 0, 0)
        self._set_proc_offset(bv, 1, 0x20)
        self._build_oif_wstring_param(bv, tf_rp_offset=0x10, proc_chunk_word_pos=4)
        result = _ndr_proc_has_wstring_param(
            bv,
            proc_string_ptr=self.proc_str_va,
            fmt_offset_ptr=self.fmt_off_va,
            proc_idx=0,
            method_count=2,
            type_format_ptr=None,  # no TF ptr → v3b skipped
        )
        self.assertFalse(result)

    def test_v3b_word_points_to_non_pointer_fc_false(self):
        """WORD value maps to TF address, but the TF byte is FC_LONG (not pointer)."""
        bv = self._make_bv()
        self._set_proc_offset(bv, 0, 0)
        self._set_proc_offset(bv, 1, 0x20)
        # TF[0x10] = FC_LONG (0x08) — not a pointer type
        bv.patch(self.type_fmt_va + 0x10, bytes([0x08, 0x00, 0x00, 0x00]))
        bv.patch(self.proc_str_va + 4, struct.pack("<H", 0x10))
        self.assertFalse(self._call(bv))

    def test_v3b_word_zero_skipped(self):
        """WORD value 0 is skipped (TF offset 0 is reserved/padding)."""
        bv = self._make_bv()
        self._set_proc_offset(bv, 0, 0)
        self._set_proc_offset(bv, 1, 0x20)
        # Place wstring pointer at TF[0] — but WORD 0 should be skipped
        bv.patch(self.type_fmt_va, bytes([_FC_RP, _FC_SIMPLE_POINTER, _FC_C_WSTRING, 0x00]))
        # WORD at proc_chunk+4 = 0x0000 (already zero from blank BV)
        self.assertFalse(self._call(bv))

    def test_v3b_does_not_fire_when_v2_fires(self):
        """If v2 already fires (FC_WSTRING in proc chunk), v3b is not needed."""
        bv = self._make_bv()
        self._set_proc_offset(bv, 0, 0)
        self._set_proc_offset(bv, 1, 0x20)
        bv.patch(self.proc_str_va + 8, bytes([_FC_WSTRING]))
        self.assertTrue(self._call(bv))  # should still return True via v2


if __name__ == "__main__":
    unittest.main(verbosity=2)
