"""Unit tests for heap.py struct-field aliasing helpers.

Tests _load_to_base_offset, _extract_load_base_offset, _resolve_to_param_idx,
and _ptr_root using lightweight MLIL expression stubs — no Binary Ninja runtime.

These helpers support find_struct_field_double_free() which detects the pattern:
    callee(struct_t *p) { free(p->field); }
    caller()            { callee(&s); free(s.field); }  // double-free
"""
from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).parent.parent / "scripts"
if str(_SCRIPTS.parent) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS.parent))

# Stub heavy Binary Ninja imports so the module can be imported without it.
for _mod in ("binaryninja",):
    if _mod not in sys.modules:
        sys.modules[_mod] = types.ModuleType(_mod)

from scripts.analysis.heap import (
    _load_to_base_offset,
    _extract_load_base_offset,
    _resolve_to_param_idx,
    _ptr_root,
)


# ─────────────────────────────────────────────────────────────────
# MLIL stub objects
# ─────────────────────────────────────────────────────────────────

class _Var:
    """Minimal Binary Ninja Variable stub."""
    def __init__(self, ident: int, name: str = "v", is_stack: bool = False):
        self.identifier = ident
        self.name = name
        self.source_type = _StackST() if is_stack else _RegST()
        self.is_stack_variable = is_stack


class _StackST:
    name = "StackVariableSourceType"


class _RegST:
    name = "RegisterVariableSourceType"


class _SSAVar:
    """Minimal SSA variable stub."""
    def __init__(self, var: _Var, version: int = 0):
        self.var = var
        self.version = version

    def __str__(self):
        return f"{self.var.name}#{self.version}"


class _VarSsaExpr:
    """Wraps an SSAVar as a VarSsa expression (has .src that is the SSA var)."""
    def __init__(self, ssa_var: _SSAVar):
        self.src = ssa_var
        self._cls = "MediumLevelILVarSsa"

    def __class_getitem__(cls, item):
        return cls


class _Const:
    def __init__(self, value: int):
        self.constant = value


class _Add:
    def __init__(self, left, right):
        self.left = left
        self.right = right
        self._cls = "MediumLevelILAdd"


class _Sub:
    def __init__(self, left, right):
        self.left = left
        self.right = right
        self._cls = "MediumLevelILSub"


class _Load:
    def __init__(self, src):
        self.src = src
        self._cls = "MediumLevelILLoadSsa"


class _SetVar:
    """SSA definition: dst_ssa = src_expr."""
    def __init__(self, dst: _SSAVar, src):
        self.dest = dst
        self.src = src
        self._cls = "MediumLevelILSetVarSsa"


class _AddressOf:
    """AddressOf(stack_var)."""
    def __init__(self, var: _Var):
        self.src = var
        self._cls = "MediumLevelILAddressOf"


# Monkeypatch __name__ on stub classes so type(x).__name__ checks work
for _cls in (_VarSsaExpr, _Const, _Add, _Sub, _Load, _SetVar, _AddressOf):
    _cls.__name__ = _cls.__dict__.get("_cls", _cls.__name__)

# But instance attribute lookup shadows class for type(x).__name__, so set
# a real class name on the type object.
_Load.__name__ = "MediumLevelILLoadSsa"
_Add.__name__ = "MediumLevelILAdd"
_Sub.__name__ = "MediumLevelILSub"
_AddressOf.__name__ = "MediumLevelILAddressOf"
_SetVar.__name__ = "MediumLevelILSetVarSsa"
_VarSsaExpr.__name__ = "MediumLevelILVarSsa"


def _ssa_expr(var: _Var, version: int = 0) -> _VarSsaExpr:
    return _VarSsaExpr(_SSAVar(var, version))


# ─────────────────────────────────────────────────────────────────
# Stub function with controllable SSA def table
# ─────────────────────────────────────────────────────────────────

class _StubFunc:
    """Fake MLIL function that returns pre-canned SSA definitions."""
    def __init__(self, defs: dict = None):
        self._defs = defs or {}  # str(ssa_var) → _SetVar

    def get_ssa_var_definition(self, ssa_var):
        return self._defs.get(str(ssa_var))

    # Make _to_ssa_form happy
    def get_ssa_var_uses(self, *a):
        return []

    @property
    def source_function(self):
        return self


# Inject stub into _to_ssa_form path: if the object already has
# get_ssa_var_uses it's returned as-is.


# ─────────────────────────────────────────────────────────────────
# Tests: _load_to_base_offset
# ─────────────────────────────────────────────────────────────────

class TestLoadToBaseOffset(unittest.TestCase):

    def _make_ssa(self, ident=1):
        return _SSAVar(_Var(ident, "p"), 0)

    def test_direct_var_load(self):
        """Load(var) → (var, 0)"""
        ssa = self._make_ssa()
        load = _Load(_VarSsaExpr(ssa))
        result = _load_to_base_offset(load)
        self.assertIsNotNone(result)
        base, offset = result
        self.assertEqual(offset, 0)
        self.assertIs(base, ssa)

    def test_add_var_const(self):
        """Load(var + 8) → (var, 8)"""
        ssa = self._make_ssa()
        load = _Load(_Add(_VarSsaExpr(ssa), _Const(8)))
        base, offset = _load_to_base_offset(load)
        self.assertEqual(offset, 8)
        self.assertIs(base, ssa)

    def test_add_const_var(self):
        """Load(8 + var) → (var, 8)"""
        ssa = self._make_ssa()
        load = _Load(_Add(_Const(8), _VarSsaExpr(ssa)))
        base, offset = _load_to_base_offset(load)
        self.assertEqual(offset, 8)
        self.assertIs(base, ssa)

    def test_sub_var_const(self):
        """Load(var - 4) → (var, -4)"""
        ssa = self._make_ssa()
        load = _Load(_Sub(_VarSsaExpr(ssa), _Const(4)))
        base, offset = _load_to_base_offset(load)
        self.assertEqual(offset, -4)

    def test_none_input(self):
        self.assertIsNone(_load_to_base_offset(None))

    def test_no_src(self):
        class _NoSrc:
            pass
        _NoSrc.__name__ = "MediumLevelILLoadSsa"
        obj = _NoSrc()
        self.assertIsNone(_load_to_base_offset(obj))

    def test_non_load_no_src_returns_none(self):
        """Expression without .src attribute returns None."""
        class _NoAttr:
            pass
        _NoAttr.__name__ = "MediumLevelILLoadSsa"
        self.assertIsNone(_load_to_base_offset(_NoAttr()))


# ─────────────────────────────────────────────────────────────────
# Tests: _extract_load_base_offset
# ─────────────────────────────────────────────────────────────────

class TestExtractLoadBaseOffset(unittest.TestCase):

    def test_direct_load(self):
        """Direct Load expression is handled without func context."""
        ssa = _SSAVar(_Var(1, "p"), 0)
        load = _Load(_VarSsaExpr(ssa))
        result = _extract_load_base_offset(load)
        self.assertIsNotNone(result)
        self.assertEqual(result[1], 0)

    def test_named_field_via_def_chain(self):
        """free(e_name_var) where e_name_var = Load(base + 0) → follows def chain."""
        base_var = _Var(10, "base_ptr")
        base_ssa = _SSAVar(base_var, 0)
        # e_name is a named field var defined as Load(base_ptr + 0)
        field_var = _Var(20, "e_name")
        field_ssa = _SSAVar(field_var, 1)
        load_def = _Load(_VarSsaExpr(base_ssa))
        defn = _SetVar(field_ssa, load_def)
        func = _StubFunc({str(field_ssa): defn})
        result = _extract_load_base_offset(_VarSsaExpr(field_ssa), func=func)
        self.assertIsNotNone(result)
        got_base, got_offset = result
        self.assertEqual(got_offset, 0)
        self.assertIs(got_base, base_ssa)

    def test_no_func_context_returns_none_for_named_var(self):
        """Named var without func context returns None (can't walk defs)."""
        ssa = _SSAVar(_Var(1, "v"), 0)
        result = _extract_load_base_offset(_VarSsaExpr(ssa), func=None)
        self.assertIsNone(result)

    def test_none_input(self):
        self.assertIsNone(_extract_load_base_offset(None))


# ─────────────────────────────────────────────────────────────────
# Tests: _resolve_to_param_idx
# ─────────────────────────────────────────────────────────────────

class TestResolveToParamIdx(unittest.TestCase):

    def _make_params(self, n: int):
        return [_Var(100 + i, f"arg{i}") for i in range(n)]

    def test_direct_param(self):
        params = self._make_params(3)
        ssa = _SSAVar(params[1], 0)
        func = _StubFunc()
        idx = _resolve_to_param_idx(func, ssa, params)
        self.assertEqual(idx, 1)

    def test_non_param_returns_minus_one(self):
        params = self._make_params(2)
        other_var = _Var(999, "other")
        ssa = _SSAVar(other_var, 0)
        func = _StubFunc()
        idx = _resolve_to_param_idx(func, ssa, params)
        self.assertEqual(idx, -1)

    def test_param_via_def_chain(self):
        """param is re-assigned to another var; resolve via SSA defs."""
        params = self._make_params(2)
        param_ssa0 = _SSAVar(params[0], 0)
        derived_var = _Var(200, "e_ptr_copy")
        derived_ssa = _SSAVar(derived_var, 1)
        # derived_ssa#1 = param_ssa0
        defn = _SetVar(derived_ssa, _VarSsaExpr(param_ssa0))
        func = _StubFunc({str(derived_ssa): defn})
        idx = _resolve_to_param_idx(func, derived_ssa, params)
        self.assertEqual(idx, 0)

    def test_empty_params_returns_minus_one(self):
        ssa = _SSAVar(_Var(1), 0)
        self.assertEqual(_resolve_to_param_idx(_StubFunc(), ssa, []), -1)

    def test_none_ssa_returns_minus_one(self):
        params = self._make_params(1)
        self.assertEqual(_resolve_to_param_idx(_StubFunc(), None, params), -1)


# ─────────────────────────────────────────────────────────────────
# Tests: _ptr_root
# ─────────────────────────────────────────────────────────────────

class TestPtrRoot(unittest.TestCase):

    def test_direct_stack_var(self):
        """SSA var whose underlying Variable is a stack var → ('stack', id)."""
        stack_v = _Var(42, "e", is_stack=True)
        ssa = _SSAVar(stack_v, 0)
        root = _ptr_root(_StubFunc(), ssa)
        self.assertIsNotNone(root)
        self.assertEqual(root, ("stack", 42))

    def test_addressof_stack_via_def_chain(self):
        """Register var set to &stack_var → resolves to ('stack', stack_id)."""
        stack_v = _Var(55, "local_e", is_stack=True)
        reg_v = _Var(99, "rdi")
        reg_ssa = _SSAVar(reg_v, 0)
        addr_of = _AddressOf(stack_v)
        defn = _SetVar(reg_ssa, addr_of)
        func = _StubFunc({str(reg_ssa): defn})
        root = _ptr_root(func, reg_ssa)
        self.assertIsNotNone(root)
        self.assertEqual(root, ("stack", 55))

    def test_two_different_regs_same_stack_var_match(self):
        """Two registers both holding &same_stack_var have equal roots."""
        stack_v = _Var(77, "s", is_stack=True)
        rdi = _SSAVar(_Var(10, "rdi"), 0)
        rsi = _SSAVar(_Var(11, "rsi"), 0)
        defs = {
            str(rdi): _SetVar(rdi, _AddressOf(stack_v)),
            str(rsi): _SetVar(rsi, _AddressOf(stack_v)),
        }
        func = _StubFunc(defs)
        root_rdi = _ptr_root(func, rdi)
        root_rsi = _ptr_root(func, rsi)
        self.assertEqual(root_rdi, ("stack", 77))
        self.assertEqual(root_rsi, ("stack", 77))
        self.assertEqual(root_rdi, root_rsi)

    def test_different_stack_vars_differ(self):
        """Pointers to different stack vars must NOT match."""
        s1 = _Var(10, "s1", is_stack=True)
        s2 = _Var(20, "s2", is_stack=True)
        ssa1 = _SSAVar(s1, 0)
        ssa2 = _SSAVar(s2, 0)
        r1 = _ptr_root(_StubFunc(), ssa1)
        r2 = _ptr_root(_StubFunc(), ssa2)
        self.assertNotEqual(r1, r2)

    def test_fallback_reg_identity(self):
        """Non-stack register var falls back to ('reg', var_id)."""
        reg_v = _Var(88, "rcx")
        ssa = _SSAVar(reg_v, 2)
        root = _ptr_root(_StubFunc(), ssa)
        self.assertIsNotNone(root)
        self.assertEqual(root, ("reg", 88))

    def test_none_returns_none(self):
        self.assertIsNone(_ptr_root(_StubFunc(), None))


if __name__ == "__main__":
    unittest.main()
