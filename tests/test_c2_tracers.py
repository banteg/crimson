from __future__ import annotations

import importlib.util
import re
import struct
import sys
from pathlib import Path

import pytest

from crimson_re import match_c2 as c2


def load(name: str):
    """A scripts/c2 tracer, registered under its own name so its sibling imports share it."""
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / "scripts" / "c2" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fp = load("frame_predict")
ns = load("native_slots")
pt = load("priority_trace")

# Observer macros come from the layout tables; anything else upper-case is C or Win32.
C_NAMES = {"HOOK_COUNT", "INVOKE_RVA", "BUMP_VALUE", "BUMP_BONUS", "DECISIONS", "DECISION_BASE", "MAX_NODES"}


def macros_used(text: str) -> set[str]:
    """Upper-case names with an underscore, and every global read through G(...)."""
    names = set(re.findall(r"\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b", text)) | set(re.findall(r"\bG\(([A-Z]\w*)\)", text))
    return {name for name in names if not name.startswith(("WIN", "INVALID_"))}


@pytest.mark.parametrize("compiler", sorted(pt.LAYOUTS))
def test_priority_observer_defines_every_field_it_reads(compiler, monkeypatch):
    monkeypatch.setattr(c2, "invoke_rva", lambda: 0x57444)
    pt.observer_source(compiler, 0, 0)(pt.profile(compiler))
    assert macros_used(pt.EXTRA) - C_NAMES <= set(pt.LAYOUTS[compiler].fields)


@pytest.mark.parametrize("compiler", sorted(fp.LAYOUTS))
def test_frame_observer_defines_every_field_it_reads(compiler, monkeypatch):
    monkeypatch.setattr(c2, "invoke_rva", lambda: 0x57444)
    fp.observer_source(compiler)
    used = macros_used(fp.OBSERVER) - C_NAMES - {"GENERIC_WRITE", "CREATE_ALWAYS", "PAGE_EXECUTE_READWRITE"}
    assert used <= set(fp.LAYOUTS[compiler].fields)
    assert {role for role, *_ in fp.LAYOUTS[compiler].hooks} == set(fp.ROLES)


def test_decision_hooks_only_exist_in_8966(monkeypatch):
    monkeypatch.setattr(c2, "invoke_rva", lambda: 0x57444)
    base = len(fp.LAYOUTS["msvc6.5"].hooks)
    assert f"DECISION_BASE {base}" in fp.observer_source("msvc6.5", decisions=True)
    with pytest.raises(ValueError, match="8966"):
        fp.observer_source("msvc6.5pp", decisions=True)


def event(phase: int, *lines: str) -> str:
    return f"EVENT {phase} fn=1\n" + "".join(line + "\n" for line in lines) + "END\n"


def test_priority_report_prints_order_and_per_block_contributions(tmp_path, capsys):
    blocks = ("BLK n=1 p=a0 d=0 in= out=7, ref=7,", "BLK n=2 p=b0 d=1 in=7, out= ref=7,")
    cursor = "LR id=7 p=c sym=89 cls=3 prio={} ben={} refs=4 tie=36 reg={} fb=a0 lb=b0 allowed={}"
    delta = "LR id=9 p=d sym=873 cls=3 prio=20 ben=5 refs=3 tie=41 reg=1 fb=a0 lb=a0 allowed=1,"
    trace = (
        event(0)
        + event(1)
        + event(6, "BS n=1 d=0 : 7=0/0 9=0/0")
        + event(6, "BS n=2 d=1 : 7=12/3 9=20/5")
        + event(101, *blocks, cursor.format(30, 7, 0, "7,8,"), delta)
        + event(3, cursor.format(30, 7, 0, "6,7,8,"))
        + event(103, cursor.format(30, 7, 7, ""))
    )
    (tmp_path / "observed").mkdir()
    (tmp_path / "observed/phases.bin").write_bytes(trace.encode("latin-1"))
    pt.report(tmp_path, set(), {"89"}, set())
    out = capsys.readouterr().out
    assert re.search(r"#1 +lr +7 sym #89 c3 +prio +30 tie +36 blocks 1\.\.2 +allowed ebp,esi,edi +-> esi", out)
    assert re.search(r"block +1 depth 0: prio \+12 +benefit \+3", out)
    assert re.search(r"block +2 depth 1: prio \+18 +benefit \+4", out)
    assert "lr9" not in out


def words(*values: int) -> bytes:
    return struct.pack(f"<{len(values)}I", *(v & 0xFFFFFFFF for v in values))


def name(text: str) -> bytes:
    return text.encode().ljust(64, b"\0")


def obj(ptr: int, cls: int, size: int, weight: int, index: int, label: str) -> bytes:
    fields = [ptr, cls, 0, 0, 0, 0x1004, index, size, 0, weight, index, 0, 0, 0, 0, size, cls, 0, 0, index]
    return words(0xF2, *fields) + name(label) + words(0)


def test_slot_order_reports_frame_order_and_packing_positions(capsys):
    # One parameter, then three locals the density sort reorders: packed a, b, c; sorted b, a, c.
    data = (
        words(0xF0, 0x10)
        + name("_f")
        + words(0xF3, 0x10, 0, 1, 4)
        + obj(0x100, 5, 4, 1, 0, "_p")
        + obj(0x200, 4, 4, 3, 1, "_a")
        + obj(0x300, 4, 4, 5, 2, "_b")
        + obj(0x400, 4, 8, 2, 3, "_c")
        + words(0xF9)
        + words(0xF8, 1, 3, 4, 3, 1, 1, 4, 5, 1, 2, 8, 2, 1, 3)
        + words(0xF4, -16, 4, 4, 1, 4, 1, 0, 4, 5, 0, 1, 2, 4, 3, 0, 1, 1, 8, 2, 0, 1, 3)
        + words(0x100, 4, 0, 0x200, -8, 0, 0x300, -4, 0, 0x400, -16, 0, 0xF9)
        + words(0xF5, 0x10, 0x10)
    )
    (frame,) = fp.decode(data)
    assert frame.local_bytes == 16
    names = {o.ptr: o.name + "$" for o in frame.objects}
    bottom = {o.ptr: o.offset + 0x10 for o in frame.objects if o.cls != 5}
    rows = ns.slot_order(frame, {"names": names, "native": {0x300: 0xC}, "bottom": bottom})
    assert [(row["members"], row["packed"]) for row in rows] == [
        (["_p$"], None),
        (["_b$"], 2),
        (["_a$"], 1),
        (["_c$"], 3),
    ]
    assert [row["density"] for row in rows[1:]] == [1250, 750, 250]
    assert "_b$ (0xc)" in capsys.readouterr().out
