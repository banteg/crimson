from __future__ import annotations

import importlib.util
import re
import struct
import sys
from collections import Counter
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


def test_slot_report_exposes_disagreement_about_an_aggregate_base(capsys):
    (frame,) = fp.decode(
        words(0xF0, 0x10)
        + name("_f")
        + words(0xF3, 0x10, 0, 0, 2)
        + obj(1, 4, 8, 8, 0, "_delta")
        + obj(2, 4, 4, 2, 1, "_angle")
        + words(0xF9),
    )
    result = ns.report(
        frame,
        {
            "names": {1: "_delta", 2: "_angle"},
            "native": {1: 0x14, 2: 0x18},
            "bottom": {1: 0x28, 2: 0x30},
            "votes": {1: Counter({0x14: 4, 0x04: 4}), 2: Counter({0x18: 2})},
            "tf": 0x110,
            "cf": 0x110,
            "unexplained": [],
        },
    )
    output = capsys.readouterr().out
    assert "_delta(0x28,w8,n4/8)" in output
    assert "_angle(0x30,w2,n2/2)" in output
    assert "_delta: 0x14: 4, 0x4: 4" in output
    assert "field +4" not in output
    assert result["split_votes"] == {"_delta": [{"base": 0x14, "votes": 4}, {"base": 0x04, "votes": 4}]}


@pytest.mark.parametrize("prefix", ("", "8b08", "8b08 53"))
def test_stack_refs_keep_frame_across_an_indirect_call(prefix):
    # Optional register load/save, fixed locals, one argument; the callee pops that argument.
    head = bytes.fromhex(prefix)
    body = bytes.fromhex("83ec18 6a01 ff5104 8b442408 83c418")
    saved = prefix.endswith("53")
    code = head + body + (b"\x5b" if saved else b"") + b"\xc3"
    frame = fp.stack_refs(code, 0, lambda _: None)
    body_depth = 24 + 4 * saved
    assert frame["frame_size"] == 24
    assert frame["body_depth"] == body_depth
    assert frame["depths"][len(head) + 8] == body_depth
    assert frame["refs"][0][1] == 8 - body_depth
    assert frame["depths"][len(code) - 1] == 0


def test_stack_refs_distinguish_frame_release_from_argument_cleanup():
    # The indirect callee pops its pushed argument; the following add releases locals.
    code = bytes.fromhex("8b08 83ec10 50 ff5104 83c410 c3")
    frame = fp.stack_refs(code, 0, lambda _: None)
    assert frame["frame_size"] == 16
    assert frame["depths"][9] == 16
    assert frame["depths"][len(code) - 1] == 0


def test_stack_refs_keep_stack_arguments_out_of_frame_size():
    # Reserve a 24-byte by-value argument, then push its argument index. Both
    # belong to the virtual call. The next call uses an ordinary pushed argument.
    code = bytes.fromhex("83ec18 892424 6a0f ff5114 50 ff5120 8b442404 c3")
    frame = fp.stack_refs(code, 0, lambda _: None)
    assert frame["frame_size"] == 0
    assert frame["body_depth"] == 0
    assert frame["depths"][11] == 0
    assert frame["refs"][-1][1] == 4


@pytest.mark.parametrize("saved,restore", [("53 8bdc", "8be3 5b"), ("55 8bec", "c9"), ("55 8bec", "8be5 5d")])
def test_stack_refs_restore_a_saved_frame_base(saved, restore):
    # D3DX uses EBX as the frame base for some SSE routines.
    prefix = bytes.fromhex(saved + " 83ec18")
    code = prefix + bytes.fromhex("8b442408 " + restore + " c3")
    frame = fp.stack_refs(code, 0, lambda _: None)
    assert frame["frame_size"] == 24
    assert frame["body_depth"] == 28
    assert frame["depths"][len(prefix)] == 28
    assert frame["depths"][len(code) - 1] == 0


def test_stack_refs_account_for_eh_prolog_before_the_fixed_allocation():
    # The VC6 helper replaces its own return slot with saved EBP and pushes
    # three registration words. The next direct call has a cdecl argument.
    code = bytes.fromhex("b834120000 e800000000 83ec18 53 6a01 e800000000 83c404 8b442408 5b c9 c3")
    frame = fp.stack_refs(code, 0, lambda insn: -16 if insn.address == 5 else 0)
    assert frame["frame_size"] == 24
    assert frame["body_depth"] == 44
    assert frame["refs"][-1][1] == 8 - 44
    assert frame["depths"][len(code) - 1] == 0


@pytest.mark.parametrize("pop", [0, None])
def test_stack_refs_keep_cdecl_cleanup_with_a_frame_buffer(pop):
    # Pass an address into the local buffer. The last add releases it along
    # with the pushed cdecl argument. An unknown direct call is handled too.
    code = bytes.fromhex("83ec10 8d0c24 51 e800000000 83c414 c3")
    frame = fp.stack_refs(code, 0, lambda _: pop)
    assert frame["frame_size"] == frame["body_depth"] == 16
    assert frame["depths"][12] == 20
    assert frame["depths"][len(code) - 1] == 0


def test_stack_refs_ignore_cdecl_by_value_space_with_combined_cleanup():
    # Passing the record itself (and a separate word) needs no local frame.
    code = bytes.fromhex("83ec10 8bc4 c70001000000 6a01 e800000000 83c414 c3")
    frame = fp.stack_refs(code, 0, lambda _: 0)
    assert frame["frame_size"] == 0
    assert frame["depths"][len(code) - 1] == 0


def test_stack_refs_find_locals_live_across_a_cdecl_call():
    # quest_build_fallback defers popping its arguments, then uses the stack
    # just above them for a temporary before releasing both ranges together.
    code = bytes.fromhex("83ec08 6a01 6a02 e800000000 89442408 83c410 c3")
    frame = fp.stack_refs(code, 0, lambda _: 0)
    assert frame["frame_size"] == frame["body_depth"] == 8
    assert frame["refs"][-1][1] == -8
    assert frame["depths"][len(code) - 1] == 0


def test_stack_refs_keep_frame_for_biased_ebp_and_leave():
    # C2 uses a biased EBP to reach more locals with an 8-bit displacement.
    code = bytes.fromhex("55 8d6c24b0 81ecb4000000 53 5b 83c550 c9 c3")
    assert fp.stack_refs(code, 0, lambda _: None)["frame_size"] == 0xb4


def test_stack_refs_account_for_inline_eh_record_in_combined_cleanup():
    # Entry ESP is E. The inline registration is [E-12, E), the 24-byte
    # local area is [E-36, E-12), and saved EBX is at E-40.
    code = bytes.fromhex(
        "64a100000000 6aff 8b0d00010000 684c332211 50 64892500000000 "
        "8b01 83ec18 53 6a01 ff5044 "
        "8b442404 8a44241b 8b4c241c 8b1424 5b 64890d00000000 83c424 c3",
    )
    frame = fp.stack_refs(code, 0, lambda _: None)
    assert frame["frame_size"] == 24
    assert frame["local_bottom_depth"] == 36
    assert frame["body_depth"] == frame["depths"][38] == 40
    # The first and last local bytes are retained. The saved FS link and EBX
    # are visible in raw references but excluded from native slot votes.
    assert [off for _, off, _ in frame["refs"]] == [-36, -13, -12, -40]
    assert list(fp.local_refs(frame)) == [(38, 0), (42, 23)]
    assert frame["depths"][len(code) - 1] == 0


@pytest.mark.parametrize("setup", ["33f6", "8bc8 33f6"])
def test_stack_refs_allow_register_initialization_before_an_indirect_cdecl_cleanup(setup):
    # Two arguments, an indirect cdecl call, then XOR ESI,ESI before its ADD.
    code = bytes.fromhex("6a01 6a02 ff51cc " + setup + " 83c408 8b442404 c3")
    frame = fp.stack_refs(code, 0, lambda _: None)
    assert frame["depths"][7] == 8
    assert frame["refs"][-1][1] == 4
    assert frame["depths"][len(code) - 1] == 0


@pytest.mark.parametrize("extra_arg", [False, True])
def test_stack_refs_keep_by_value_cdecl_arg_after_inline_eh_out_of_locals(extra_arg):
    # The original record and the 24-byte cdecl argument share the final ADD.
    # There is no intervening save or local buffer that lives across a call.
    call = "53 89442404 e800000000 83c404" if extra_arg else "892424 e800000000"
    code = bytes.fromhex(
        "64a100000000 6aff 684c332211 50 64892500000000 "
        "83ec18 " + call + " 8b4c2418 64890d00000000 83c424 c3",
    )
    frame = fp.stack_refs(code, 0, lambda _: 0)
    assert frame["frame_size"] == 0
    assert frame["depths"][len(code) - 1] == 0


def test_stack_refs_keep_inline_eh_without_locals_across_an_indirect_call():
    code = bytes.fromhex(
        "64a100000000 6aff 684c332211 50 64892500000000 "
        "6a01 ff5104 8b0c24 64890d00000000 83c40c c3",
    )
    frame = fp.stack_refs(code, 0, lambda _: None)
    assert frame["frame_size"] == 0
    assert frame["body_depth"] == 12
    assert frame["refs"][-1][1] == -12
    assert list(fp.local_refs(frame)) == []
    assert frame["depths"][len(code) - 1] == 0
