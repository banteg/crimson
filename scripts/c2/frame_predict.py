"""Report and predict VC6 C2 stack-frame layout for a scratch.

Runs the scratch through the pinned msvc6.5 C2 with an observer on the stack
layout pass (stack.c), records the compiler's own stack objects, reference
counts, interference sets, slots and offsets, then re-simulates the packer in
Python and checks that the simulation reproduces every offset. A pure-source
reference estimate is shown next to the compiler's weight for named locals.

    uv run python scripts/c2/frame_predict.py tools/match/scratches/<name> --out /tmp/<new-dir>
    uv run python scripts/c2/frame_predict.py <scratch> --out <dir> --source variant.cpp --json out.json

Diagnostic only: no compiler decision is changed and no match credit is earned.
See tools/match/c2/compiler/frame-model.md.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import struct
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path

from crimson import match
from crimson import match_c2 as c2
from crimson import match_c2_replay as replay

# (site RVA, target RVA, return hook) for C2.DLL 12.00.8966, image base 0x10700000.
HOOKS = (
    (0x583FC, 0x33B7B, False),  # 0 compile_functions -> stack_frame_layout_pass (ecx = function)
    (0x33EDA, 0x3C7E4, False),  # 1 count refs: source operand -> order_stack_object
    (0x33F7C, 0x3C7E4, False),  # 2 count refs: destination operand
    (0x93CC0, 0x3C7E4, False),  # 3 count refs: call alias-set member, source side
    (0x93D2A, 0x3C7E4, False),  # 4 count refs: call alias-set member, destination side
    (0x33CDE, 0x4B617, True),  # 5 pack_frame_locals -> pack_stack_slots
    (0x5842F, 0x3404F, False),  # 6 compile_functions -> generate_prolog_epilog (frame size known)
)
REF_KIND = {1: "src", 2: "dst", 3: "src-alias", 4: "dst-alias"}
# Optional allocator decision hooks (--decisions): (site, target, return hook, label, register holding the range).
# pushad order in the observer: edi 0, esi 1, ebp 2, esp 3, ebx 4, edx 5, ecx 6, eax 7.
DECISION_HOOKS = (
    (0x3094B, 0x1F578, False, "forward-substituted", 5),  # forward_substitute_single_def_ranges
    (0x5277C, 0x1F578, False, "rematerialized-defs", 5),  # rematerialize_candidate_definitions
    (0x6A6CC, 0x1F578, False, "rematerialized-range", 5),  # try_rematerialize_live_range
    (0x8EF73, 0x1F578, False, "substituted-before-colour", 5),  # try_substitute_before_colouring
    (0x25B74, 0x25EED, False, "demoted-low-use", 5),  # prune_low_use_live_ranges
    (0x3207B, 0x25EED, False, "demoted-unprofitable", 5),  # handle_unprofitable_live_range
    (0x320EE, 0x43722, False, "split-at-block-entries", 6),
    (0x32108, 0x43722, False, "split-at-block-entries", 6),
    (0x2FE5F, 0x32F7C, True, "coloured", 6),  # choose_register_for_live_range; return reads esi
    (0x3091C, 0x31A50, True, "substitution base check", 1),  # has_intervening_base_definition, esi = range
    (0x3097D, 0x31A50, True, "substitution index check", 1),
    (0x2FBBD, 0x306C1, False, "substitution input", -1),  # dump every named-range operand before 0x306c1
)

OBSERVER = r"""
#include <windows.h>
#include "replay_settings.h"
typedef int (__stdcall *invoke_t)(int, char **, void *);
typedef BOOL (__stdcall *protect_t)(LPVOID, DWORD, DWORD, PDWORD);
static HANDLE out;
static unsigned char *base;
static unsigned long targets[HOOK_COUNT], returns[HOOK_COUNT], active[HOOK_COUNT];
#define G(rva) (*(unsigned long *)(base + (rva)))
static void put(const void *data, unsigned long size)
{
    DWORD written;
    if (!WriteFile(out, data, size, &written, 0) || written != size) ExitProcess(79);
}
static void word(unsigned long v) { put(&v, 4); }
static void text(const char *s)
{
    char buf[64];
    unsigned long i;
    for (i = 0; i < 64; ++i) buf[i] = 0;
    for (i = 0; s && i < 63 && s[i]; ++i) buf[i] = s[i];
    put(buf, 64);
}
static void bits(unsigned long *set)
{
    unsigned long *chunk, n = 0, b;
    for (chunk = set ? (unsigned long *)set[0] : 0; chunk; chunk = (unsigned long *)chunk[1])
        for (b = 0; b < 32; ++b) if (chunk[2] & (1ul << b)) ++n;
    word(n);
    for (chunk = set ? (unsigned long *)set[0] : 0; chunk; chunk = (unsigned long *)chunk[1])
        for (b = 0; b < 32; ++b) if (chunk[2] & (1ul << b)) word(chunk[0] + b);
}
static void object(unsigned long *s)
{
    unsigned char *b = (unsigned char *)s;
    unsigned char *fe = (unsigned char *)s[0];
    word(0xF2); word((unsigned long)s); word(b[4]); word(b[5]); word(b[6]); word(b[7]);
    word(*(unsigned short *)(b + 0x10)); word(s[0x1c / 4]); word(s[0x20 / 4]); word(s[0x24 / 4]);
    word(s[0x34 / 4]); word(s[0x38 / 4]); word((unsigned long)fe);
    word(fe ? *(unsigned long *)(fe + 0x14) : 0); word(fe ? *(unsigned long *)(fe + 0x36) : 0);
    word(fe ? *(unsigned long *)(fe + 0x0c) : 0); word(fe ? *(unsigned long *)(fe + 0x10) : 0);
    word(fe ? fe[4] : 0); word(fe ? fe[0x30] : 0); word(fe ? fe[0x31] : 0); word(fe ? *(unsigned long *)(fe + 0x28) : 0);
    text(fe ? *(char **)(fe + 0x18) : 0);
}
#ifdef DECISIONS
static void dump_named_operands(unsigned char *fn)
{
    unsigned char *t = *(unsigned char **)(**(unsigned char ***)(fn + 8) + 0x1c), *op, *lr, *sym, *fe;
    unsigned long n = 0, side;
    for (; t; t = *(unsigned char **)t, ++n) {
        if (!(t[9] & 1)) continue;
        for (side = 0; side < 2; ++side)
            for (op = *(unsigned char **)(t + 0x18 + side * 4); op; op = *(unsigned char **)op) {
                if (op[8] != 1) continue;
                lr = *(unsigned char **)(op + 0x18);
                if (!lr || lr[4] != 2) continue;
                sym = *(unsigned char **)lr;
                fe = sym ? *(unsigned char **)sym : 0;
                if (!fe || !*(char **)(fe + 0x18)) continue;
                word(0xF7); word(n); word(*(unsigned short *)(t + 0x10)); word(*(unsigned long *)(t + 4)); word(t[8]);
                word(side); word(op[0x10]); word((unsigned long)lr); text(*(char **)(fe + 0x18));
            }
    }
}
/* c2_live_range: +0 symbol, +5/+6 flags, +0xc priority, +0x10 register, +0x24 refs, +0x38 def, +0x3c benefit */
static void decision(unsigned long phase, unsigned long *lr, unsigned long result)
{
    unsigned char *sym = (unsigned char *)lr[0];
    unsigned char *fe = sym ? *(unsigned char **)sym : 0;
    unsigned char *def = (unsigned char *)lr[0x38 / 4];
    word(0xF6); word(phase); word((unsigned long)lr); word((unsigned long)sym); word(sym ? sym[4] : 0);
    word(sym ? *(unsigned short *)(sym + 0x10) : 0); word(def ? *(unsigned short *)(def + 0x10) : 0);
    word(def ? *(unsigned long *)(def + 4) : 0); word(lr[0x3c / 4]); word(lr[0xc / 4]); word(lr[0x24 / 4]);
    word(((unsigned char *)lr)[5] | (((unsigned char *)lr)[6] << 8)); word(lr[0x10 / 4] ? lr[0x10 / 4] - (unsigned long)base : 0);
    word(result);
    text(fe ? *(char **)(fe + 0x18) : 0);
}
#endif
static void __cdecl observe(unsigned long phase, unsigned long *r)
{
    unsigned long *s, i, n;
    unsigned char *t, *fn;
    if (phase == 0) {
        fn = (unsigned char *)r[6];
        word(0xF0); word(*(unsigned long *)(fn + 0x34));
        text(*(char **)(*(unsigned char **)fn + 0x18));
    } else if (phase >= 1 && phase <= 4) {
        t = (unsigned char *)r[4];
        s = (unsigned long *)r[10 + 4];
        word(0xF1); word(phase); word(r[6]); word((unsigned long)t); word(t[8]); word(*(unsigned long *)(t + 4));
        word(*(unsigned short *)(t + 0x10)); word(*(unsigned char *)(r[2] + 8));
        word(s ? (unsigned long)s : 0); word(s ? *(short *)((unsigned char *)s + 0x6e) : 0);
        word(s ? *(short *)((unsigned char *)s + 0x6c) : 0);
    } else if (phase == 5) {
        fn = (unsigned char *)r[6];
        word(0xF3); word(*(unsigned long *)(fn + 0x34)); word(r[5]); word(G(0x9F21C)); word(G(0x9F20C));
        for (s = (unsigned long *)G(0x9F220); s; s = (unsigned long *)s[0x2c / 4]) {
            object(s);
            bits(((unsigned long **)G(0x9F204))[s[0x38 / 4]]);
        }
        word(0xF9);
    } else if (phase == 105) {
        word(0xF4); word(G(0x9F1FC)); word(G(0xAC108)); n = G(0x9F224); word(n);
        for (i = 0; i < n; ++i) {
            s = (unsigned long *)(G(0x9F228) + i * 0x14);
            word(s[2]); word(s[3]); word(s[4]); bits((unsigned long *)s[0]);
        }
        for (s = (unsigned long *)G(0x9F220); s; s = (unsigned long *)s[0x2c / 4]) {
            word((unsigned long)s);
            word(((unsigned char *)s)[4] == 4 || ((unsigned char *)s)[4] == 5 ? *(unsigned long *)((unsigned char *)s[0] + 0xc) : s[0x28 / 4]);
            word(((unsigned char *)s)[5]);
        }
        word(0xF9);
    } else if (phase == 6) {
        fn = (unsigned char *)r[6];
        word(0xF5); word(*(unsigned long *)(*(unsigned char **)fn + 0x5b)); word(*(unsigned long *)(fn + 0x34));
    }
#ifdef DECISIONS
    else if (phase >= 7 && phase < 100 && decision_reg[phase - 7] < 0) dump_named_operands((unsigned char *)r[6]);
    else if (phase >= 7 && phase < 100) decision(phase, (unsigned long *)r[decision_reg[phase - 7]], 0);
    else if (phase >= 107) decision(phase, (unsigned long *)r[1], r[7]);
#endif
}
/* HOOKS */
void __stdcall start(void)
{
    HMODULE module;
    invoke_t invoke;
    protect_t protect;
    unsigned char *site;
    unsigned long i;
    DWORD old;
    int result;
    if (!LoadLibraryA(pdb_path)) ExitProcess(90);
    module = LoadLibraryA(backend_path);
    if (!module) ExitProcess(91);
    invoke = (invoke_t)GetProcAddress(module, "_InvokeCompilerPass@12");
    if (!invoke) ExitProcess(92);
    base = (unsigned char *)invoke - INVOKE_RVA;
    protect = (protect_t)GetProcAddress(LoadLibraryA("kernel32.dll"), "VirtualProtect");
    out = CreateFileA("frame.bin", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    if (out == INVALID_HANDLE_VALUE) ExitProcess(94);
    for (i = 0; i < HOOK_COUNT; ++i) {
        site = base + sites[i];
        targets[i] = (unsigned long)base + offsets[i];
        if (site[0] != 0xe8 || (unsigned long)(site + 5) + *(long *)(site + 1) != targets[i]) ExitProcess(95);
        if (!protect(site, 5, PAGE_EXECUTE_READWRITE, &old)) ExitProcess(96);
        *(long *)(site + 1) = (long)hooks[i] - (long)site - 5;
    }
    result = invoke(sizeof(arguments) / sizeof(arguments[0]), arguments, 0);
    CloseHandle(out);
    ExitProcess(result);
}
"""


def hook_source(hooks) -> str:
    """Naked callsite wrappers (same shape as match_c2.observer_source, own phase numbering)."""
    out = [f"#define HOOK_COUNT {len(hooks)}", "#define INVOKE_RVA 357444"]
    wrappers = []
    for index, (_, _, ret) in enumerate(hooks):
        slot = index * 4
        body = f" pushfd\n pushad\n mov eax,esp\n push eax\n push {index}\n call observe\n add esp,8\n"
        if ret:
            body += (
                f" popad\n popfd\n push eax\n mov eax,dword ptr [esp+4]\n mov dword ptr [returns+{slot}],eax\n"
                f" mov dword ptr [esp+4],offset after_{index}\n pop eax\n jmp dword ptr [targets+{slot}]\n"
                f" after_{index}:\n pushfd\n pushad\n mov eax,esp\n push eax\n push {index + 100}\n call observe\n"
                f" add esp,8\n popad\n popfd\n jmp dword ptr [returns+{slot}]\n"
            )
        else:
            body += f" popad\n popfd\n jmp dword ptr [targets+{slot}]\n"
        wrappers.append(f"__declspec(naked) static void phase_{index}(void) {{\n __asm {{\n{body} }}\n}}")
    arrays = [
        "static unsigned long sites[] = {" + ",".join(str(h[0]) for h in hooks) + "};",
        "static unsigned long offsets[] = {" + ",".join(str(h[1]) for h in hooks) + "};",
        "static void (*hooks[])(void) = {" + ",".join(f"phase_{i}" for i in range(len(hooks))) + "};",
    ]
    return "\n".join(out), "\n".join(wrappers + arrays)


def observer_source(decisions: bool = False) -> str:
    hooks = HOOKS + tuple(h[:3] for h in DECISION_HOOKS) if decisions else HOOKS
    defines, wrappers = hook_source(hooks)
    if decisions:
        regs = ",".join(str(h[4]) for h in DECISION_HOOKS)
        defines += f"\n#define DECISIONS 1\nstatic const long decision_reg[] = {{{regs}}};"
    return defines + OBSERVER.replace("/* HOOKS */", wrappers)


# ---------------------------------------------------------------- decoding


@dataclass
class Obj:
    ptr: int
    cls: int
    f5: int
    f6: int
    f7: int
    type: int
    id: int
    size: int
    part_offset: int
    weight: int
    index: int
    fe: int
    fe_flags14: int
    fe_storage: int
    fe_offset: int
    fe_size: int
    fe_cls: int
    fe_30: int
    fe_31: int
    fe_id: int
    name: str
    interf: list[int]
    offset: int = 0
    f5_after: int = 0
    refs: list[dict] = field(default_factory=list)


@dataclass
class Frame:
    name: str
    flags: int
    fpo_arg: int = 0
    param_slots: int = 0
    objects: list[Obj] = field(default_factory=list)
    slots: list[dict] = field(default_factory=list)
    local_bytes: int = 0
    cursor: int = 0
    frame_size: int = 0
    refs: list[dict] = field(default_factory=list)
    decisions: list[dict] = field(default_factory=list)
    range_operands: list[dict] = field(default_factory=list)


def s32(v: int) -> int:
    return v - (1 << 32) if v & 0x80000000 else v


def decode(data: bytes) -> list[Frame]:
    at = 0
    frames: list[Frame] = []
    pending: list[dict] = []
    pending_uses: list[dict] = []

    def w() -> int:
        nonlocal at
        (v,) = struct.unpack_from("<I", data, at)
        at += 4
        return v

    def txt() -> str:
        nonlocal at
        raw = data[at : at + 64]
        at += 64
        return raw.split(b"\0", 1)[0].decode("latin1")

    def bitlist() -> list[int]:
        return [w() for _ in range(w())]

    while at < len(data):
        tag = w()
        if tag == 0xF0:
            flags = w()
            frames.append(Frame(name=txt(), flags=flags, decisions=pending, range_operands=pending_uses))
            pending, pending_uses = [], []
        elif tag == 0xF1:
            keys = ("site", "obj", "tuple", "tuple_kind", "opcode", "line", "operand_kind", "block", "depth", "bindex")
            ref = dict(zip(keys, [w() for _ in keys], strict=True))
            ref["kind"] = REF_KIND[ref.pop("site")]
            frames[-1].refs.append(ref)
        elif tag == 0xF3:
            fr = frames[-1]
            fr.flags, fr.fpo_arg, fr.param_slots, _count = w(), w(), w(), w()
            while (tag := w()) != 0xF9:
                assert tag == 0xF2, hex(tag)
                vals = [w() for _ in range(20)]
                fr.objects.append(Obj(*vals, name=txt(), interf=bitlist()))
                fr.objects[-1].part_offset = s32(fr.objects[-1].part_offset)
                fr.objects[-1].fe_offset = s32(fr.objects[-1].fe_offset)
        elif tag == 0xF4:
            fr = frames[-1]
            fr.local_bytes, fr.cursor = w(), s32(w())
            for _ in range(w()):
                size, weight, offset = w(), w(), s32(w())
                fr.slots.append({"size": size, "weight": weight, "offset": offset, "members": bitlist()})
            by_ptr = {o.ptr: o for o in fr.objects}
            while (ptr := w()) != 0xF9:
                o = by_ptr[ptr]
                o.offset, o.f5_after = s32(w()), w()
        elif tag == 0xF5:
            frames[-1].frame_size, frames[-1].flags = w(), w()
        elif tag == 0xF6:
            keys = (
                "phase",
                "lr",
                "sym",
                "cls",
                "type",
                "line",
                "opcode",
                "benefit",
                "priority",
                "refs",
                "flags",
                "reg",
                "result",
            )
            d = dict(zip(keys, [w() for _ in keys], strict=True))
            d["name"] = txt()
            ph = d["phase"] % 100
            d["event"] = DECISION_HOOKS[ph - len(HOOKS)][3]
            if d["phase"] >= 100:
                d["event"] += " (register chosen)" if d["event"] == "coloured" else f" -> {d['result']}"
            d["benefit"], d["priority"] = s32(d["benefit"]), s32(d["priority"])
            pending.append(d)
        elif tag == 0xF7:
            keys = ("tuple", "line", "opcode", "kind", "side", "flags10", "lr")
            d = dict(zip(keys, [w() for _ in keys], strict=True))
            d["name"] = txt()
            pending_uses.append(d)
        else:
            raise ValueError(f"bad record {tag:#x} at {at - 4}")
    for fr in frames:
        by_ptr = {o.ptr: o for o in fr.objects}
        for ref in fr.refs:
            if ref["obj"] in by_ptr:
                by_ptr[ref["obj"]].refs.append(ref)
    return frames


# ---------------------------------------------------------------- model


def ref_order(refs: list[tuple[int, int, int]]) -> list[tuple[int, int]]:
    """Replay order_stack_object: refs are (object key, size, 1) in walk order; returns [(key, weight)]."""
    order: list[list[int]] = []  # [key, size, weight]
    for key, size, inc in refs:
        pos = next((i for i, e in enumerate(order) if e[0] == key), None)
        if pos is None:
            i = 0
            while i < len(order) and order[i][1] <= size:
                i += 1
            order.insert(i, [key, size, inc])
            continue
        order[pos][2] += inc
        weight = order[pos][2]
        j = pos - 1
        while j >= 0 and order[j][2] < weight and order[j][1] == size:
            j -= 1
        if j != pos - 1:
            order.insert(j + 1, order.pop(pos))
    return [(e[0], e[2]) for e in order]


def density_sort(slots: list[dict], lo: int, hi: int) -> None:
    """sort_stack_slots_by_density 0x10761bf0: K&R quicksort, middle pivot, strict >, descending."""

    def dens(s: dict) -> int:
        return int(s["weight"] * 1000 / s["size"])  # idiv truncates toward zero

    while lo < hi:
        mid = (lo + hi) // 2 if lo + hi >= 0 else -((-(lo + hi)) // 2)
        slots[lo], slots[mid] = slots[mid], slots[lo]
        last = lo
        for i in range(lo + 1, hi + 1):
            if dens(slots[i]) > dens(slots[lo]):
                last += 1
                slots[last], slots[i] = slots[i], slots[last]
        slots[lo], slots[last] = slots[last], slots[lo]
        density_sort(slots, lo, last - 1)
        lo = last + 1


def align(off: int, size: int, default: int = 4) -> int:
    if size == 1:
        return off
    if size == 2:
        return (off + 1) & ~1
    return (off + default - 1) & ~(default - 1)


def simulate(objs: list[dict], *, fpo: bool, param_reuse: bool, aligned: bool = False) -> dict:
    """pack_stack_slots 0x1074b617 on objects in list order.

    objs: dicts with key, cls, size, weight, type, interf (set of keys), all_conflict, param_offset.
    Returns the slots in final order, each object's frame offset, local bytes and the pre-sort order.
    """
    keys = {o["key"] for o in objs}
    interf = {o["key"]: (keys - {o["key"]}) if o["all_conflict"] else o["interf"] for o in objs}

    def fits(o: dict, s: dict, limit: int) -> bool:
        return (
            o["size"] <= limit
            and o["key"] not in s["interf"]
            and not (interf[o["key"]] & {m["key"] for m in s["members"]})
        )

    def run(with_params: bool, reuse: bool):
        slots = []
        if with_params:
            for o in objs:
                if o["cls"] == 5:
                    slots.append(
                        {
                            "members": [o],
                            "interf": set(interf[o["key"]]),
                            "size": (o["size"] + 3) & ~3,
                            "weight": o["weight"],
                            "offset": o["param_offset"],
                        },
                    )
        nparam = len(slots)
        local_bytes = joined_param = 0
        for o in objs:
            if o["cls"] == 5:
                continue
            hit = next((s for s in slots[:nparam] if fits(o, s, s["size"])), None) if reuse else None
            if hit:
                hit["members"].append(o)
                hit["interf"] |= interf[o["key"]]
                joined_param += 1
                continue
            hit = next((s for s in reversed(slots[nparam:]) if fits(o, s, 2 * s["size"])), None)
            if hit:
                hit["members"].append(o)
                hit["interf"] |= interf[o["key"]]
                hit["weight"] += o["weight"]
                if o["size"] > hit["size"]:
                    local_bytes += o["size"] - hit["size"]
                    hit["size"] = o["size"]
            else:
                slots.append(
                    {"members": [o], "interf": set(interf[o["key"]]), "size": o["size"], "weight": o["weight"]},
                )
                local_bytes += o["size"]
        return slots, nparam, local_bytes, joined_param

    slots, nparam, local_bytes, joined = run(True, param_reuse)
    redone = fpo and joined > 0 and local_bytes >= 0x70
    if redone:
        slots, nparam, local_bytes, _ = run(False, False)
    before_sort = [[m["key"] for m in s["members"]] for s in slots]
    if local_bytes > 0x80:
        local = slots[nparam:]
        density_sort(local, 0, len(local) - 1)
        slots[nparam:] = local
    cursor = 0
    offsets: dict = {}
    for i in range(len(slots) - 1, -1, -1) if fpo else range(len(slots)):
        s = slots[i]
        if i < nparam:
            off = s["offset"]
        else:
            al = 8 if aligned and fpo and any(m["type"] == 0x4008 for m in s["members"]) else 0
            size = (s["size"] + al - 1) & ~(al - 1) if al else s["size"]
            cursor = -align(-(cursor - size), size, al or 4)
            off = cursor
        s["final"] = off
        for m in s["members"]:
            offsets[m["key"]] = off if fpo else -align(-(s["size"] - m["size"] + off), m["size"])
    for o in objs:
        if o["cls"] == 5:
            offsets.setdefault(o["key"], o["param_offset"])  # a parameter keeps its home even without a slot
    return {
        "slots": slots,
        "offsets": offsets,
        "local_bytes": local_bytes,
        "cursor": cursor,
        "before_sort": before_sort,
        "nparam": nparam,
        "redone_without_param_reuse": redone,
    }


def frame_objects(fr: Frame) -> list[dict]:
    idx = {o.index: o.ptr for o in fr.objects}
    return [
        {
            "key": o.ptr,
            "cls": o.cls,
            "size": o.size,
            "weight": o.weight,
            "type": o.type,
            "interf": {idx[i] for i in o.interf if i in idx} - {o.ptr},
            "all_conflict": bool(o.f6 & 4),
            "param_offset": o.fe_offset,
        }
        for o in fr.objects
    ]


# ---------------------------------------------------------------- source estimate


def function_body(source: str, name: str) -> str | None:
    for m in re.finditer(rf"\b{re.escape(name)}\s*\([^;{{]*\)\s*\{{", source):
        depth, i = 0, m.end() - 1
        while i < len(source):
            depth += {"{": 1, "}": -1}.get(source[i], 0)
            if depth == 0:
                return source[m.end() : i]
            i += 1
    return None


def source_estimate(body: str, name: str) -> dict:
    """Pure-source reference estimate for a named local: every token occurrence, except a bare declaration."""
    code = re.sub(r"//.*|/\*.*?\*/", "", body, flags=re.DOTALL)
    tokens = len(re.findall(rf"(?<![\w.>]){re.escape(name)}\b", code))
    bare = len(re.findall(rf"\b[\w:<>*&\s]+\b{re.escape(name)}\s*(\[[^\]]*\])?\s*;", code))
    addr = bool(re.search(rf"&\s*{re.escape(name)}\b", code))
    calls = len(re.findall(r"\b[A-Za-z_]\w*\s*\(", code))
    return {"tokens": tokens - bare, "address_taken": addr, "calls_in_body": calls}


# ---------------------------------------------------------------- binary stack references


def _callee_pop(image, va: int) -> int | None:
    """Bytes a native callee pops: the immediate of its first `ret N`; None for an import thunk."""
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for _ in range(4):
        code = image.mapped[va - image.image_base : va - image.image_base + 0x4000]
        first = next(md.disasm(code, va), None)
        if first is None or first.mnemonic != "jmp":
            break
        if not first.op_str.startswith("0x"):
            return None
        va = int(first.op_str, 0)
    for insn in md.disasm(code, va):
        if insn.mnemonic == "ret":
            return int(insn.op_str, 0) if insn.op_str else 0
    return None


def stack_refs(code: bytes, base: int, direct_pop) -> dict:
    """Frame offsets of every esp-relative operand, relative to the entry esp (return address at 0).

    Linear sweep with depth carried along fallthrough and jump edges. A call pops the callee's
    `ret N` bytes when direct_pop(insn) knows the callee; otherwise, unless an `add esp` follows, it
    pops every argument byte pushed since the previous call (callee-cleaned vtable/COM calls).
    """
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    insns = list(md.disasm(code, base))
    state_at: dict[int, tuple[int, int]] = {}
    depths: dict[int, int] = {}
    refs, conflicts = [], []
    depth: int | None = 0
    window = 0
    saves_open = True
    written: set[str] = set()
    body_depth = None
    for i, insn in enumerate(insns):
        if insn.address in state_at:
            if depth is None:
                depth, window = state_at[insn.address]
            elif depth != state_at[insn.address][0]:
                conflicts.append((insn.address, depth, state_at[insn.address][0]))
        if depth is None:
            depth, window = body_depth or 0, 0
        mn, ops = insn.mnemonic, insn.op_str
        depths[insn.address] = depth
        if body_depth is None and (mn.startswith("j") or mn in ("call", "ret")):
            body_depth = depth - window
        for m in re.finditer(r"\[esp(?: \+ (0x[0-9a-f]+|\d+))?\]", ops):
            refs.append((insn.address, (int(m.group(1), 0) if m.group(1) else 0) - depth, f"{mn} {ops}"))
        if mn == "push":
            depth += 4
            if saves_open and ops in ("ebx", "ebp", "esi", "edi") and ops not in written:
                pass
            else:
                window += 4
        elif mn == "pop":
            depth -= 4
            window = max(0, window - 4)
        elif mn in ("sub", "add") and ops.startswith("esp, "):
            v = int(ops.split(", ")[1], 0) * (1 if mn == "sub" else -1)
            depth += v
            if mn == "add" or i > 0:
                window = max(0, window + v)
        elif mn == "call":
            saves_open = False
            nxt = insns[i + 1] if i + 1 < len(insns) else None
            follows_add = nxt is not None and nxt.mnemonic == "add" and nxt.op_str.startswith("esp, ")
            pop = 0 if follows_add else direct_pop(insn)
            if pop is None:
                pop = window
            depth -= pop
            window = 0
        elif mn not in ("cmp", "test") and ops[:3] in ("ebx", "ebp", "esi", "edi"):
            written.add(ops[:3])
        if (mn in ("jmp",) or mn.startswith(("j", "loop"))) and ops.startswith("0x"):
            state_at.setdefault(int(ops, 0), (depth, window))
        if mn in ("jmp", "ret"):
            depth = None
            window = 0
    frame = next(
        (int(i.op_str.split(", ")[1], 0) for i in insns[:8] if i.mnemonic == "sub" and i.op_str.startswith("esp, ")), 0,
    )
    return {"refs": refs, "conflicts": conflicts, "body_depth": body_depth, "depths": depths, "frame_size": frame}


def binary_frames(config, object_path: Path) -> dict:
    """esp-relative frame references of the native target and the compiled candidate."""
    manifest = match.load_function_manifest(
        match.default_functions_path(config.image),
        metadata_path=match.default_metadata_path(config.image),
        image_name=match.default_image_path(config.image).name,
    )
    _, start, end = match.resolve_function(manifest, config.function, end_override=config.end_va)
    image = match.load_image(match.default_image_path(config.image), manifest.image_base)
    by_name = manifest.by_name

    def native_pop(insn):
        if insn.op_str.startswith("0x"):
            return _callee_pop(image, int(insn.op_str, 0))
        return None

    target = stack_refs(image.function_bytes(start, end), start, native_pop)
    obj = match.parse_coff_object(object_path.read_bytes())
    cand = match.extract_object_function(obj, config.symbol)
    relocs = {r.offset: r.symbol_name for r in cand.relocation_references}

    def candidate_pop(insn):
        name = relocs.get(insn.address + 1)
        if name is None:
            return None
        if re.fullmatch(r"_\w+@\d+", name):
            return int(name.rsplit("@", 1)[1])
        if name.startswith("?") and "@@YA" in name:
            return 0
        clean = name.lstrip("_").split("@")[0].lstrip("?")
        sym = by_name.get(clean)
        return _callee_pop(image, sym.address) if sym is not None else None

    candidate = stack_refs(cand.data, 0, candidate_pop)
    return {"target": target, "candidate": candidate}


# ---------------------------------------------------------------- driver


def capture_and_observe(
    scratch: Path,
    out: Path,
    source: Path | None,
    *,
    decisions: bool = False,
) -> tuple[list[Frame], dict]:
    config = match.load_scratch_config(scratch.resolve())
    if out.exists():
        raise SystemExit(f"--out must be a new directory: {out}")
    out = out.resolve()
    out.mkdir(parents=True)
    src = out / "source"
    shutil.copytree(config.directory, src, ignore=shutil.ignore_patterns("build", "__pycache__", "*.json", "*.jsonl"))
    if source is not None:
        shutil.copyfile(source, src / config.source)
    folders = {n: out / n for n in ("helper", "capture", "observed")}
    for d in folders.values():
        d.mkdir()
    frozen = replace(config, directory=src)
    with c2.compiler_environment():
        shutil.copyfile(c2.ASSETS / "capture.c", folders["helper"] / "capture.c")
        replay.compile_driver(folders["helper"], "capture.c", "capture.obj")
        replay.link(folders["helper"], "capture.dll", "capture.obj", dll=True)
        normal = match.compile_scratch(frozen, force=True)
        captured = out / "captured-source"
        shutil.copytree(src, captured, ignore=shutil.ignore_patterns("build"))
        wrapped = replace(
            frozen,
            directory=captured,
            cflags=config.cflags + f' /B2"Z:{folders["helper"] / "capture.dll"}" /Bd',
        )
        os.environ["CRIMSON_IL_CAPTURE_DIR"] = replay.windows_path(folders["capture"])
        try:
            match.compile_scratch(wrapped, force=True)
        finally:
            os.environ.pop("CRIMSON_IL_CAPTURE_DIR", None)
        arguments, _ = replay.read_arguments(folders["capture"])
        obs = folders["observed"]
        settings = (
            "static const char *backend_path = "
            + json.dumps(replay.windows_path(replay.COMPILER / "Bin/C2.DLL"))
            + ";\nstatic const char *pdb_path = "
            + json.dumps(replay.windows_path(replay.COMPILER / "Bin/MSPDB60.DLL"))
            + ";\nstatic char *arguments[] = {\n"
            + ",\n".join(json.dumps(a) for a in arguments)
            + "\n};\n"
        )
        (obs / "replay_settings.h").write_text(settings)
        (obs / "observer.c").write_text(observer_source(decisions))
        replay.compile_driver(obs, "observer.c", "observer.obj")
        replay.link(obs, "observer.exe", "observer.obj")
        replay.run([replay.WIBO, "observer.exe"], obs)
    same = replay.normalized_coff(normal) == replay.normalized_coff(obs / "replay.obj")
    if not same:
        raise SystemExit("Observed object differs from the normal compile; observation is not preserving")
    try:
        metrics = replay.function_metrics(frozen, normal)
    except (ValueError, KeyError):  # a synthetic control with no native counterpart
        metrics = None
    return decode((obs / "frame.bin").read_bytes()), {
        "config": config,
        "source": (src / config.source).read_text(encoding="latin1"),
        "metrics": metrics,
        "object": str(normal),
    }


def describe(o: Obj) -> str:
    if o.name:
        return o.name
    lines = sorted({r["line"] for r in o.refs})
    return "temp@" + (",".join(map(str, lines[:4])) + ("..." if len(lines) > 4 else "") if lines else "?")


def analyze(fr: Frame, source_body: str | None) -> dict:
    objs = frame_objects(fr)
    fpo = bool(fr.flags & 0x10 or fr.flags & 0x600000)
    reuse = not (fr.flags & 0x40 or fr.flags & 0x600000)
    sim = simulate(objs, fpo=fpo, param_reuse=reuse, aligned=bool(fr.flags & 0x600000))
    size_of = {o.ptr: o.size for o in fr.objects}
    # references to objects homed before counting (EH record, /GX guard) are ignored by order_stack_object
    replayed = ref_order([(r["obj"], size_of[r["obj"]], 1) for r in fr.refs if r["obj"] in size_of])
    list_ok = replayed == [(o.ptr, o.weight) for o in fr.objects]
    # Pure-source what-if: named locals weighted by their source token count, everything else as observed.
    ests = {}
    for o in fr.objects:
        plain = o.name.removeprefix("_")  # front-end local names carry the C prefix
        if source_body and plain and o.cls in (4, 5):
            ests[o.ptr] = source_estimate(source_body, plain)
    rank = {o["key"]: i for i, o in enumerate(objs)}
    src_objs = [dict(o, weight=ests[o["key"]]["tokens"] if o["key"] in ests else o["weight"]) for o in objs]
    src_objs.sort(key=lambda o: (o["size"], -o["weight"], rank[o["key"]]))
    src_sim = simulate(src_objs, fpo=fpo, param_reuse=reuse, aligned=bool(fr.flags & 0x600000))
    rows = []
    slot_of = {}
    for i, s in enumerate(sim["slots"]):
        for m in s["members"]:
            slot_of[m["key"]] = i
    for o in fr.objects:
        est = ests.get(o.ptr)
        kinds: dict[str, int] = {}
        for r in o.refs:
            kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
        rows.append(
            {
                "name": describe(o),
                "fe_id": o.fe_id,
                "lines": sorted({r["line"] for r in o.refs}),
                "cls": o.cls,
                "size": o.size,
                "type": f"{o.type:#06x}",
                "weight": o.weight,
                "ref_kinds": kinds,
                "max_depth": max((r["depth"] for r in o.refs), default=0),
                "flags": f"{o.f5:02x}/{o.f6:02x}/{o.f7:02x}",
                "fe_flags14": f"{o.fe_flags14:#x}",
                "fe_storage": f"{o.fe_storage:#x}",
                "slot": slot_of.get(o.ptr),
                "observed": o.offset,
                "predicted": sim["offsets"].get(o.ptr),
                "source_predicted": src_sim["offsets"].get(o.ptr),
                "bottom": fr.frame_size + o.offset if o.cls != 5 else None,
                "source_refs": est,
            },
        )
    return {
        "function": fr.name,
        "fn_flags": f"{fr.flags:#x}",
        "fpo": fpo,
        "frame_size": fr.frame_size,
        "local_bytes": fr.local_bytes,
        "sorted_by_density": fr.local_bytes > 0x80,
        "sim_local_bytes": sim["local_bytes"],
        "list_order_replayed": list_ok,
        "offsets_predicted": all(r["predicted"] == r["observed"] for r in rows),
        "source_prediction_misses": sum(r["source_predicted"] != r["observed"] for r in rows),
        "source_frame_size": (-src_sim["cursor"] + 3) & ~3,  # compute_frame_size rounds to 4
        "slots": [
            {
                "size": s["size"],
                "weight": s["weight"],
                "density": int(s["weight"] * 1000 / s["size"]),
                "offset": s["final"],
                "members": [describe(next(o for o in fr.objects if o.ptr == m["key"])) for m in s["members"]],
            }
            for s in sim["slots"]
        ],
        "objects": rows,
    }


REGISTER_NAMES = ("", "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")


def register_name(rva: int) -> str:
    """g_reg_symbols 0x107ac730 + n*0x54: 1 eax .. 8 edi, sub-registers after."""
    if not rva:
        return ""
    n, rest = divmod(rva - 0xAC730, 0x54)
    return REGISTER_NAMES[n] if not rest and n < len(REGISTER_NAMES) else f"reg{n}"


def decision_summary(fr: Frame) -> list[dict]:
    """Allocator events for named locals and pointer-typed ranges, in event order."""
    rows = []
    for d in fr.decisions:
        if not (d["name"] or d["type"] >> 12 == 3):
            continue
        rows.append(
            {
                "event": d["event"],
                "range": f"{d['lr']:#x}",
                "name": d["name"] or f"temp:{d['type']:#06x}",
                "def_line": d["line"],
                "benefit": d["benefit"],
                "priority": d["priority"],
                "refs": d["refs"],
                "flags": f"{d['flags']:04x}",
                "register": register_name(d["reg"]),
            },
        )
    return rows


def print_report(rep: dict) -> None:
    print(
        f"== {rep['function']}  flags={rep['fn_flags']} fpo={rep['fpo']} frame={rep['frame_size']:#x}"
        f" local_bytes={rep['local_bytes']:#x} density_sort={rep['sorted_by_density']}",
    )
    print(
        f"   ref-count list replayed: {rep['list_order_replayed']}   offsets predicted: {rep['offsets_predicted']}"
        f"   pure-source what-if: {rep['source_prediction_misses']} offsets differ, frame {rep['source_frame_size']:#x}",
    )
    print(f"   {'object':<28} cls size type    wt  src dst alias depth flags     slot  offset  bottom  src-est")
    for r in rep["objects"]:
        k = r["ref_kinds"]
        alias = k.get("src-alias", 0) + k.get("dst-alias", 0)
        est = r["source_refs"]
        est_s = "" if est is None else f"{est['tokens']}{'&' if est['address_taken'] else ''}"
        mark = "" if r["predicted"] == r["observed"] else f" (sim {r['predicted']})"
        if r["source_predicted"] != r["observed"]:
            mark += f" src-what-if {r['source_predicted']}"
        bottom = "" if r["bottom"] is None else f"{r['bottom']:#x}"
        print(
            f"   {r['name'][:28]:<28} {r['cls']:>3} {r['size']:>4} {r['type']} {r['weight']:>4} {k.get('src', 0):>4}"
            f" {k.get('dst', 0):>3} {alias:>5} {r['max_depth']:>5} {r['flags']} {r['slot']!s:>4} {r['observed']:>7}"
            f" {bottom:>7}  {est_s}{mark}",
        )
    for d in rep.get("decisions", []):
        print(
            f"   decision {d['event']:<34} {d['name'][:22]:<22} range={d['range']} def-line={d['def_line']:<4}"
            f" benefit={d['benefit']:<5} priority={d['priority']:<7} refs={d['refs']:<3} flags={d['flags']} {d['register']}",
        )
    print("   slots (final order):")
    for i, s in enumerate(rep["slots"]):
        print(
            f"   [{i:2}] off={s['offset']:>6} size={s['size']:>4} weight={s['weight']:>4} density={s['density']:>6}"
            f"  {', '.join(s['members'])}",
        )


def print_native(config, object_path: Path) -> None:
    """Per-dword reference counts, offsets from the frame bottom (add the callee-saved pushes for esp+N)."""
    frames = binary_frames(config, object_path)
    counts = {}
    for side, r in frames.items():
        pushes = r["body_depth"] - r["frame_size"]
        counts[side] = ({}, r["frame_size"], pushes)
        for _, off, _ in r["refs"]:
            if -r["frame_size"] <= off < 0:
                bottom = (off + r["frame_size"]) & ~3
                counts[side][0][bottom] = counts[side][0].get(bottom, 0) + 1
    (tc, tf, tp), (cc, cf, cp) = counts["target"], counts["candidate"]
    print(f"native frame {tf:#x} (+{tp} pushed), candidate frame {cf:#x} (+{cp} pushed); bottom-relative refs:")
    for bottom in range(0, max(tf, cf), 4):
        print(f"   {bottom:#05x}  native {tc.get(bottom, '-')!s:>4}  candidate {cc.get(bottom, '-')!s:>4}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="new work directory (short ASCII path)")
    parser.add_argument("--source", type=Path, help="compile this source instead of the scratch's own")
    parser.add_argument("--function", help="report only this function (default: the scratch FUNCTION)")
    parser.add_argument("--all", action="store_true", help="report every compiled function")
    parser.add_argument("--json", type=Path, help="write the full report as JSON")
    parser.add_argument(
        "--native",
        action="store_true",
        help="also print esp-tracked frame references of the native target and the candidate, bottom-relative",
    )
    parser.add_argument(
        "--decisions",
        action="store_true",
        help="also hook substitution, rematerialization, demotion, block splitting and colouring of named/pointer ranges",
    )
    parser.add_argument(
        "--control",
        action="store_true",
        help="synthetic compiler control: skip scratch source validation (inline asm, volatile); never a scratch",
    )
    args = parser.parse_args()
    if args.control:
        match.validate_scratch_source = lambda source: None
        match._validate_scratch_source_text = lambda text, source: None
    frames, info = capture_and_observe(args.scratch, args.out, args.source, decisions=args.decisions)
    config = info["config"]
    want = args.function or config.symbol or config.function
    reports = []
    for fr in frames:
        if not args.all and want not in fr.name:
            continue
        body = function_body(info["source"], fr.name.split("@")[0].lstrip("?_")) or function_body(
            info["source"],
            config.function,
        )
        rep = analyze(fr, body)
        if args.decisions:
            rep["decisions"] = decision_summary(fr)
        reports.append(rep)
        print_report(rep)
    m = info["metrics"]
    if m:
        print(
            f"metrics: {m['ratio'] * 100:.4f}% {m['candidate_instructions']}/{m['target_instructions']}"
            f" refs {m['references_ok']}/{m['reference_problems']}",
        )
    if args.native:
        print_native(info["config"], Path(info["object"]))
    if args.json:
        args.json.write_text(json.dumps({"reports": reports, "metrics": m}, indent=1) + "\n")
    if not all(r["offsets_predicted"] and r["list_order_replayed"] for r in reports):
        sys.exit(2)


if __name__ == "__main__":
    main()
