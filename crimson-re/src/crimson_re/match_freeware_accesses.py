"""Lower bounds on named data storage from direct memory accesses in exact native code."""

from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict
from pathlib import Path
from typing import Any

import capstone
from capstone import x86

from . import match, match_builds
from .match_freeware_data_maps import _exact

# LEA, prefetch, bit strings with a variable bit offset, and register-indexed
# operands cannot establish the bytes occupied at the displacement.
_MEMORY_OPS = {
    "mov", "movzx", "movsx", "push", "pop", "call", "jmp", "xchg", "add", "adc", "sub", "sbb",
    "inc", "dec", "neg", "not", "and", "or", "xor", "cmp", "test", "mul", "imul", "div", "idiv",
    "fld", "fild", "fst", "fstp", "fist", "fistp", "fadd", "fsub", "fsubr", "fmul", "fdiv", "fdivr",
    "fcom", "fcomp", "fiadd", "fisub", "fisubr", "fimul", "fidiv", "fidivr",
}


def fixed_accesses(
    placements: list[dict[str, Any]], functions: list[dict[str, Any]], bounded: list[dict[str, Any]],
    image_paths: dict[str, Path], sections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Record one witness for the widest proven access at each otherwise unbounded name."""
    ranges = defaultdict(list)
    addresses = defaultdict(set)
    for s in sections:
        addresses[s["image"]].add(s["address"] + s["size"])
    for row in bounded:
        ranges[row["image"]].append((row["address"], row["address"] + row["size"]))
        addresses[row["image"]].add(row["address"])
    for placement in placements:
        addresses[placement["image"]].add(placement["address"])
    starts = {name: sorted(values) for name, values in addresses.items()}

    uses: dict[tuple[str, int], dict[int, dict[str, Any]]] = defaultdict(dict)
    for placement in placements:
        name, address = placement["image"], placement["address"]
        if not placement["names"] or any(lo <= address < hi for lo, hi in ranges[name]):
            continue
        for ref in placement["references"]:
            if ref["name"] not in placement["names"]:
                continue
            sites = uses[name, ref["function"]]
            if ref["addend"] == 0:
                sites[ref["site"]] = placement
            for site, addend in ref.get("additional_operands", ()):
                if addend == 0:
                    sites[site] = placement

    if not any(uses.values()):
        return []
    originals = {name: match.load_image(path) for name, path in image_paths.items()}
    results = {}
    for f in functions:
        name, function = f["image"], f["address"]
        sites = uses.get((name, function))
        if not sites or not _exact(f):
            continue
        raw = originals[name].function_bytes(function, f["end"])
        for ins in match_builds._flow_disassembler().disasm(raw, function):
            if ins.mnemonic not in _MEMORY_OPS or ins.disp_size != 4:
                continue
            site = ins.address + ins.disp_offset
            if site not in sites:
                continue
            placement = sites[site]
            address = placement["address"]
            for op in ins.operands:
                if (op.type != x86.X86_OP_MEM or not op.access & (capstone.CS_AC_READ | capstone.CS_AC_WRITE)
                        or op.mem.base or op.mem.index or op.mem.segment or op.mem.disp & 0xffffffff != address
                        or op.size not in (1, 2, 4, 8)):
                    continue
                next_index = bisect_right(starts[name], address)
                if next_index < len(starts[name]) and address + op.size > starts[name][next_index]:
                    continue  # A wide operation can span two distinct globals.
                key = name, address
                if key not in results or op.size > results[key]["size"]:
                    results[key] = {"image": name, "address": address, "size": op.size, "names": placement["names"],
                                    "owner": placement["owner"], "function": function, "instruction": ins.address,
                                    "operand_site": site, "mnemonic": ins.mnemonic}
    return [results[key] for key in sorted(results)]
