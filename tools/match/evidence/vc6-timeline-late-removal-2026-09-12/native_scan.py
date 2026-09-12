"""Screen executable sections for adjacent dword frame overwrites.

Every possible 89/C7 MOV start is decoded, including unaligned bytes. Hits are
candidates for manual review, not proof of deadness or valid control flow.
"""

import argparse
import hashlib
import json
from pathlib import Path

import capstone as cs
import pefile
from capstone.x86_const import X86_OP_MEM, X86_REG_EBP, X86_REG_ESP

from crimson import match


def frame(insn):
    if insn.mnemonic != "mov" or len(insn.operands) != 2:
        return None
    dest = insn.operands[0]
    if dest.type != X86_OP_MEM or dest.size != 4 or dest.mem.base not in (X86_REG_ESP, X86_REG_EBP) or dest.mem.index:
        return None
    return dest.mem.base, dest.mem.disp


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
inventory = json.loads((match.REPO_ROOT / "analysis/decomp/1.9.93.json").read_text())
dis = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
dis.detail = True
rows = []
for name in ("crimsonland.exe", "grim.dll"):
    path = match.REPO_ROOT / "game_bins/crimsonland/1.9.93-gog" / name
    pe = pefile.PE(str(path))
    functions = [f for f in inventory["functions"] if f["image"] == name]
    boundaries = {}
    for function in functions:
        code = pe.get_data(function["address"] - pe.OPTIONAL_HEADER.ImageBase, function["size"])
        for insn in dis.disasm(code, function["address"]):
            boundaries[insn.address] = function["name"]
    hits = []
    sections = []
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        code = section.get_data()[: section.Misc_VirtualSize]
        base = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
        sections.append({"name": section.Name.rstrip(b"\0").decode(), "address": hex(base), "bytes": len(code)})
        for offset, byte in enumerate(code):
            if byte not in (0x89, 0xC7):
                continue
            pair = list(dis.disasm(code[offset : offset + 30], base + offset, count=2))
            if len(pair) != 2 or frame(pair[0]) is None or frame(pair[0]) != frame(pair[1]):
                continue
            hits.append(
                {
                    "address": hex(pair[0].address),
                    "inventory_function": boundaries.get(pair[0].address),
                    "second_at_known_boundary": pair[1].address in boundaries,
                    "instructions": [f"{i.address:08x} {i.mnemonic} {i.op_str}" for i in pair],
                },
            )
    rows.append(
        {
            "image": name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "inventoried_functions": len(functions),
            "known_instruction_boundaries": len(boundaries),
            "sections": sections,
            "hits": hits,
        },
    )
args.out.write_text(json.dumps(rows, indent=2) + "\n")
print(json.dumps(rows, indent=2))
