"""Test whether operand flag 0x10 explains the missing creature field-pointer homes.

Diagnostic only. Records, per pass, the operand byte +0x11 bit 0x10 on the
pointer-definition copies, then checks whether the flagged pointer survives in
the emitted object. It changes no compiler decision and earns no match credit.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

import capstone

from crimson import match
from crimson import match_c2 as c2

HERE = Path(__file__).resolve().parent
SOURCE_SHA = "7bb97911b09a9e96d60b4b7b93530f07702d92de55d343d75fb5b642b49f44bd"
# Function-relative C2 line labels of the pointer definitions in SOURCE_SHA.
POINTERS = {"health": 27, "lifecycle": 120, "collision": 122, "size": 420, "cooldown": 453, "target_player": 461}


def flagged_copies(snapshot, line):
    """Temporary/memory source operands of copy nodes (op 0x15b or 0x1) on a line."""
    rows = []
    for node in snapshot["nodes"]:
        if node["line"] != line or node["op"] not in (0x15B, 0x1):
            continue
        for operand in node["src"]:
            rows.append(bool((operand["raw"][4] >> 8) & 0x10))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    scratch = match.DEFAULT_MATCH_ROOT / "scratches/creature_update_all"
    assert hashlib.sha256((scratch / "scratch.cpp").read_bytes()).hexdigest() == SOURCE_SHA
    c2.trace(scratch, args.out)
    snapshots = c2.read_verified(args.out)
    passes = [s for s in snapshots if s["boundary"] == "entry" and s["phase"] < 12]
    table = {hex(s["target_rva"]): {name: flagged_copies(s, line) for name, line in POINTERS.items()} for s in passes}
    five = [n for n in POINTERS if n != "target_player"]
    # The front end sets the bit on every pointer-definition copy at 0xfcda.
    assert all(True in table["0xfcda"][n] for n in five)
    # 0x281cd clears it on the five field pointers...
    for rva in ("0x281cd", "0x2930f", "0x29511", "0x296de", "0x306c1"):
        assert not any(True in table[rva][n] for n in five), rva
    # ...while target_player carries it from 0x2930f through 0x30308.
    for rva in ("0x2930f", "0x29511", "0x296de", "0x26d75", "0x2f8fc", "0x30308"):
        assert table[rva]["target_player"] == [True], rva
    # Nevertheless, the emitted object forms no target_player pointer.
    coff = match.parse_coff_object((args.out / "observed" / "replay.obj").read_bytes())
    body = match.extract_object_function(coff, "_creature_update_all").data
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    listing = [f"{i.mnemonic} {i.op_str}" for i in md.disasm(body, 0)]
    # Unrelocated displacement: creature_pool + 0x70 appears as esi*8 + 0x70.
    direct = sum(1 for line in listing if "[esi*8 + 0x70]" in line)
    lea = sum(1 for line in listing if re.match(r"lea e.., \[esi\*8 \+ 0x70\]", line))
    assert lea == 0 and direct == 13, (lea, direct)
    record = {
        "source_sha256": SOURCE_SHA,
        "operand_0x10_on_definition_copies": table,
        "target_player": {"pointer_leas": lea, "direct_scaled_accesses": direct},
        "conclusion": "Operand flag 0x10 on the definition copy does not retain the pointer.",
    }
    (HERE / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print("PASS: flag present on target_player through allocation; no pointer emitted")


if __name__ == "__main__":
    main()
