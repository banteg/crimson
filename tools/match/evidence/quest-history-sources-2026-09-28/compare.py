"""Compile the timeline sources under C2 9044 and 8966 and compare them with the historical bodies."""

import argparse
import difflib
import json
import re
import struct
from pathlib import Path

import capstone

from crimson import match

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SCRATCH = ROOT / "tools/match/scratches/quest_spawn_timeline_update"
SENTINEL = 0x7FFF0000
# (source, compiler, historical body)
BUILDS = (("msvc6.5pp", "1.9.8"), ("msvc6.5", "1.9.93"))


def listing(source, compiler, out):
    """Compile `source` as the timeline scratch and return its address-masked instruction list."""
    work = out / f"{source.stem}-{compiler}"
    work.mkdir(parents=True)
    (work / "scratch.cpp").write_text(source.read_text())
    conf = [
        line for line in (SCRATCH / "scratch.conf").read_text().splitlines()
        if not line.startswith(("SOURCE=", "COMPILER=", "RECOVERY=", "RESIDUAL="))
    ]
    (work / "scratch.conf").write_text("\n".join([*conf, "SOURCE=scratch.cpp", f"COMPILER={compiler}"]) + "\n")
    config = match.load_scratch_config(work)
    obj = match.compile_scratch(config, match.DEFAULT_MATCH_ROOT.resolve())
    function = match.extract_object_function(match.parse_coff_object(Path(obj).read_bytes()), config.symbol)
    body = bytearray(function.data)
    for offset in function.relocation_offsets:
        struct.pack_into("<I", body, offset, SENTINEL)
    lines = []
    for item in capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32).disasm(bytes(body), 0):
        operand = item.op_str
        if item.mnemonic.startswith("j"):
            operand = hex(int(operand, 16))
        elif item.mnemonic == "call":
            operand = "EXTERNAL_CALL"
        else:
            operand = operand.replace(hex(SENTINEL), "IMAGE")
        lines.append(f"{item.mnemonic} {operand}")
    return lines


def pointer_stores(lines):
    return [line for line in lines if re.fullmatch(r"mov dword ptr \[esp \+ 0x[0-9a-f]+\], e(si|di|bp)", line)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", type=Path, required=True, help="output directory of historical.py")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    targets = {version: (args.history / f"{version}.asm").read_text().splitlines() for _, version in BUILDS}
    sources = [SCRATCH / "scratch.cpp", *sorted((HERE / "sources").glob("*.cpp"))]
    results = {}
    for source in sources:
        name = "canonical" if source.parent == SCRATCH else source.stem
        results[name] = {}
        for compiler, version in BUILDS:
            lines = listing(source, compiler, args.out)
            ratio = difflib.SequenceMatcher(a=targets[version], b=lines, autojunk=False).ratio()
            results[name][compiler] = {
                "target": version,
                "exact": lines == targets[version],
                "ratio": round(ratio, 4),
                "instructions": len(lines),
                "pointer_stores": pointer_stores(lines),
            }
            state = "EXACT" if lines == targets[version] else f"{ratio:.4f}"
            print(f"{name:32} {compiler:10} vs {version:6} {state:7} {len(lines)} insns {pointer_stores(lines)}")
    assert not results["canonical"]["msvc6.5pp"]["exact"]
    for name in ("top_entry_indexed_template", "indexed_loop_template_pointer", "top_entry_indexed_x"):
        assert results[name]["msvc6.5pp"]["exact"], name
    assert results["top_entry_indexed_x"]["msvc6.5"]["pointer_stores"] == ["mov dword ptr [esp + 0x14], esi"] * 2
    assert results["block_entry_dead_store"]["msvc6.5"]["pointer_stores"] == ["mov dword ptr [esp + 0x10], esi"]
    (args.out / "results.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
