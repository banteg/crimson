"""Observe the baseline demo-angle clone; never change a compiler decision."""

import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

import pefile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
spec = importlib.util.spec_from_file_location("il_stage_trace", ROOT / "scripts/c2/il_stage_trace.py")
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scratch", type=Path, help="baseline scratch made by verify.py under --out/before")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    source = (args.scratch / "scratch.cpp").read_bytes()
    assert source == (HERE / "before.cpp").read_bytes()
    compiler = ROOT / "tools/match/compilers/msvc6.5/Bin/C2.DLL"
    assert (
        hashlib.sha256(compiler.read_bytes()).hexdigest()
        == "d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a"
    )
    pe = pefile.PE(str(compiler))
    call = pe.get_data(0x3695F, 5)
    assert call[0] == 0xE8
    clone = 0x1073695F + 5 + struct.unpack("<i", call[1:])[0]
    s.PRESETS["clone"] = (
        (0x107584BC, 0x1073663C, "mover", False, 3),
        (0x10736A07, 0x10737AD8, "length", True, 0),
        (0x1073695F, clone, "clone", False, 0),
    )
    c2, iv = s.load_modules()
    s.trace(c2, iv, args.scratch.resolve(), args.out.resolve(), "clone")
    events = s.decode((args.out / "observed/phases.bin").read_bytes(), s.result_profile(args.out))
    il, pending, rows = {}, {}, []
    for event in events:
        if event["name"] == "mover":
            il = {line.split()[1]: line for line in event["body"].splitlines() if line.startswith("T ")}
        elif event["name"] == "length":
            fields = s.head_fields(event)
            if event["boundary"] == "entry":
                pending = fields
            else:
                line = il.get(pending.get("ecx"), "")
                match = s.TUPLE.match(line)
                if match and int(match[5]) == 585:
                    rows.append({"length": int(fields["eax"], 16), "tuple": s.pretty(line)})
        elif event["name"] == "clone":
            fields = s.head_fields(event)
            line = il.get(fields.get("ecx"), "")
            match = s.TUPLE.match(line)
            if match and int(match[5]) == 585:
                rows.append({"clone": s.pretty(line)})
    assert [row["length"] for row in rows if "length" in row] == [3, 0, 3, 0, 2, 0, 6, 5]
    assert sum("clone" in row for row in rows) == 8
    (args.out / "decisions.json").write_text(json.dumps(rows, indent=2) + "\n")
    print("Estimated 19-byte tail: eight cloned IR tuples, four extra emitted instructions.")


if __name__ == "__main__":
    main()
