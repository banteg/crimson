"""Compare 1.4.0 menu draws, hit tests and spawned creature bytes with the original PE, then exercise a full run."""

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from crimson_re.dbg.native_oracle import NativeOracle, StubCall, SymbolTable

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "crimson-core"))
from freeware.build import game_flags, game_sources


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("install", type=Path, help="1.4.0 directory containing crimson.exe")
    args = parser.parse_args()
    exe = args.install / "crimson.exe"
    spec = next(b for b in json.loads((ROOT / "decomp/builds.json").read_text())["builds"] if b["id"] == "1.4.0")
    assert hashlib.sha256(exe.read_bytes()).hexdigest() == next(
        i["sha256"] for i in spec["images"] if i["name"] == exe.name
    )
    compiler = shutil.which("clang++")
    if not compiler:
        raise SystemExit("clang++ is required")
    with tempfile.TemporaryDirectory() as tmp:
        test = Path(tmp) / "freeware-cycle"
        subprocess.run(
            [
                compiler,
                *game_flags(ROOT),
                *game_sources(ROOT),
                ROOT / "crimson-core/checks/freeware_cycle.cpp",
                "-o",
                test,
            ],
            check=True,
        )
        lines = subprocess.check_output([test], text=True).splitlines()
    oracle = NativeOracle(exe, symbols=SymbolTable({}), rand_state_address=0x432C40)
    oracle.write(0x442AF8, b"\x5a" * (512 * 128))
    oracle.write_u8(0x442AF8 + 2 * 128, 0)
    oracle.write_u32(0x4428A8, 2)
    oracle.write_f32(0x452DC4, 1.25)
    oracle.rand_state = 1
    slot = oracle.call(0x40FB70, oracle.alloc_f32s(1088, 643), oracle.alloc_f32s(0.4, 0.8, 0.6, 1), 1).eax_i32
    assert slot == 2
    assert f"spawn {oracle.read(0x442AF8 + slot * 128, 128).hex()}" in lines
    # Capture the actual Grim calls made by the eight-row loop. Only the backend is replaced.
    vtable = oracle.alloc(256)
    oracle.write_u32(0x452D94, oracle.alloc(4, data=struct.pack("<I", vtable)))
    draws = []

    def draw(call: StubCall) -> None:
        label = oracle.read(call.arg_u32(2), 70).split(b"\0")[0].decode("ascii")
        draws.append(f"row {call.arg_f32(0):.0f} {call.arg_f32(1):.0f} {label}")

    for offset, pop, fn in [(0xB8, 16, None), (0xC8, 12, draw)]:
        address = oracle.load_code(b"\xc3")
        oracle.stub(address, fn, pop=pop)
        oracle.write_u32(vtable + offset, address)
    labels = [0x431BC8, 0x431BB8, 0x431B80, 0x432580, 0x432574, 0x432564, 0x432554, 0x431B34]
    for i, address in enumerate(labels):
        oracle.write_u32(0x4387C8 + 4 * i, address)
    oracle.write_u32(0x42FB90, 1024)
    rows = [line for line in lines if line.startswith("row ")]
    for line in lines:
        if line.startswith("hover "):
            _, x, y, expected = line.split()
            oracle.write_f32(0x438800, float(x))
            oracle.write_f32(0x438804, float(y))
            draws.clear()
            oracle.run(0x41B38A, 0x41B527, regs={"ebp": 0})
            assert rows == draws
            assert oracle.read_i32(0x452DA8) == int(expected), line
    print("1.4.0: eight original menu draws, 32 boundary hits, all 128 spawn bytes, kill, death and restart passed")


if __name__ == "__main__":
    main()
