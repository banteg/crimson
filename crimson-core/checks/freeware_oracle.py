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


def check_volleys(oracle: NativeOracle, lines: list[str]) -> None:
    # Run the complete original player_update with stationary controls, the fire button held and the
    # reload button released. Only the input, arena-wall collision, visual effects and sound are stubbed.
    table = oracle.alloc(256)
    oracle.write_u32(0x452D94, oracle.alloc(4, data=struct.pack("<I", table)))
    for offset, fn in [
        (0x40, lambda call: int((call.arg_u32(0) & 255) == 0x0F)),
        (0x44, 0),
        (0x48, lambda call: int(call.arg_u32(0) == 0)),
        (0x4C, 1),
    ]:
        address = oracle.load_code(b"\xc3")
        oracle.stub(address, fn, pop=4)
        oracle.write_u32(table + offset, address)
    for address in (0x405630, 0x40E6B0, 0x40E6F0, 0x404EE0):
        oracle.stub(address, 0, pop=12 if address == 0x404EE0 else 0)
    oracle.write_u32(0x43CBB8, oracle.alloc(200))
    for address, value in [(0x4428A0, 1), (0x4428A8, 1), (0x4428AC, 0), (0x42FBD8, 1024), (0x42FBDC, 1024)]:
        oracle.write_u32(address, value)
    for address, value in [
        (0x42FB8C, 1),
        (0x452E94, 1 / 60),
        (0x452DC4, 7),
        (0x438490, 512),
        (0x438494, 512),
        (0x4384A0, 4),
        (0x438800, 712),
        (0x438804, 512),
        (0x4385CC, 1),
        (0x4384D0, 2),
        (0x4384E4, 10),
        (0x4385DC, 10),
        (0x438508, 1),
    ]:
        oracle.write_f32(address, value)
    for address in (0x452D59, 0x4428F4, 0x452D4D):
        oracle.write_u8(address, 1)
    oracle.write_u8(0x4385F8, 0x0F)
    baseline = oracle.snapshot()
    volleys = [line.split() for line in lines if line.startswith("volley ")]
    assert len(volleys) == 20
    for _, wid, cooldown, ammo, *expected in volleys:
        oracle.restore(baseline)
        oracle.rand_state = 42
        oracle.write_u32(0x4385D4, int(wid))
        oracle.call(0x4126E0)
        assert abs(oracle.read_f32(0x438504) - float(cooldown)) < 1e-6, wid
        assert abs(oracle.read_f32(0x4384E4) - float(ammo)) < 1e-5, wid
        slots = (
            ("b", 0x439260, 64, 52, 32),
            ("r", 0x43BB78, 64, 40, 28),
            ("p", 0x439F60, 128, 56, 48),
        )
        actual = [
            f"{kind}{oracle.read_u8(a + offset)}"
            for kind, base, count, stride, offset in slots
            for a in range(base, base + count * stride, stride)
            if oracle.read_u8(a)
        ]
        assert actual == expected, (wid, actual, expected)


def check_choices(oracle: NativeOracle, lines: list[str]) -> None:
    vt = oracle.alloc(256)
    oracle.write_u32(0x452D94, oracle.alloc(4, data=struct.pack("<I", vt)))
    lookup = oracle.load_code(b"\xc3")
    oracle.stub(lookup, 1, pop=4)
    oracle.write_u32(vt + 0x90, lookup)
    # Initialize the actual perk records and their eligibility bits without the graphics backend.
    oracle.stub(0x4078B0, lambda call: call.arg_u32(0))
    oracle.call(0x4036A0)
    oracle.call(0x407920)
    oracle.stub(0x405630, 0)
    for line in lines:
        if line.startswith("boss "):
            _, level, xp, body = line.split()
            oracle.write(0x442AF8, bytes(512 * 128))
            oracle.write_u8(0x442AF9, 1)
            oracle.write_u32(0x4428A8, 1)
            oracle.write_u32(0x4384F8, int(xp))
            oracle.write_u32(0x438500, int(level) - 1)
            oracle.write_u8(0x452DA4, 1)
            oracle.rand_state = 1234
            oracle.call(0x408600)
            assert oracle.read_u32(0x438500) == int(level)
            actual = oracle.read(0x442AF8, 128)
            assert actual == bytes.fromhex(body), (
                level,
                [(hex(i), a, b) for i, (a, b) in enumerate(zip(actual, bytes.fromhex(body), strict=True)) if a != b],
            )
    samples = [line.split() for line in lines if line.startswith("choices ")]
    assert len(samples) == 32
    for _, mode, seed, next_rand, *choices in samples:
        mode = int(mode)
        oracle.write_u32(0x4428A0, 1 + (mode & 1))
        oracle.write_u8(0x452D84, bool(mode & 2))
        oracle.write_u32(0x43850C + 4, 1)
        oracle.write_u32(0x43850C + 16, 1)
        oracle.write_u32(0x43850C + 25 * 4, bool(mode & 4))
        oracle.rand_state = int(seed)
        oracle.call(0x408CF0)
        assert [i for i, flag in enumerate(oracle.read(0x43C598, 48)) if flag] == list(map(int, choices))
        assert oracle.call(0x422414).eax == int(next_rand)


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
                *game_sources(ROOT, Path(tmp)),
                ROOT / "crimson-core/checks/freeware_cycle.cpp",
                "-o",
                test,
            ],
            check=True,
        )
        lines = subprocess.check_output([test], text=True).splitlines()
    oracle = NativeOracle(exe, symbols=SymbolTable({}), rand_state_address=0x432C40)
    check_choices(oracle, lines)
    check_volleys(NativeOracle(exe, symbols=SymbolTable({}), rand_state_address=0x432C40), lines)
    oracle.write(0x442AF8, b"\x5a" * (512 * 128))
    oracle.write_u8(0x442AF8 + 2 * 128, 0)
    oracle.write_u32(0x4428A8, 2)
    oracle.write_f32(0x452DC4, 1.25)
    oracle.rand_state = 1
    slot = oracle.call(0x40FB70, oracle.alloc_f32s(1088, 643), oracle.alloc_f32s(0.4, 0.8, 0.6, 1), 1).eax_i32
    assert slot == 2
    assert f"spawn {oracle.read(0x442AF8 + slot * 128, 128).hex()}" in lines
    # Compare the Career spawner, armory (including both player strides) and the native .top codec.
    assert len([line for line in lines if line.startswith("career ")]) == 9
    for line in lines:
        if line.startswith("career "):
            _, seed, body = line.split()
            oracle.write(0x442AF8, bytes(512 * 128))
            oracle.write_u32(0x4384F8, 1731)
            oracle.write_u32(0x4428A8, 1)
            oracle.write_u32(0x452D8C, 0)
            oracle.rand_state = int(seed)
            edge = oracle.call(0x422414).eax % 4
            coord = oracle.call(0x422414).eax % 1024
            pos = [(coord, -40), (coord, 1064), (-40, coord), (1064, coord)][edge]
            assert oracle.call(0x40F650, oracle.alloc_f32s(*pos)).eax & 255 == 1
            original = oracle.read(0x442AF8, 128)
            assert original == bytes.fromhex(body), (
                seed,
                [(hex(i), a, b) for i, (a, b) in enumerate(zip(original, bytes.fromhex(body), strict=True)) if a != b],
            )
        elif line.startswith("weapon "):
            _, who, weapon, rounds, name = line.split(" ", 4)
            who, weapon = int(who), int(weapon)
            oracle.write_u8(0x452D59, 1)
            oracle.call(0x4065B0, who, weapon)
            assert oracle.read_f32(0x4384E4 + 392 * who) == float(rounds)
            ptr = oracle.call(0x406BB0, weapon).eax
            assert oracle.read(ptr, 64).split(b"\0")[0].decode() == name
        elif line.startswith("scores "):
            _, board, encoded = line.split()
            board = int(board)
            raw = bytes.fromhex(encoded)
            oracle.write_u32(0x4428A0, board % 2 + 1)
            oracle.write_u32(0x4428A8, board // 2 + 1)
            oracle.call(0x406E10)
            blob = oracle.alloc(len(raw), data=raw)
            assert oracle.call(0x406F20, blob, len(raw) - 4).eax & 255 == 1
            assert oracle.read(blob, 9) == b"Oracle 0\0"
            oracle.call(0x406EB0, blob, len(raw) - 4)
            assert oracle.read(blob, len(raw)) == raw
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
    print(next(line for line in lines if line.startswith("Natural Career:")))
    print("1.4.0 oracle passed: menu bounds, Career/Survival spawns, five bosses, twenty weapon IDs, perk RNG, four score formats, co-op, death and restart")


if __name__ == "__main__":
    main()
