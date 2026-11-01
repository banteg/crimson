"""Compare early Survival spawns with their respective x86 executables and exercise the shipped 1.3.0 maps."""

import argparse
import hashlib
import json
import math
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from crimson_re.dbg.native_oracle import NativeOracle, SymbolTable

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "crimson-core"))
from freeware.build import game_flags, game_sources

# spawn, pool, elapsed seconds, spawn count, game mode, CRT seed
ADDRESSES = {
    "1.0.2": (0x4067A0, 0x4252D0, 0x428810, 0x428868, 0x41C0A0, 0x41DCC8),
    "1.3.0": (0x40BA70, 0x4374F8, 0x447784, 0x44780C, 0x4374B0, 0x42B634),
}


def check(edition, install, tmp, web):
    exe = install / "crimson.exe"
    registry = json.loads((ROOT / "decomp/builds.json").read_text())
    build = next(b for b in registry["builds"] if b["id"] == edition)
    assert hashlib.sha256(exe.read_bytes()).hexdigest() == next(
        i["sha256"] for i in build["images"] if i["name"] == exe.name
    )

    def tool(name):
        result = shutil.which(name)
        if not result:
            raise SystemExit(f"{name} is required")
        return result

    sources = [*game_flags(ROOT, edition), *game_sources(ROOT, tmp), ROOT / "crimson-core/checks/freeware_early.cpp"]
    binary = tmp / edition
    subprocess.run([tool("clang++"), *sources, "-o", binary], check=True)
    lines = subprocess.check_output([binary, install], text=True).splitlines()
    if web:
        js = tmp / f"early-{edition}.js"
        subprocess.run([tool("em++"), *sources, "-sENVIRONMENT=node", "-sNODERAWFS", "-o", js], check=True)
        wasm = subprocess.check_output([tool("node"), js, install], text=True).splitlines()
        # Compare the original-facing observations. Both runs also assert the complete menu and score cycle.
        prefixes = ("spawn ", "wall ")
        assert [s for s in lines if s.startswith(prefixes)] == [s for s in wasm if s.startswith(prefixes)]
    early = edition == "1.0.2"
    spawn, pool, elapsed, counter, mode_addr, seed_addr = ADDRESSES[edition]
    pe = NativeOracle(exe, symbols=SymbolTable({}), rand_state_address=seed_addr)
    stride = 104 if early else 128
    pos = pe.alloc(8)
    tint = pe.alloc_f32s(0.25, 0.5, 0.75, 1)
    if not early:
        level = pe.alloc(128)
        wall = pe.alloc(48, data=struct.pack("<5f", 106, 90, 0, 10, 20) + bytes(28))
        walls = pe.alloc(4, data=struct.pack("<I", wall))
        pe.write_u32(0x433F10, level)
        pe.write(level + 0x28, struct.pack("<2I", walls, walls + 4))
        pe.write_f32(0x447828, 1 / 60)
        start = pe.alloc_f32s(100, 100)
        records = [line.split() for line in lines if line.startswith("wall ")]
        assert len(records) == 6
        assert any(r[2:4] == ["1", "1"] for r in records), "missing wall ricochet case"
        for _, seed, slot, active, x, y, life, rng in records:
            if slot == "0":
                pe.write(0x4307D0, bytes(64 * 52))
                pe.rand_state = int(seed)
                pe.call(0x4060D0, start, 1.57079637, 1)
                pe.call(0x406260)
            shot = 0x4307D0 + int(slot) * 52
            assert pe.read_u8(shot) == int(active) and pe.rand_state == int(rng), (seed, slot, rng)
            for offset, value in [(8, x), (12, y), (36, life)]:
                assert math.isclose(pe.read_f32(shot + offset), float(value), abs_tol=1e-4), (seed, slot, offset, value)
    previous = None
    cases = 0
    for line in lines:
        if not line.startswith("spawn "):
            continue
        _, mode, seed, x, y, slot, count, rng, *values = line.split()
        if previous != (mode, seed):
            pe.write(pool, bytes((128 if early else 512) * stride))
            pe.write_u32(counter, 0)
            pe.write_f32(elapsed, 12.5)
            pe.write_u32(mode_addr, int(mode))
            pe.rand_state = int(seed)
            previous = mode, seed
        pe.write(pos, struct.pack("<2f", float(x), float(y)))
        ret = pe.call(spawn, pos, tint, 1).eax
        assert pe.rand_state == int(rng) and pe.read_u32(counter) == int(count), line
        if early:
            assert bool(ret & 255) == (int(slot) >= 0), line
        else:
            assert ret == int(slot), line
        if int(slot) >= 0:
            record = pe.read(pool + int(slot) * stride, stride)
            offsets = (12, 16, 28, 32, 72, 36, 80, 68, 40) if early else (24, 28, 40, 44, 88, 52, 96, 84, 56)
            xoff, yoff, hp, heading, speed, size, reward, damage, color = offsets
            fields = [struct.unpack_from("<f", record, offset)[0] for offset in (xoff, yoff, hp, heading, speed, size)]
            fields.append(struct.unpack_from("<i" if early else "<d", record, reward)[0])
            fields.append(struct.unpack_from("<f", record, damage)[0])
            fields.extend(struct.unpack_from("<4f", record, color))
            assert all(math.isclose(a, float(b), rel_tol=1e-7) for a, b in zip(fields, values, strict=True)), (
                line,
                fields,
            )
        cases += 1
    assert cases == (15 if early else 30)
    print(f"{edition}: {cases} original spawn calls matched, including final CRT state")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("installs", type=Path, help="parent directory containing the original release folders")
    parser.add_argument("--web", action="store_true", help="also run the Emscripten game code under Node")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        for edition in ADDRESSES:
            check(edition, (args.installs / edition).resolve(), Path(tmp), args.web)
