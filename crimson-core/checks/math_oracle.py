"""Check gameplay math against real x87 instructions, not an oracle stub.

Normalize calls D3DX8's concrete x87 implementation (0x00455587). Level-up
checks both CRT __CIpow and the original gameplay threshold instruction range.
This adjudicates these seams only; it is not whole-run original equivalence.
"""

import argparse
import json
import math
import random
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from builder_oracle import read_snapshots

from crimson.gameplay import survival_level_threshold
from crimson.math_parity import x87_pc24_crt_pow
from crimson_re.dbg.native_oracle import NativeOracle
from grim.geom import Vec2

HERE = Path(__file__).resolve().parent
CORE = HERE.parent


def f32(value):
    return struct.unpack("<f", struct.pack("<f", value))[0]


def from_bits(value):
    return struct.unpack("<f", struct.pack("<I", value))[0]


def vectors():
    # FLT_MIN squared-length gate, near-unit early return, signs, and aliasing.
    cases = [(0.0, 0.0), (-0.0, -0.0), (0.6, 0.8), (100.0, 50.0)]
    for boundary in (0x3F800000, 0x20000000):  # 1, sqrt(FLT_MIN)
        for bits in range(boundary - 8, boundary + 9):
            for sign in (1, -1):
                cases.extend([(sign * from_bits(bits), 0.0), (0.0, sign * from_bits(bits))])
    rng = random.Random(0x455587)
    for _ in range(1024):
        angle = rng.uniform(-math.pi, math.pi)
        cases.append((math.cos(angle), math.sin(angle)))
    for _ in range(1024):
        # All finite float32 exponent ranges, including product overflow and
        # underflow. The original's F32 spills matter as well as PC24 precision.
        pair = [from_bits(rng.randrange(0x7F800000)) * rng.choice((-1, 1)) for _ in range(2)]
        cases.append(tuple(pair))
    return [struct.unpack("<2f", struct.pack("<2f", *case)) for case in cases]


def movement_products():
    # Include the exact heading/speed at the old snapshot-257 divergence.
    cases = [(f32(f32(5.9573140144348145) - f32(1.5707964)), 0.8333332538604736)]
    rng = random.Random(0x414335)
    cases += [(f32(rng.uniform(-7, 13)), f32(rng.uniform(0, 2.8))) for _ in range(1500)]
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--build", type=Path, default=CORE / "build")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    samples = vectors()
    products = movement_products()
    cases = (
        [(operation, *struct.unpack("<2I", struct.pack("<2f", *vector))) for vector in samples for operation in (1, 3)]
        + [(2, level, 0) for level in range(1, 2001)]
        + [(4, *struct.unpack("<2I", struct.pack("<2f", *case))) for case in products]
    )
    payload = b"".join(struct.pack("<3I", *case) for case in cases)
    native = subprocess.check_output([str(args.build / "native/core"), "--math-probe"], input=payload)
    with tempfile.NamedTemporaryFile() as source:
        source.write(payload)
        source.flush()
        wasm = subprocess.check_output(
            [shutil.which("node"), str(HERE / "math_probe.mjs"), source.name, str(args.build / "wasm/core.wasm")],
        )
    if native != wasm:
        raise ValueError("Native/WASM math probes differ")
    snapshots = read_snapshots(native)
    if len(snapshots) != len(cases):
        raise ValueError("Missing math snapshots")
    oracle = NativeOracle(args.exe)
    source, target = oracle.alloc(8), oracle.alloc(8)
    differences, python_differences = [], []
    for case, actual in zip(cases, snapshots, strict=True):
        operation, a, b = case
        if operation in (1, 3):
            packed = struct.pack("<2I", a, b)
            oracle.write(source, packed)
            out = source if operation == 3 else target
            result = oracle.call(0x00455587, out, source)
            if result.eax != out:
                raise ValueError("Original normalize return pointer differs")
            expected = oracle.read(out, 8)
            reference = Vec2(*struct.unpack("<2f", packed)).normalized()
            python = struct.pack("<2f", reference.x, reference.y)
        elif operation == 2:
            exponent = f32(1.8)
            power = oracle.call("crt_ci_pow", st=(exponent, float(a))).st0
            oracle.write_u32("player_level", a)
            oracle.run(0x0040AFAE, 0x0040AFCE, regs={"esi": 1000})
            threshold = struct.unpack("<i", struct.pack("<I", oracle.reg("ecx")))[0]
            expected = struct.pack("<fi", power, threshold)
            python = struct.pack("<fi", x87_pc24_crt_pow(float(a), exponent), survival_level_threshold(a))
        else:
            angle, speed = struct.unpack("<2f", struct.pack("<2I", a, b))
            player = oracle.resolve("player_state_table")
            oracle.write_f32(player + 0x68, speed)
            cosine = oracle.run(0x00414335, 0x0041433C, regs={"edi": player}, st=(angle, 0.0)).st0
            sine = oracle.run(0x00414356, 0x0041435B, regs={"edi": player}, st=(angle,)).st0
            expected = struct.pack("<2f", cosine, sine)
            python = struct.pack("<2f", math.cos(angle) * speed, math.sin(angle) * speed)
        if expected != actual:
            differences.append({"case": case, "original": expected.hex(), "recovered": actual.hex()})
        if expected != python:
            python_differences.append({"case": case, "original": expected.hex(), "python": python.hex()})
    report = {
        "cases": len(cases),
        "normalize_vectors": len(samples),
        "normalize_alias_modes": 2,
        "levels": 2000,
        "movement_trig_products": len(products),
        "x87_control_word": "0x007f",
        "native_wasm": "bit exact",
        "original_mismatches": differences,
        "python_original_mismatches": python_differences,
    }
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    # Python is a comparison baseline, not the authority. Record its extreme
    # vector discrepancies without weakening the recovered-vs-original gate.
    if differences:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
