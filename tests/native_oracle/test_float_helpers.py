"""Leaf float helpers: native code vs the Python port, bit for bit."""

from __future__ import annotations

import math
import random
import struct
from collections.abc import Callable

import pytest

from crimson.math_parity import (
    NATIVE_TAU,
    f32,
    x87_pc24_add,
    x87_pc24_cos_mul,
    x87_pc24_div,
    x87_pc24_mul,
    x87_pc24_sin_mul,
    x87_pc24_sqrt,
    x87_pc24_sub,
)
from crimson.sim.timing import ftol_ms_i32

from ._support import f32_bits, fmt_value

_SAMPLES = 4000


def _random_f32(rng: random.Random, lo: float, hi: float) -> float:
    return f32(rng.uniform(lo, hi))


def test_angle_approach_matches_native(oracle) -> None:
    """`angle_approach` (0x0041f430) vs `creatures.runtime._angle_approach`."""

    from crimson.creatures.runtime import _angle_approach

    rng = random.Random(0x41F430)
    tau = float(NATIVE_TAU)
    cases: list[tuple[float, float, float, float]] = []
    for _ in range(_SAMPLES):
        cases.append((
            _random_f32(rng, -2 * tau, 3 * tau),
            _random_f32(rng, 0.0, tau),
            _random_f32(rng, 0.05, 12.0),
            _random_f32(rng, 0.0005, 0.1),
        ))
    # Wrap-boundary and near-equal cases.
    for _ in range(_SAMPLES // 4):
        angle = _random_f32(rng, 0.0, tau)
        cases.append((angle, f32(angle + rng.choice((-1, 1)) * rng.uniform(0.0, 1e-3)), 4.0, 0.016))
        cases.append((f32(tau - rng.uniform(0.0, 1e-3)), f32(rng.uniform(0.0, 1e-3)), 4.0, 0.016))

    slot = oracle.alloc(4)
    failures = []
    for angle, target, rate, dt in cases:
        oracle.write_f32(slot, angle)
        oracle.write_f32("frame_dt", dt)
        oracle.call("angle_approach", slot, target, rate)
        native = oracle.read_f32(slot)
        python = _angle_approach(angle, target, rate, dt)
        if f32_bits(native) != f32_bits(python) or f32(python) != python:
            failures.append(
                f"angle={fmt_value(angle)} target={fmt_value(target)} rate={fmt_value(rate)} dt={fmt_value(dt)}: "
                f"native {fmt_value(native)} python {fmt_value(python)}",
            )
    assert not failures, f"{len(failures)}/{len(cases)} mismatches:\n" + "\n".join(failures[:20])


def test_crt_ftol_truncates_like_port(oracle) -> None:
    """`__ftol` (0x00461054) truncates toward zero regardless of the caller's rounding mode."""

    rng = random.Random(0x461054)
    values = [rng.uniform(-2.0e9, 2.0e9) for _ in range(_SAMPLES)]
    values += [rng.uniform(-4.0, 4.0) for _ in range(_SAMPLES)]
    values += [-0.5, 0.5, -1.0, 1.0, -0.0, 2147483647.0, -2147483648.0]
    failures = []
    for value in values:
        native = oracle.call("crt_ftol", st=(value,)).eax_i32
        if native != math.trunc(value):
            failures.append(f"{value!r}: native {native} python {math.trunc(value)}")
    assert not failures, "\n".join(failures[:20])


def test_ftol_ms_i32_matches_native_scale_and_ftol(oracle) -> None:
    """`ftol_ms_i32` vs native `fmul dword 1000.0f; call __ftol` at PC24."""

    thousand = oracle.alloc_f32s(1000.0)
    ftol = oracle.resolve("crt_ftol")
    probe = oracle.load_code(bytes(11))
    code = b"\xd8\x0d" + struct.pack("<I", thousand) + b"\xe9"  # fmul dword [1000.0f]; jmp __ftol
    code += struct.pack("<i", ftol - (probe + len(code) + 4))
    oracle.write(probe, code)
    rng = random.Random(0x1000)
    dts = [f32(rng.uniform(0.0, 0.2)) for _ in range(_SAMPLES)] + [f32(k / 1000.0) for k in range(200)]
    failures = []
    for dt in dts:
        native = oracle.call(probe, st=(dt,)).eax_i32
        if native != ftol_ms_i32(dt):
            failures.append(f"dt={fmt_value(dt)}: native {native} python {ftol_ms_i32(dt)}")
    assert not failures, "\n".join(failures[:20])


# ST0 = lhs, ST1 = rhs; `op st(0), st(1)`; ret.
_BINARY_OPS: dict[str, tuple[bytes, Callable[[float, float], float]]] = {
    "add": (b"\xd8\xc1\xc3", x87_pc24_add),
    "sub": (b"\xd8\xe1\xc3", x87_pc24_sub),
    "mul": (b"\xd8\xc9\xc3", x87_pc24_mul),
    "div": (b"\xd8\xf1\xc3", x87_pc24_div),
}


@pytest.mark.parametrize("op", sorted(_BINARY_OPS))
def test_x87_pc24_arithmetic_on_f32_operands(oracle, op: str) -> None:
    code, port = _BINARY_OPS[op]
    probe = oracle.load_code(code)
    rng = random.Random(op)
    failures = []
    for _ in range(_SAMPLES):
        lhs = f32(rng.uniform(-1e4, 1e4) * 10 ** rng.uniform(-6, 2))
        rhs = f32(rng.uniform(-1e4, 1e4) * 10 ** rng.uniform(-6, 2))
        native = oracle.call(probe, st=(lhs, rhs)).st0
        if f32_bits(native) != f32_bits(port(lhs, rhs)):
            failures.append(f"{lhs!r} {op} {rhs!r}: native {fmt_value(native)} python {fmt_value(port(lhs, rhs))}")
    assert not failures, "\n".join(failures[:20])


def test_x87_pc24_sqrt(oracle) -> None:
    probe = oracle.load_code(b"\xd9\xfa\xc3")  # fsqrt; ret
    rng = random.Random(0x5A)
    failures = []
    for _ in range(_SAMPLES):
        value = f32(rng.uniform(0.0, 1e6) * 10 ** rng.uniform(-6, 0))
        native = oracle.call(probe, st=(value,)).st0
        if f32_bits(native) != f32_bits(x87_pc24_sqrt(value)):
            failures.append(f"sqrt {value!r}: native {fmt_value(native)} python {fmt_value(x87_pc24_sqrt(value))}")
    assert not failures, "\n".join(failures[:20])


@pytest.mark.parametrize(("name", "opcode", "port"), [("cos", b"\xd9\xff", x87_pc24_cos_mul), ("sin", b"\xd9\xfe", x87_pc24_sin_mul)])
def test_x87_trig_then_pc24_multiply(oracle, name: str, opcode: bytes, port: Callable[..., float]) -> None:
    """`fcos|fsin; fmul dword [k]` vs `x87_pc24_{cos,sin}_mul`.

    Unicorn evaluates `fsin`/`fcos` with host double libm (like the port), so this
    checks the PC24 rounding structure around them, not x87 transcendental accuracy.
    """

    scale = oracle.alloc_f32s(1.5)
    probe = oracle.load_code(opcode + b"\xd8\x0d" + struct.pack("<I", scale) + b"\xc3")
    rng = random.Random(name)
    failures = []
    for _ in range(_SAMPLES):
        angle = f32(rng.uniform(-10.0, 10.0))
        native = oracle.call(probe, st=(angle,)).st0
        python = port(angle, 1.5)
        if f32_bits(native) != f32_bits(python):
            failures.append(f"{name}({angle!r})*1.5: native {fmt_value(native)} python {fmt_value(python)}")
    assert not failures, "\n".join(failures[:20])
