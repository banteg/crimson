"""Bounded fixtures and an independent rational x87 corner oracle."""

import itertools
import random
import struct
from fractions import Fraction

TYPES = (*range(8), 29)
CONTROL_WORDS = (0x037F, 0x007F)


def f32(value):
    return struct.unpack("<f", struct.pack("<f", value))[0]


def power2(exponent):
    return Fraction(2**exponent) if exponent >= 0 else Fraction(1, 2**-exponent)


def round_significand(value, precision):
    """Round a rational to nearest, ties to even, without a host-float intermediate."""
    if not value:
        return value
    sign = -1 if value < 0 else 1
    value = abs(value)
    exponent = value.numerator.bit_length() - value.denominator.bit_length()
    if value < power2(exponent):
        exponent -= 1
    unit = power2(exponent - precision + 1)
    quotient, remainder = divmod(value / unit, 1)
    quotient = int(quotient)
    if remainder > Fraction(1, 2) or remainder == Fraction(1, 2) and quotient % 2:
        quotient += 1
    return sign * quotient * unit


def corner_bits(row, camera, control_word, *, previous_source=False):
    """Model native finite, normal-range fixtures at 0x4230e5..0x42363a.

    Stored X width serves the origin pair; wider X width serves the head pair.
    Scaled branches store head X between its plus and minus corners. Assault
    duplicates the wide sum instead. Y screen sums and widths are stored first.
    """
    assert control_word in CONTROL_WORDS
    precision = 24 if control_word == 0x007F else 64

    def operand(value):
        return Fraction(f32(value))

    def arithmetic(value):
        return round_significand(value, precision)

    def store(value):
        return round_significand(value, 24)

    def result(value):
        # The rational is binary32-representable before conversion to binary64.
        return struct.unpack("<I", struct.pack("<f", float(store(arithmetic(value)))))[0]

    factor = operand({1: 1.2, 2: 1.0, 6: 1.1}.get(row["type_id"], 0.7))
    width_x = arithmetic(operand(row["velocity"][0]) * factor)
    width_y = store(arithmetic(operand(row["velocity"][1]) * factor))
    origin_x = arithmetic(operand(camera[0]) + operand(row["origin"][0]))
    origin_y = store(arithmetic(operand(camera[1]) + operand(row["origin"][1])))
    head_x = arithmetic(operand(camera[0]) + operand(row["position"][0]))
    head_y = store(arithmetic(operand(camera[1]) + operand(row["position"][1])))
    origin_width_x = width_x if previous_source else store(width_x)
    plus_head_x = store(head_x) if previous_source and row["type_id"] in (1, 6) else head_x
    minus_head_x = head_x if row["type_id"] == 2 else store(head_x)
    if previous_source:
        minus_head_x = store(head_x) if row["type_id"] in (1, 6) else head_x
    return [
        result(origin_x - origin_width_x),
        result(origin_y - width_y),
        result(origin_x + origin_width_x),
        result(origin_y + width_y),
        result(plus_head_x + width_x),
        result(head_y + width_y),
        result(minus_head_x - width_x),
        result(head_y - width_y),
    ]


def record(
    type_id,
    *,
    index=0,
    active=1,
    life=0.2,
    angle=0.3,
    position=(111.25, 208.5),
    origin=(50.125, 91.75),
    velocity=(0.6, -0.8),
):
    return {
        "index": index,
        "type_id": type_id,
        "active": active,
        "life": f32(life),
        "angle": f32(angle),
        "position": list(map(f32, position)),
        "origin": list(map(f32, origin)),
        "velocity": list(map(f32, velocity)),
    }


def case(group, records, *, control_word=0x037F, alpha=0.7, glow=1, camera=(13.125, -21.75)):
    return {
        "group": group,
        "records": records,
        "fpcw": control_word,
        "alpha": f32(alpha),
        "glow": glow,
        "camera": list(map(f32, camera)),
    }


def fixtures():
    # Reproduce the full discovery matrix, including all 61 prior-source failures.
    rng = random.Random(0x4234E7)
    for index in range(160):
        span = 32 if index % 2 else 2048
        position = [f32(rng.uniform(-span, span)) for _ in range(2)]
        origin = [f32(rng.uniform(-span, span)) for _ in range(2)]
        velocity = [f32(rng.uniform(-1, 1)) for _ in range(2)]
        for kind, cw in itertools.product((1, 2, 3, 6), CONTROL_WORDS):
            yield case(
                "discovery",
                [record(kind, position=position, origin=origin, velocity=velocity)],
                control_word=cw,
            )
    for index, kind, life, alpha, glow, cw in itertools.product(
        (0, 1, 47, 95),
        TYPES,
        (-0.1, 0.0, 0.2, 0.39, 0.4, 1.2),
        (0.0, 0.7),
        (0, 1),
        CONTROL_WORDS,
    ):
        yield case("pool-and-gates", [record(kind, index=index, life=life)], control_word=cw, alpha=alpha, glow=glow)
    for kind, active, cw in itertools.product(TYPES, (0, 2), CONTROL_WORDS):
        yield case("active-byte", [record(kind, index=95, active=active)], control_word=cw)
    for alpha, glow, cw in itertools.product((0.0, 0.7), (0, 1), CONTROL_WORDS):
        yield case("empty", [], control_word=cw, alpha=alpha, glow=glow)
    for arrangement, alpha, glow, cw in itertools.product(range(3), (0.0, 0.7, 1.5), (0, 1), CONTROL_WORDS):
        indices = (tuple(range(9)), (0, 1, 2, 31, 47, 48, 93, 94, 95), tuple(range(87, 96)))[arrangement]
        rows = [
            record(
                kind,
                index=index,
                active=0 if order == arrangement else 1,
                life=(0.0, 0.2, 0.4)[order % 3],
                position=(31.672157287597656 + order, -13.814879417419434 - order),
                origin=(-31.661039352416992 + order, -16.981664657592773 - order),
                velocity=(0.34550151228904724, 0.19489352405071259),
            )
            for order, (kind, index) in enumerate(zip(TYPES, indices, strict=True))
        ]
        yield case("mixed", list(reversed(rows)), control_word=cw, alpha=alpha, glow=glow)
    rng = random.Random(0x4231F3)
    for index in range(128):
        camera = [f32(rng.uniform(-1024, 1024)) for _ in range(2)]
        position = [f32(rng.uniform(-2048, 2048)) for _ in range(2)]
        origin = [f32(rng.uniform(-2048, 2048)) for _ in range(2)]
        velocity = [f32(rng.uniform(-2, 2)) for _ in range(2)]
        for kind, cw in itertools.product((1, 2, 3, 6), CONTROL_WORDS):
            yield case(
                "moving-camera",
                [record(kind, index=index % 96, position=position, origin=origin, velocity=velocity)],
                control_word=cw,
                camera=camera,
            )
    for velocity, cw in itertools.product(((0.0, 0.0), (1.5, 0.0), (0.0, 1.5)), CONTROL_WORDS):
        yield case(
            "coincident",
            [
                record(kind, index=i, position=(-13.125, 21.75), origin=(-13.125, 21.75), velocity=velocity)
                for i, kind in enumerate(TYPES)
            ],
            control_word=cw,
        )
