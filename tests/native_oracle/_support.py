"""Shared layouts and bit-exact comparison helpers for native-oracle differential tests."""

from __future__ import annotations

import math
import struct
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass

# `creature_t` (0x98 bytes), third_party/headers/crimsonland_types.h.
CREATURE_STRIDE = 0x98
CREATURE_POOL_SLOTS = 0x180
CREATURE_LAYOUT: dict[str, tuple[int, str]] = {
    "active": (0x00, "B"),
    "phase_seed": (0x04, "i"),
    "lifecycle_stage": (0x10, "f"),
    "pos_x": (0x14, "f"),
    "pos_y": (0x18, "f"),
    "vel_x": (0x1C, "f"),
    "vel_y": (0x20, "f"),
    "health": (0x24, "f"),
    "max_health": (0x28, "f"),
    "heading": (0x2C, "f"),
    "size": (0x34, "f"),
    "tint_r": (0x3C, "f"),
    "tint_g": (0x40, "f"),
    "tint_b": (0x44, "f"),
    "tint_a": (0x48, "f"),
    "contact_damage": (0x58, "f"),
    "move_speed": (0x5C, "f"),
    "reward_value": (0x64, "f"),
    "type_id": (0x6C, "i"),
    "link_index": (0x78, "i"),
    "target_offset_x": (0x7C, "f"),
    "target_offset_y": (0x80, "f"),
    "orbit_angle": (0x84, "f"),
    "orbit_radius": (0x88, "f"),
    "flags": (0x8C, "i"),
    "ai_mode": (0x90, "i"),
}

# `creature_spawn_slot_t` (0x18 bytes).
SPAWN_SLOT_STRIDE = 0x18
SPAWN_SLOT_LAYOUT: dict[str, tuple[int, str]] = {
    "owner": (0x00, "I"),
    "count": (0x04, "i"),
    "limit": (0x08, "i"),
    "interval": (0x0C, "f"),
    "timer": (0x10, "f"),
    "template_id": (0x14, "i"),
}

# `projectile_t` (0x40 bytes).
PROJECTILE_STRIDE = 0x40
PROJECTILE_LAYOUT: dict[str, tuple[int, str]] = {
    "active": (0x00, "B"),
    "angle": (0x04, "f"),
    "pos_x": (0x08, "f"),
    "pos_y": (0x0C, "f"),
    "origin_x": (0x10, "f"),
    "origin_y": (0x14, "f"),
    "vel_x": (0x18, "f"),
    "vel_y": (0x1C, "f"),
    "type_id": (0x20, "i"),
    "life_timer": (0x24, "f"),
    "reserved": (0x28, "f"),
    "speed_scale": (0x2C, "f"),
    "damage_pool": (0x30, "f"),
    "hit_radius": (0x34, "f"),
    "travel_budget": (0x38, "f"),
    "owner_id": (0x3C, "i"),
}

# `secondary_projectile_t` (0x2c bytes). Detonations keep their timer and scale in `vel_x`/`vel_y`.
SECONDARY_PROJECTILE_STRIDE = 0x2C
SECONDARY_PROJECTILE_LAYOUT: dict[str, tuple[int, str]] = {
    "active": (0x00, "B"),
    "angle": (0x04, "f"),
    "life_timer": (0x08, "f"),
    "pos_x": (0x0C, "f"),
    "pos_y": (0x10, "f"),
    "vel_x": (0x14, "f"),
    "vel_y": (0x18, "f"),
    "type_id": (0x1C, "i"),
    "trail_timer": (0x20, "f"),
    "target_id": (0x24, "i"),
}

# `particle_t` (0x38 bytes).
PARTICLE_STRIDE = 0x38
PARTICLE_LAYOUT: dict[str, tuple[int, str]] = {
    "active": (0x00, "B"),
    "pos_x": (0x04, "f"),
    "pos_y": (0x08, "f"),
    "vel_x": (0x0C, "f"),
    "vel_y": (0x10, "f"),
    "intensity": (0x24, "f"),
    "angle": (0x28, "f"),
    "style_id": (0x30, "B"),
}

# `player_state_t` field offsets (stride 0x360), from analysis/ghidra/maps/data_map.json.
PLAYER_STRIDE = 0x360
PLAYER_OFFSETS = {
    "pos_x": 0x14,
    "pos_y": 0x18,
    "health": 0x24,
    "size": 0x34,
    "aim_x": 0x50,
    "aim_y": 0x54,
    "spread_heat": 0x2B8,
    "weapon_id": 0x2C0,
    "clip_size": 0x2C4,
    "ammo": 0x2CC,
    "aim_heading": 0x300,
}


def prepare_gameplay(oracle, *, world_size: int = 1024) -> None:
    """Seed the startup state that `projectile_update` and the fire paths need.

    The D3DX normalize dispatcher probes the CPU and registry on first use; bind it
    to the x87 implementation that native captures resolve to. Demo mode keeps
    kills from rolling bonus drops, matching the port's demo world.
    """

    oracle.call("weapon_table_init")
    oracle.call("effect_defaults_reset")
    oracle.stub("sfx_play_panned", 0)
    oracle.write_u32("vec2_normalize_impl", oracle.resolve("d3dx_c_vec2_normalize"))
    oracle.write_u8("demo_mode_active", 1)
    oracle.write_u32("terrain_texture_width", world_size)
    oracle.write_u32("terrain_texture_height", world_size)
    oracle.write_u32("config_player_count", 1)
    oracle.write_u32("shock_chain_projectile_id", 0xFFFF_FFFF)
    # A zeroed cvar: friendly fire off.
    oracle.write_u32("cv_friendlyFire", oracle.alloc(0x40))


def f32_bits(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0]


def is_f32(value: float) -> bool:
    return math.isnan(value) or struct.unpack("<f", struct.pack("<f", value))[0] == value


def fmt_value(value: float) -> str:
    if isinstance(value, float):
        if not is_f32(value):
            return f"{value!r} (not f32; f32 0x{f32_bits(value):08x})"
        return f"{value!r} (0x{f32_bits(value):08x})"
    return repr(value)


@dataclass(frozen=True, slots=True)
class Mismatch:
    case: str
    field: str
    native: float | int
    python: float | int
    address: int

    @property
    def kind(self) -> str:
        """`bits`: different float32/int value; `unrounded`: same f32 bits but Python keeps a wider double."""

        if isinstance(self.native, float) and f32_bits(float(self.python)) == f32_bits(self.native):
            return "unrounded"
        return "bits"

    def __str__(self) -> str:
        return (
            f"[{self.kind}] {self.case} {self.field} @0x{self.address:08x}: native {fmt_value(self.native)} "
            f"!= python {fmt_value(self.python)}"
        )


def compare_fields(
    case: str,
    native: Mapping[str, float | int],
    python: Mapping[str, float | int | None],
    *,
    address: int,
) -> list[Mismatch]:
    """Compare Python values against native ones bit-for-bit (None = not modelled)."""

    mismatches = []
    for name, python_value in python.items():
        if python_value is None:
            continue
        native_value = native[name]
        if isinstance(native_value, float):
            python_float = float(python_value)
            same = is_f32(python_float) and f32_bits(python_float) == f32_bits(native_value)
        else:
            same = int(python_value) == native_value
        if not same:
            mismatches.append(Mismatch(case, name, native_value, python_value, address))
    return mismatches


def mismatch_report(mismatches: list[Mismatch], *, total_cases: int, limit: int = 40) -> str:
    """Summarize by kind and field; list the first examples of each (field, kind) group."""

    by_group = Counter((mismatch.kind, mismatch.field) for mismatch in mismatches)
    lines = [f"{len(mismatches)} mismatching fields over {total_cases} cases"]
    lines.extend(f"  {kind:9} {field}: {count}" for (kind, field), count in sorted(by_group.items()))
    shown: Counter[tuple[str, str]] = Counter()
    for mismatch in sorted(mismatches, key=lambda m: m.kind):
        group = (mismatch.kind, mismatch.field)
        if shown[group] < 3 and sum(shown.values()) < limit:
            shown[group] += 1
            lines.append(str(mismatch))
    return "\n".join(lines)
