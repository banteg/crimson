"""Shared layouts and bit-exact comparison helpers for native-oracle differential tests."""

from __future__ import annotations

import math
import struct
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass

from crimson.effects import EFFECT_POOL_SIZE, EffectPool, SpriteEffect
from crimson.game_modes import GameMode
from crimson.math_parity import f32

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

# `sprite_effect_t` (0x2c bytes).
SPRITE_STRIDE = 0x2C
SPRITE_LAYOUT: dict[str, tuple[int, str]] = {
    "active": (0x00, "B"),
    "color_r": (0x04, "f"),
    "color_g": (0x08, "f"),
    "color_b": (0x0C, "f"),
    "color_a": (0x10, "f"),
    "rotation": (0x14, "f"),
    "pos_x": (0x18, "f"),
    "pos_y": (0x1C, "f"),
    "vel_x": (0x20, "f"),
    "vel_y": (0x24, "f"),
    "scale": (0x28, "f"),
}


def python_sprite(entry: SpriteEffect) -> dict[str, float | int]:
    return {
        "active": int(entry.active),
        "color_r": entry.color.r,
        "color_g": entry.color.g,
        "color_b": entry.color.b,
        "color_a": entry.color.a,
        "rotation": entry.rotation,
        "pos_x": entry.pos.x,
        "pos_y": entry.pos.y,
        "vel_x": entry.vel.x,
        "vel_y": entry.vel.y,
        "scale": entry.scale,
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
    to the x87 implementation that native captures resolve to. Attract mode stays
    off, matching the port's full-version play: a Survival run with its weapon
    availability refreshed (kills roll bonus drops) and the game tune already
    started (hits play their own sfx, like the port's `hit_audio_game_tune_started`).
    """

    oracle.call("weapon_table_init")
    oracle.call("effect_defaults_reset")
    oracle.stub("sfx_play_panned", 0)
    oracle.write_u32("vec2_normalize_impl", oracle.resolve("d3dx_c_vec2_normalize"))
    oracle.write_u8("demo_mode_active", 0)
    oracle.write_u8("music_playlist_randomized_latch", 1)
    oracle.write_u32("config_game_mode", int(GameMode.SURVIVAL))
    oracle.call("weapon_refresh_available")
    # Bonus amounts feed the kill-drop rejection; descriptions need font metrics.
    oracle.stub("wrap_text_to_width_alloc", 0)
    oracle.call("bonus_metadata_init")
    oracle.call("bonus_reset_availability")
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


# `effect_entry_t` (0xbc bytes) up to `scale_step`, then `next_free` at 0xb8.
_EFFECT_ENTRY_STRIDE = 0xBC
_EFFECT_ENTRY_NEXT_FREE = 0xB8
_EFFECT_ENTRY_FIELDS = (
    "pos_x", "pos_y", "effect_id", "vel_x", "vel_y", "rotation", "scale", "half_width", "half_height",
    "age", "lifetime", "flags", "color_r", "color_g", "color_b", "color_a", "rotation_step", "scale_step",
)  # fmt: skip
_EFFECT_ENTRY_FORMAT = struct.Struct("<2fB3x8fi6f")
# `effect_template_t` (0x3c bytes): the entry fields from `velocity` to `scale_step`.
_EFFECT_TEMPLATE_FIELDS = _EFFECT_ENTRY_FIELDS[3:]
_EFFECT_TEMPLATE_FORMAT = struct.Struct("<8fi6f")


def compare_effect_pool(oracle, pool: EffectPool, label: str) -> list[Mismatch]:
    """All 512 effect entries (free-list links included), the free-list head, the template and the skip counter."""

    base = oracle.resolve("effect_pool")

    def index(address: int) -> int:
        return (address - base) // _EFFECT_ENTRY_STRIDE if address else -1

    mismatches: list[Mismatch] = []
    raw = oracle.read(base, _EFFECT_ENTRY_STRIDE * EFFECT_POOL_SIZE)
    for slot, entry in enumerate(pool.entries):
        offset = slot * _EFFECT_ENTRY_STRIDE
        native = dict(zip(_EFFECT_ENTRY_FIELDS, _EFFECT_ENTRY_FORMAT.unpack_from(raw, offset), strict=True))
        native["next_free"] = index(struct.unpack_from("<I", raw, offset + _EFFECT_ENTRY_NEXT_FREE)[0])
        python = {
            "pos_x": entry.pos.x,
            "pos_y": entry.pos.y,
            "effect_id": entry.effect_id,
            "vel_x": entry.vel.x,
            "vel_y": entry.vel.y,
            "rotation": entry.rotation,
            "scale": entry.scale,
            "half_width": entry.half_width,
            "half_height": entry.half_height,
            "age": entry.age,
            "lifetime": entry.lifetime,
            "flags": entry.flags,
            "color_r": entry.color.r,
            "color_g": entry.color.g,
            "color_b": entry.color.b,
            "color_a": entry.color.a,
            "rotation_step": entry.rotation_step,
            "scale_step": entry.scale_step,
            "next_free": entry.next_free,
        }
        mismatches += compare_fields(f"{label} effect[{slot}]", native, python, address=base + offset)

    # The template slots are float32; the port rounds them when `effect_spawn` copies them.
    template_address = oracle.resolve("effect_template")
    native_template = dict(
        zip(_EFFECT_TEMPLATE_FIELDS, _EFFECT_TEMPLATE_FORMAT.unpack(oracle.read(template_address, 0x3C)), strict=True),
    )
    template = pool.template
    python_template = {
        "vel_x": f32(template.vel.x),
        "vel_y": f32(template.vel.y),
        "rotation": f32(template.rotation),
        "scale": f32(template.scale),
        "half_width": f32(template.half_width),
        "half_height": f32(template.half_height),
        "age": f32(template.age),
        "lifetime": f32(template.lifetime),
        "flags": template.flags,
        "color_r": f32(template.color.r),
        "color_g": f32(template.color.g),
        "color_b": f32(template.color.b),
        "color_a": f32(template.color.a),
        "rotation_step": f32(template.rotation_step),
        "scale_step": f32(template.scale_step),
    }
    mismatches += compare_fields(f"{label} template", native_template, python_template, address=template_address)

    for name, native_value, python_value in (
        ("effect_free_list_head", index(oracle.read_u32("effect_free_list_head")), pool._free_head),
        ("effect_spawn_detail_skip_counter", oracle.read_u32("effect_spawn_detail_skip_counter"), pool._detail_skip_counter),
    ):
        if native_value != python_value:
            mismatches.append(Mismatch(label, name, native_value, python_value, 0))
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
