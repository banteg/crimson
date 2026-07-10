from __future__ import annotations

import msgspec

from ..sim.input_providers import ReplayPostludeOperation, ReplayPreludeOperation, ReplayTickCommand
from ..sim.timing import ftol_ms_i32


class SnapshotVec2(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    x: float
    y: float


class SnapshotWeapon(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    weapon_id: int
    ammo: float
    clip_size: int
    reload_active: bool
    reload_timer: float
    reload_timer_max: float
    shot_cooldown: float


class SnapshotPlayer(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    index: int
    pos: SnapshotVec2
    heading: float
    move_speed: float
    move_phase: float
    aim: SnapshotVec2
    aim_heading: float
    health: float
    weapon: SnapshotWeapon
    experience: int
    level: int


class ReplayInputSample(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    move_x: float
    move_y: float
    aim_x: float
    aim_y: float
    flags: int


class ReplayStepSnapshot(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    dt: float
    inputs: list[ReplayInputSample]
    prelude: list[ReplayPreludeOperation]
    postlude: list[ReplayPostludeOperation]
    commands: list[ReplayTickCommand]


class SnapshotBonusTimers(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    weapon_power_up_ms: int
    reflex_boost_ms: int
    energizer_ms: int
    double_experience_ms: int
    freeze_ms: int


class SnapshotGameplay(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    mode_id: int
    quest_stage_major: int
    quest_stage_minor: int
    perk_pending_count: int
    perk_choices_dirty: bool
    bonus_timers: SnapshotBonusTimers


class SimStateSnapshot(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    gameplay: SnapshotGameplay
    players: list[SnapshotPlayer]


class RngStreamRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    tick_call_index: int
    value_15: int
    state_before_u32: int
    state_after_u32: int
    caller: int | None


class TimingSampleRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    tick_index: int
    gameplay_frame: int | None
    phase: str
    write_kind: str
    frame_dt_f32: float | None
    frame_dt_ms_i32: int | None
    frame_dt_ms_f32: float | None
    time_scale_active_entry: bool | None
    time_scale_active_current: bool | None
    time_scale_factor: float | None
    bonus_reflex_boost_timer: float | None
    mode_fn: str | None
    player_index: int | None


class CreatureEntitySample(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    uid: int
    generation: int
    pool_kind: str
    index: int
    active: bool
    type_id: int
    hp: float
    pos: SnapshotVec2
    flags: int
    ai_mode: int
    link_index: int
    force_target: int
    target: SnapshotVec2
    target_player: int
    target_offset: SnapshotVec2
    heading: float
    target_heading: float
    collision_timer: float
    attack_cooldown: float
    orbit_angle: float
    orbit_radius: float
    lifecycle_stage: float
    vel: SnapshotVec2
    move_speed: float


class ProjectileEntitySample(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    uid: int
    generation: int
    pool_kind: str
    index: int
    active: bool
    type_id: int
    angle: float
    pos: SnapshotVec2
    vel: SnapshotVec2
    life_timer: float
    speed_scale: float
    damage_pool: float
    hit_radius: float
    travel_budget: float
    owner_id: int


class SecondaryProjectileEntitySample(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    uid: int
    generation: int
    pool_kind: str
    index: int
    active: bool
    type_id: int
    angle: float
    pos: SnapshotVec2
    vel: SnapshotVec2
    speed: float
    trail_timer: float
    owner_id: int
    target_id: int


class BonusEntitySample(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    uid: int
    generation: int
    pool_kind: str
    index: int
    active: bool
    bonus_id: int
    picked: bool
    time_left: float
    time_max: float
    pos: SnapshotVec2
    amount: int


class EntitySamplesSnapshot(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    creatures: list[CreatureEntitySample]
    projectiles: list[ProjectileEntitySample]
    secondary_projectiles: list[SecondaryProjectileEntitySample]
    bonuses: list[BonusEntitySample]


_ENTITY_KIND_IDS = {
    "creature": 1,
    "projectile": 2,
    "secondary_projectile": 3,
    "bonus": 4,
}


def entity_uid(*, pool_kind: str, index: int, generation: int) -> int:
    """Return a trace-wide entity id unique across pools and slot reuse."""

    try:
        kind_id = _ENTITY_KIND_IDS[str(pool_kind)]
    except KeyError as exc:
        raise ValueError(f"unknown entity pool kind: {pool_kind!r}") from exc
    slot = int(index)
    lifetime = int(generation)
    if not (0 <= slot < 1_000_000):
        raise ValueError(f"entity pool index out of range: {slot}")
    if not (0 <= lifetime < 1_000):
        raise ValueError(f"entity generation out of range: {lifetime}")
    return int(kind_id * 1_000_000_000 + lifetime * 1_000_000 + slot)


def bonus_timer_ms(value: float) -> int:
    return max(0, int(ftol_ms_i32(float(value))))
