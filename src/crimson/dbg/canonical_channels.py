from __future__ import annotations

import msgspec

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
    health: float
    weapon: SnapshotWeapon
    experience: int
    level: int

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
    caller: int | None = None


class TimingSampleRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    tick_index: int
    gameplay_frame: int | None = None
    phase: str = ""
    write_kind: str = "snapshot"
    frame_dt_f32: float | None = None
    frame_dt_ms_i32: int | None = None
    frame_dt_ms_f32: float | None = None
    time_scale_active_entry: bool | None = None
    time_scale_active_current: bool | None = None
    time_scale_factor: float | None = None
    bonus_reflex_boost_timer: float | None = None
    mode_fn: str | None = None
    player_index: int | None = None


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
    heading: float
    target_heading: float
    orbit_angle: float
    orbit_radius: float
    lifecycle_stage: float
    # Movement channels (capture v14+); None in older traces. These pin down
    # which factor diverges when the per-tick velocity product drifts by ulps.
    vel: SnapshotVec2 | None = None
    move_speed: float | None = None


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


def bonus_timer_ms(value: float) -> int:
    return max(0, int(ftol_ms_i32(float(value))))
