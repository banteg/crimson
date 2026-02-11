from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TypeAlias

from grim.geom import Vec2

PERK_COUNT_SIZE = 0x80


@dataclass(slots=True)
class PlayerState:
    index: int
    pos: Vec2
    health: float = 100.0
    size: float = 48.0

    speed_multiplier: float = 2.0
    move_speed: float = 0.0
    move_phase: float = 0.0
    heading: float = 0.0
    turn_speed: float = 1.0
    death_timer: float = 16.0
    low_health_timer: float = 100.0

    aim: Vec2 = field(default_factory=Vec2)
    aim_heading: float = 0.0
    aim_dir: Vec2 = field(default_factory=lambda: Vec2(1.0, 0.0))
    evil_eyes_target_creature: int = -1

    bonus_aim_hover_index: int = -1
    bonus_aim_hover_timer_ms: float = 0.0

    weapon_id: int = 1
    clip_size: int = 0
    ammo: float = 0.0
    reload_active: bool = False
    reload_timer: float = 0.0
    reload_timer_max: float = 0.0
    shot_cooldown: float = 0.0
    shot_seq: int = 0
    weapon_reset_latch: int = 0
    aux_timer: float = 0.0
    spread_heat: float = 0.01
    muzzle_flash_alpha: float = 0.0

    alt_weapon_id: int | None = None
    alt_clip_size: int = 0
    alt_ammo: float = 0.0
    alt_reload_active: bool = False
    alt_reload_timer: float = 0.0
    alt_reload_timer_max: float = 0.0
    alt_shot_cooldown: float = 0.0

    experience: int = 0
    level: int = 1

    perk_counts: list[int] = field(default_factory=lambda: [0] * PERK_COUNT_SIZE)
    plaguebearer_active: bool = False
    hot_tempered_timer: float = 0.0
    man_bomb_timer: float = 0.0
    living_fortress_timer: float = 0.0
    fire_cough_timer: float = 0.0

    speed_bonus_timer: float = 0.0
    shield_timer: float = 0.0
    fire_bullets_timer: float = 0.0


@dataclass(frozen=True, slots=True)
class BonusPickupEvent:
    player_index: int
    bonus_id: int
    amount: int
    pos: Vec2


GameplayState: TypeAlias = Any
