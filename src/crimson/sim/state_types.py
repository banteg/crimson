from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeAlias

from grim.geom import Vec2

PERK_COUNT_SIZE = 0x80


@dataclass(slots=True)
class WeaponSlot:
    weapon_id: int
    clip_size: int = 0
    ammo: float = 0.0
    reload_active: bool = False
    reload_timer: float = 0.0
    reload_timer_max: float = 0.0
    shot_cooldown: float = 0.0


@dataclass(slots=True, init=False)
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
    auto_target: int = -1

    bonus_aim_hover_index: int = -1
    bonus_aim_hover_timer_ms: float = 0.0

    weapon: WeaponSlot = field(default_factory=lambda: WeaponSlot(weapon_id=1))
    alt_weapon: WeaponSlot | None = None

    shot_seq: int = 0
    weapon_reset_latch: int = 0
    aux_timer: float = 0.0
    spread_heat: float = 0.01
    muzzle_flash_alpha: float = 0.0

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

    def __init__(
        self,
        index: int,
        pos: Vec2,
        *,
        health: float = 100.0,
        size: float = 48.0,
        speed_multiplier: float = 2.0,
        move_speed: float = 0.0,
        move_phase: float = 0.0,
        heading: float = 0.0,
        turn_speed: float = 1.0,
        death_timer: float = 16.0,
        low_health_timer: float = 100.0,
        aim: Vec2 | None = None,
        aim_heading: float = 0.0,
        aim_dir: Vec2 | None = None,
        evil_eyes_target_creature: int = -1,
        auto_target: int = -1,
        bonus_aim_hover_index: int = -1,
        bonus_aim_hover_timer_ms: float = 0.0,
        weapon: WeaponSlot | None = None,
        alt_weapon: WeaponSlot | None = None,
        shot_seq: int = 0,
        weapon_reset_latch: int = 0,
        aux_timer: float = 0.0,
        spread_heat: float = 0.01,
        muzzle_flash_alpha: float = 0.0,
        experience: int = 0,
        level: int = 1,
        perk_counts: list[int] | None = None,
        plaguebearer_active: bool = False,
        hot_tempered_timer: float = 0.0,
        man_bomb_timer: float = 0.0,
        living_fortress_timer: float = 0.0,
        fire_cough_timer: float = 0.0,
        speed_bonus_timer: float = 0.0,
        shield_timer: float = 0.0,
        fire_bullets_timer: float = 0.0,
        weapon_id: int | None = None,
        clip_size: int | None = None,
        ammo: float | None = None,
        reload_active: bool | None = None,
        reload_timer: float | None = None,
        reload_timer_max: float | None = None,
        shot_cooldown: float | None = None,
        alt_weapon_id: int | None = None,
        alt_clip_size: int | None = None,
        alt_ammo: float | None = None,
        alt_reload_active: bool | None = None,
        alt_reload_timer: float | None = None,
        alt_reload_timer_max: float | None = None,
        alt_shot_cooldown: float | None = None,
    ) -> None:
        self.index = int(index)
        self.pos = pos
        self.health = float(health)
        self.size = float(size)
        self.speed_multiplier = float(speed_multiplier)
        self.move_speed = float(move_speed)
        self.move_phase = float(move_phase)
        self.heading = float(heading)
        self.turn_speed = float(turn_speed)
        self.death_timer = float(death_timer)
        self.low_health_timer = float(low_health_timer)

        self.aim = aim if aim is not None else Vec2()
        self.aim_heading = float(aim_heading)
        self.aim_dir = aim_dir if aim_dir is not None else Vec2(1.0, 0.0)
        self.evil_eyes_target_creature = int(evil_eyes_target_creature)
        self.auto_target = int(auto_target)

        self.bonus_aim_hover_index = int(bonus_aim_hover_index)
        self.bonus_aim_hover_timer_ms = float(bonus_aim_hover_timer_ms)

        primary = weapon if weapon is not None else WeaponSlot(weapon_id=1)
        if weapon_id is not None:
            primary.weapon_id = int(weapon_id)
        if clip_size is not None:
            primary.clip_size = int(clip_size)
        if ammo is not None:
            primary.ammo = float(ammo)
        if reload_active is not None:
            primary.reload_active = bool(reload_active)
        if reload_timer is not None:
            primary.reload_timer = float(reload_timer)
        if reload_timer_max is not None:
            primary.reload_timer_max = float(reload_timer_max)
        if shot_cooldown is not None:
            primary.shot_cooldown = float(shot_cooldown)
        self.weapon = primary

        alt = alt_weapon
        has_alt_overrides = any(
            value is not None
            for value in (
                alt_weapon_id,
                alt_clip_size,
                alt_ammo,
                alt_reload_active,
                alt_reload_timer,
                alt_reload_timer_max,
                alt_shot_cooldown,
            )
        )
        if alt is None and has_alt_overrides:
            alt = WeaponSlot(
                weapon_id=int(alt_weapon_id if alt_weapon_id is not None else self.weapon.weapon_id),
            )
        if alt is not None:
            if alt_weapon_id is not None:
                alt.weapon_id = int(alt_weapon_id)
            if alt_clip_size is not None:
                alt.clip_size = int(alt_clip_size)
            if alt_ammo is not None:
                alt.ammo = float(alt_ammo)
            if alt_reload_active is not None:
                alt.reload_active = bool(alt_reload_active)
            if alt_reload_timer is not None:
                alt.reload_timer = float(alt_reload_timer)
            if alt_reload_timer_max is not None:
                alt.reload_timer_max = float(alt_reload_timer_max)
            if alt_shot_cooldown is not None:
                alt.shot_cooldown = float(alt_shot_cooldown)
        self.alt_weapon = alt

        self.shot_seq = int(shot_seq)
        self.weapon_reset_latch = int(weapon_reset_latch)
        self.aux_timer = float(aux_timer)
        self.spread_heat = float(spread_heat)
        self.muzzle_flash_alpha = float(muzzle_flash_alpha)

        self.experience = int(experience)
        self.level = int(level)

        self.perk_counts = list(perk_counts) if perk_counts is not None else [0] * PERK_COUNT_SIZE
        self.plaguebearer_active = bool(plaguebearer_active)
        self.hot_tempered_timer = float(hot_tempered_timer)
        self.man_bomb_timer = float(man_bomb_timer)
        self.living_fortress_timer = float(living_fortress_timer)
        self.fire_cough_timer = float(fire_cough_timer)
        self.speed_bonus_timer = float(speed_bonus_timer)
        self.shield_timer = float(shield_timer)
        self.fire_bullets_timer = float(fire_bullets_timer)

    @property
    def weapon_id(self) -> int:
        return int(self.weapon.weapon_id)

    @weapon_id.setter
    def weapon_id(self, value: int) -> None:
        self.weapon.weapon_id = int(value)

    @property
    def clip_size(self) -> int:
        return int(self.weapon.clip_size)

    @clip_size.setter
    def clip_size(self, value: int) -> None:
        self.weapon.clip_size = int(value)

    @property
    def ammo(self) -> float:
        return float(self.weapon.ammo)

    @ammo.setter
    def ammo(self, value: float) -> None:
        self.weapon.ammo = float(value)

    @property
    def reload_active(self) -> bool:
        return bool(self.weapon.reload_active)

    @reload_active.setter
    def reload_active(self, value: bool) -> None:
        self.weapon.reload_active = bool(value)

    @property
    def reload_timer(self) -> float:
        return float(self.weapon.reload_timer)

    @reload_timer.setter
    def reload_timer(self, value: float) -> None:
        self.weapon.reload_timer = float(value)

    @property
    def reload_timer_max(self) -> float:
        return float(self.weapon.reload_timer_max)

    @reload_timer_max.setter
    def reload_timer_max(self, value: float) -> None:
        self.weapon.reload_timer_max = float(value)

    @property
    def shot_cooldown(self) -> float:
        return float(self.weapon.shot_cooldown)

    @shot_cooldown.setter
    def shot_cooldown(self, value: float) -> None:
        self.weapon.shot_cooldown = float(value)

    @property
    def alt_weapon_id(self) -> int | None:
        if self.alt_weapon is None:
            return None
        return int(self.alt_weapon.weapon_id)

    @alt_weapon_id.setter
    def alt_weapon_id(self, value: int | None) -> None:
        if value is None:
            self.alt_weapon = None
            return
        if self.alt_weapon is None:
            self.alt_weapon = WeaponSlot(weapon_id=int(value))
            return
        self.alt_weapon.weapon_id = int(value)

    @property
    def alt_clip_size(self) -> int:
        if self.alt_weapon is None:
            return 0
        return int(self.alt_weapon.clip_size)

    @alt_clip_size.setter
    def alt_clip_size(self, value: int) -> None:
        if self.alt_weapon is None:
            self.alt_weapon = WeaponSlot(weapon_id=int(self.weapon.weapon_id))
        self.alt_weapon.clip_size = int(value)

    @property
    def alt_ammo(self) -> float:
        if self.alt_weapon is None:
            return 0.0
        return float(self.alt_weapon.ammo)

    @alt_ammo.setter
    def alt_ammo(self, value: float) -> None:
        if self.alt_weapon is None:
            self.alt_weapon = WeaponSlot(weapon_id=int(self.weapon.weapon_id))
        self.alt_weapon.ammo = float(value)

    @property
    def alt_reload_active(self) -> bool:
        if self.alt_weapon is None:
            return False
        return bool(self.alt_weapon.reload_active)

    @alt_reload_active.setter
    def alt_reload_active(self, value: bool) -> None:
        if self.alt_weapon is None:
            self.alt_weapon = WeaponSlot(weapon_id=int(self.weapon.weapon_id))
        self.alt_weapon.reload_active = bool(value)

    @property
    def alt_reload_timer(self) -> float:
        if self.alt_weapon is None:
            return 0.0
        return float(self.alt_weapon.reload_timer)

    @alt_reload_timer.setter
    def alt_reload_timer(self, value: float) -> None:
        if self.alt_weapon is None:
            self.alt_weapon = WeaponSlot(weapon_id=int(self.weapon.weapon_id))
        self.alt_weapon.reload_timer = float(value)

    @property
    def alt_reload_timer_max(self) -> float:
        if self.alt_weapon is None:
            return 0.0
        return float(self.alt_weapon.reload_timer_max)

    @alt_reload_timer_max.setter
    def alt_reload_timer_max(self, value: float) -> None:
        if self.alt_weapon is None:
            self.alt_weapon = WeaponSlot(weapon_id=int(self.weapon.weapon_id))
        self.alt_weapon.reload_timer_max = float(value)

    @property
    def alt_shot_cooldown(self) -> float:
        if self.alt_weapon is None:
            return 0.0
        return float(self.alt_weapon.shot_cooldown)

    @alt_shot_cooldown.setter
    def alt_shot_cooldown(self, value: float) -> None:
        if self.alt_weapon is None:
            self.alt_weapon = WeaponSlot(weapon_id=int(self.weapon.weapon_id))
        self.alt_weapon.shot_cooldown = float(value)


@dataclass(frozen=True, slots=True)
class BonusPickupEvent:
    player_index: int
    bonus_id: int
    amount: int
    pos: Vec2


if TYPE_CHECKING:
    from ..gameplay import GameplayState as GameplayState
else:
    GameplayState: TypeAlias = object
