from __future__ import annotations

import msgspec

from grim.geom import Vec2

from ..math_parity import f32, x87_pc24_add, x87_pc24_hypot, x87_pc24_mul, x87_pc24_sub
from ..weapons import WeaponId
from .state_types import PlayerState


class SurvivalWeaponChallenge(msgspec.Struct):
    """The peaceful opening and three-kill challenge share a fire latch. An earned gun
    stays authorized after its challenge closes, until a later award changes the guard."""

    guard_weapon_id: WeaponId = WeaponId.PISTOL
    shrinkifier_enabled: bool = True
    fire_seen: bool = False
    damage_seen: bool = False
    first_kill_positions: list[Vec2] = msgspec.field(default_factory=lambda: [Vec2(), Vec2(), Vec2()])
    first_kill_count: int = 0

    @property
    def shrinkifier_window_open(self) -> bool:
        return self.shrinkifier_enabled and not self.damage_seen and not self.fire_seen

    @property
    def blade_gun_window_open(self) -> bool:
        return self.first_kill_count == 3 and not self.fire_seen

    def record_shot(self) -> None:
        self.fire_seen = True

    def record_damage(self) -> None:
        self.damage_seen = True

    def record_kill(self, pos: Vec2) -> None:
        if self.first_kill_count >= 6:
            return
        if self.first_kill_count < 3:
            self.first_kill_positions[self.first_kill_count] = Vec2(f32(pos.x), f32(pos.y))
        self.first_kill_count += 1
        if self.first_kill_count == 3:
            self.shrinkifier_enabled = False
            self.fire_seen = False

    def advance(self, player: PlayerState, elapsed_ms: float) -> WeaponId | None:
        """Consume an eligible handout in a solo Survival tick and return the gun to equip."""
        if self.shrinkifier_window_open and int(elapsed_ms) > 64000:
            # The time gate is spent even when the player no longer holds the pistol.
            self.shrinkifier_enabled = False
            self.damage_seen = True
            self.fire_seen = True
            if player.weapon.weapon_id == WeaponId.PISTOL:
                self.guard_weapon_id = WeaponId.SHRINKIFIER_5K
                return self.guard_weapon_id

        if self.blade_gun_window_open:
            pos0, pos1, pos2 = self.first_kill_positions
            centroid_x = x87_pc24_mul(x87_pc24_add(x87_pc24_add(pos0.x, pos1.x), pos2.x), f32(0.33333334))
            centroid_y = x87_pc24_mul(x87_pc24_add(x87_pc24_add(pos0.y, pos1.y), pos2.y), f32(0.33333334))
            dx = x87_pc24_sub(player.pos.x, centroid_x)
            dy = x87_pc24_sub(player.pos.y, centroid_y)
            if x87_pc24_hypot(dx, dy) < 16.0 and player.health < 15.0:
                self.guard_weapon_id = WeaponId.BLADE_GUN
                self.fire_seen = True
                self.shrinkifier_enabled = False
                return self.guard_weapon_id

        return None

    def allows(self, weapon_id: WeaponId) -> bool:
        return weapon_id not in (WeaponId.BLADE_GUN, WeaponId.SHRINKIFIER_5K) or weapon_id == self.guard_weapon_id
