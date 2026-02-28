from __future__ import annotations

from crimson.gameplay import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime.fire import player_fire_weapon
from crimson.weapons import WeaponId
from grim.geom import Vec2


def _spawn_swarmer_burst(*, preserve_bugs: bool, ammo: float) -> list[tuple[float, float]]:
    state = GameplayState(preserve_bugs=bool(preserve_bugs))
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(
            weapon_id=WeaponId.MINI_ROCKET_SWARMERS,
            clip_size=int(ammo),
            ammo=float(ammo),
        ),
        spread_heat=0.0,
    )

    player_fire_weapon(
        player,
        PlayerInput(fire_down=True, aim=Vec2(200.0, 100.0)),
        dt=0.016,
        state=state,
    )

    headings: list[tuple[float, float]] = []
    for entry in state.secondary_projectiles.entries:
        if not entry.active:
            continue
        direction = Vec2.from_heading(float(entry.angle))
        headings.append((round(float(direction.x), 6), round(float(direction.y), 6)))
    return headings


def test_mini_rocket_swarmer_clumping_bug_is_fixed_by_default() -> None:
    headings = _spawn_swarmer_burst(preserve_bugs=False, ammo=6.0)
    assert len(headings) == 6
    assert len(set(headings)) == 6


def test_mini_rocket_swarmer_clumping_bug_can_be_preserved() -> None:
    headings = _spawn_swarmer_burst(preserve_bugs=True, ammo=6.0)
    assert len(headings) == 6
    assert len(set(headings)) == 1
