from __future__ import annotations

from crimson.gameplay import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime.fire import WeaponFireCtx, fire_weapon
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

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 100.0)),
            dt=0.016,
            state=state,
        ),
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


def test_mini_rocket_swarmer_empty_clip_fires_no_rockets() -> None:
    # Reachable when firing during reload with Regression Bullets / Ammunition
    # Within; native spawns zero rockets and zeroes the clip.
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(
            weapon_id=WeaponId.MINI_ROCKET_SWARMERS,
            clip_size=6,
            ammo=-0.5,
        ),
        spread_heat=0.0,
    )

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 100.0)),
            dt=0.016,
            state=state,
        ),
    )

    assert not any(entry.active for entry in state.secondary_projectiles.entries)
    assert player.weapon.ammo == 0.0
    assert state.shots_fired[0] == 0
