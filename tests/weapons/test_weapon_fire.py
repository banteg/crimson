from __future__ import annotations

from crimson.owner_ref import OwnerRef
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime.fire import WeaponFireCtx, fire_weapon
from crimson.weapons import WeaponId
from grim.geom import Vec2


def _fire_pistol(state: GameplayState) -> GameplayState:
    player = PlayerState(
        index=1,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, clip_size=12, ammo=12),
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
    return state


def test_friendly_fire_enabled_primary_shots_can_hit_players() -> None:
    # Native encodes friendly fire in the owner id (-1 - player_index): with
    # the cvar enabled, primary player shots can hit the other player.
    state = _fire_pistol(GameplayState(friendly_fire_enabled=True))

    shots = [proj for proj in state.projectiles.entries if proj.active]
    assert shots
    assert all(proj.hits_players for proj in shots)
    assert all(proj.owner == OwnerRef.from_player(1) for proj in shots)


def test_friendly_fire_disabled_primary_shots_never_hit_players() -> None:
    state = _fire_pistol(GameplayState())

    shots = [proj for proj in state.projectiles.entries if proj.active]
    assert shots
    assert not any(proj.hits_players for proj in shots)
    assert all(proj.owner == OwnerRef.from_local_player(0) for proj in shots)
