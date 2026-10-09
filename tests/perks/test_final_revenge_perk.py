from __future__ import annotations

from crimson.effects import FxQueue, FxQueueRotated
from crimson.perks import PerkId
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.sim.world_state import WorldState
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.audio import sfx_ids
from tests.support.factories import player_input


def test_final_revenge_triggers_from_player_update_damage_same_step() -> None:
    world = WorldState.build(
        hardcore=False,
        quest_fail_retry_count=0,
    )

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=0.1, weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    world.state.perks[int(PerkId.FINAL_REVENGE)] = 1
    world.state.perks[int(PerkId.AMMUNITION_WITHIN)] = 1
    player.experience = 100
    player.weapon.reload_active = True
    player.weapon.reload_timer = 1.0
    player.weapon.reload_timer_max = 1.0
    world.players.append(player)

    events = world.step(
        0.05,
        inputs=[player_input(fire_down=True, aim=Vec2(120.0, 100.0))],
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        perk_progression_enabled=False,
    )

    assert player.health < 0.0
    assert sfx_ids(events.sfx).count(SfxId.EXPLOSION_LARGE) == 1
    assert sfx_ids(events.sfx).count(SfxId.SHOCKWAVE) == 1
