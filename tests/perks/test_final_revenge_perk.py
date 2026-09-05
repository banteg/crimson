from __future__ import annotations

import pytest

from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE, CreaturePool
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.perks import PerkId
from crimson.perks.impl.final_revenge import apply_final_revenge_on_player_death
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.sim.world_state import WorldState
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.helpers import assert_float_close


def test_final_revenge_triggers_explosion_damage_on_death() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=0.5)
    player.perk_counts[int(PerkId.FINAL_REVENGE)] = 1
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 10000.0
    creature.max_hp = 10000.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.move_speed = 0.0
    creature.contact_damage = 1.0
    creature.collision_timer = 0.1

    events = world.step(
        0.2,
        inputs=[PlayerInput()],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert player.health < 0.0
    assert_float_close(creature.hp, 7440.0)  # 10000 - (512 - 0) * 5
    assert events.sfx.count(SfxId.EXPLOSION_LARGE) == 1
    assert events.sfx.count(SfxId.SHOCKWAVE) == 1
    assert SfxId.EXPLOSION_LARGE in events.sfx
    assert SfxId.SHOCKWAVE in events.sfx


def test_final_revenge_triggers_from_player_update_damage_same_step() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=0.1, weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    player.perk_counts[int(PerkId.FINAL_REVENGE)] = 1
    player.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
    player.experience = 100
    player.weapon.reload_active = True
    player.weapon.reload_timer = 1.0
    player.weapon.reload_timer_max = 1.0
    world.players.append(player)

    events = world.step(
        0.05,
        inputs=[PlayerInput(fire_down=True, aim=Vec2(120.0, 100.0))],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert player.health < 0.0
    assert events.sfx.count(SfxId.EXPLOSION_LARGE) == 1
    assert events.sfx.count(SfxId.SHOCKWAVE) == 1


def test_final_revenge_runs_before_later_creature_slots_update() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=0.5)
    player.perk_counts[int(PerkId.FINAL_REVENGE)] = 1
    world.players.append(player)

    attacker = world.creatures.entries[0]
    attacker.active = True
    attacker.pos = Vec2(100.0, 100.0)
    attacker.hp = 10000.0
    attacker.max_hp = 10000.0
    attacker.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    attacker.size = 48.0
    attacker.move_speed = 0.0
    attacker.contact_damage = 1.0

    later = world.creatures.entries[1]
    later.active = True
    later.pos = Vec2(100.0, 100.0)
    later.hp = 100.0
    later.max_hp = 100.0
    later.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    later.size = 48.0
    later.move_speed = 0.0
    later.attack_cooldown = 1.0

    world.step(
        0.2,
        inputs=[PlayerInput()],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert player.health < 0.0
    assert later.hp < 0.0
    # The inline blast kills slot 1 before creature_update_all reaches it, so
    # its live-path attack-cooldown decrement does not run this frame.
    assert later.attack_cooldown == 1.0


def test_final_revenge_does_not_trigger_from_direct_death_clock_drain() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=0.1)
    player.perk_counts[int(PerkId.DEATH_CLOCK)] = 1
    player.perk_counts[int(PerkId.FINAL_REVENGE)] = 1
    world.players.append(player)

    events = world.step(
        0.05,
        inputs=[PlayerInput()],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert player.health < 0.0
    assert SfxId.EXPLOSION_LARGE not in events.sfx
    assert SfxId.SHOCKWAVE not in events.sfx


def test_final_revenge_aoe_includes_active_non_positive_hp_entries(mocker) -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    player.perk_counts[int(PerkId.FINAL_REVENGE)] = 1

    pool = CreaturePool(size=4)
    active_dead = pool.entries[0]
    active_dead.active = True
    active_dead.hp = 0.0
    active_dead.pos = Vec2(100.0, 100.0)

    active_alive = pool.entries[1]
    active_alive.active = True
    active_alive.hp = 10.0
    active_alive.pos = Vec2(100.0, 100.0)

    active_far = pool.entries[2]
    active_far.active = True
    active_far.hp = 10.0
    active_far.pos = Vec2(2000.0, 2000.0)

    touched: list[int] = []

    def _record_apply(creature, **_kwargs):
        touched.append(pool.entries.index(creature))
        return False

    mocker.patch(
        "crimson.creatures.damage.creature_apply_damage_with_lethal_followup",
        side_effect=_record_apply,
    )

    apply_final_revenge_on_player_death(
        state=state,
        creatures=pool,
        players=[player],
        player=player,
        dt=0.1,
        world_size=1024.0,
        detail_preset=5,
        fx_queue=None,
        deaths=[],
    )

    assert touched == [0, 1]


def test_final_revenge_damage_uses_native_pc24_arithmetic(mocker) -> None:
    state = GameplayState()
    state.bonus_spawn_guard = True
    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.FINAL_REVENGE)] = 1

    pool = CreaturePool(size=1)
    creature = pool.entries[0]
    creature.active = True
    creature.pos = Vec2(155.231201171875, 295.6527099609375)

    damage_amounts: list[float] = []

    def _record_apply(_creature, **kwargs):
        damage_amounts.append(float(kwargs["damage_amount"]))
        return False

    mocker.patch(
        "crimson.creatures.damage.creature_apply_damage_with_lethal_followup",
        side_effect=_record_apply,
    )

    apply_final_revenge_on_player_death(
        state=state,
        creatures=pool,
        players=[player],
        player=player,
        dt=0.1,
        world_size=1024.0,
        detail_preset=0,
        fx_queue=None,
        deaths=[],
    )

    assert damage_amounts == [890.364990234375]
    assert not state.bonus_spawn_guard


@pytest.mark.parametrize(
    ("preserve_bugs", "player1_has_perk", "target_has_perk", "expected_trigger"),
    [
        (True, True, False, True),
        (True, False, True, False),
        (False, False, True, True),
    ],
    ids=["native-player1-source", "native-ignores-target-perk", "corrected-target-source"],
)
def test_final_revenge_perk_source(
    preserve_bugs: bool,
    player1_has_perk: bool,
    target_has_perk: bool,
    expected_trigger: bool,
) -> None:
    state = GameplayState(preserve_bugs=preserve_bugs)
    player1 = PlayerState(index=0, pos=Vec2())
    target = PlayerState(index=1, pos=Vec2())
    player1.perk_counts[int(PerkId.FINAL_REVENGE)] = int(player1_has_perk)
    target.perk_counts[int(PerkId.FINAL_REVENGE)] = int(target_has_perk)

    apply_final_revenge_on_player_death(
        state=state,
        creatures=CreaturePool(size=0),
        players=[player1, target],
        player=target,
        dt=0.1,
        world_size=1024.0,
        detail_preset=0,
        fx_queue=None,
        deaths=[],
    )

    expected_sfx = [SfxId.EXPLOSION_LARGE, SfxId.SHOCKWAVE] if expected_trigger else []
    assert state.sfx_queue == expected_sfx
