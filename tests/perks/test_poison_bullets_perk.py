from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.creatures.spawn import CreatureFlags
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.projectiles.types import ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand


def test_poison_bullets_sets_self_damage_flag_when_rng_hits() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.state.rng = ScriptedCrand(1, fallback=ScriptedCrand.Fallback.REPEAT_LAST)  # rand & 7 == 1

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    player.perk_counts[int(PerkId.POISON_BULLETS)] = 1
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 1000.0
    creature.max_hp = 1000.0

    world.state.projectiles.spawn(
        pos=Vec2(creature.pos.x, creature.pos.y),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner=OwnerRef.from_local_player(0),
        travel_budget=45.0,
    )

    events = world.step(
        0.016,
        inputs=[PlayerInput()],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )
    assert events.hits
    assert creature.flags & CreatureFlags.SELF_DAMAGE_TICK
    assert [
        record.caller
        for record in world.state.rng.records_since()
        if record.caller == RngCallerStatic.PROJECTILE_UPDATE_POISON_BULLETS_GATE
    ] == [RngCallerStatic.PROJECTILE_UPDATE_POISON_BULLETS_GATE]


@pytest.mark.parametrize(
    ("preserve_bugs", "expected_poison"),
    [
        (True, False),
        (False, True),
    ],
)
def test_poison_bullets_selects_native_player_zero_or_corrected_any_player(
    preserve_bugs: bool,
    expected_poison: bool,
) -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.state.preserve_bugs = preserve_bugs
    world.state.rng = ScriptedCrand(1, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    player0 = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    player1 = PlayerState(index=1, pos=Vec2(100.0, 100.0))
    player1.perk_counts[int(PerkId.POISON_BULLETS)] = 1
    world.players.extend((player0, player1))

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 1000.0
    creature.max_hp = 1000.0

    world.state.projectiles.spawn(
        pos=Vec2(creature.pos.x, creature.pos.y),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner=OwnerRef.from_local_player(1),
        travel_budget=45.0,
    )

    events = world.step(
        0.016,
        inputs=[PlayerInput(), PlayerInput()],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert events.hits
    assert bool(creature.flags & CreatureFlags.SELF_DAMAGE_TICK) is expected_poison
    poison_calls = [
        record
        for record in world.state.rng.records_since()
        if record.caller == RngCallerStatic.PROJECTILE_UPDATE_POISON_BULLETS_GATE
    ]
    assert bool(poison_calls) is expected_poison


def test_poison_bullets_does_not_set_flag_when_rng_misses() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)  # rand & 7 != 1

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    player.perk_counts[int(PerkId.POISON_BULLETS)] = 1
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 1000.0
    creature.max_hp = 1000.0

    world.state.projectiles.spawn(
        pos=Vec2(creature.pos.x, creature.pos.y),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner=OwnerRef.from_local_player(0),
        travel_budget=45.0,
    )

    events = world.step(
        0.016,
        inputs=[PlayerInput()],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )
    assert events.hits
    assert not (creature.flags & CreatureFlags.SELF_DAMAGE_TICK)
    assert [
        record.caller
        for record in world.state.rng.records_since()
        if record.caller == RngCallerStatic.PROJECTILE_UPDATE_POISON_BULLETS_GATE
    ] == [RngCallerStatic.PROJECTILE_UPDATE_POISON_BULLETS_GATE]


def test_poison_bullets_does_not_trigger_on_nuke_radius_damage() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.state.rng = ScriptedCrand(1, fallback=ScriptedCrand.Fallback.REPEAT_LAST)  # rand & 7 == 1

    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))
    player.perk_counts[int(PerkId.POISON_BULLETS)] = 1
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = player.pos + Vec2(100.0, 0.0)
    creature.hp = 2000.0
    creature.max_hp = 2000.0

    assert world.state.bonus_pool.spawn_at(pos=player.pos, bonus_id=BonusId.NUKE, state=world.state) is not None

    world.step(
        0.016,
        inputs=[PlayerInput()],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )
    assert not (creature.flags & CreatureFlags.SELF_DAMAGE_TICK)


def test_poison_bullets_with_toxic_avenger_still_sets_only_weak_poison_on_bullet_hit() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.state.rng = ScriptedCrand(1, fallback=ScriptedCrand.Fallback.REPEAT_LAST)  # rand & 7 == 1

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    player.perk_counts[int(PerkId.POISON_BULLETS)] = 1
    player.perk_counts[int(PerkId.TOXIC_AVENGER)] = 1
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(300.0, 300.0)
    creature.hp = 1000.0
    creature.max_hp = 1000.0

    world.state.projectiles.spawn(
        pos=Vec2(creature.pos.x, creature.pos.y),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner=OwnerRef.from_local_player(0),
        travel_budget=45.0,
    )

    world.step(
        0.016,
        inputs=[PlayerInput()],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert creature.flags & CreatureFlags.SELF_DAMAGE_TICK
    assert not (creature.flags & CreatureFlags.SELF_DAMAGE_TICK_STRONG)


def test_poison_bullets_gate_applies_to_creature_owned_projectiles() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.state.rng = ScriptedCrand(1, fallback=ScriptedCrand.Fallback.REPEAT_LAST)  # rand & 7 == 1

    player = PlayerState(index=0, pos=Vec2(900.0, 900.0))
    player.perk_counts[int(PerkId.POISON_BULLETS)] = 1
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 1000.0
    creature.max_hp = 1000.0

    # Native gates the poison roll on the global perk count, so creature-owned
    # projectiles (splitter children, shock-chain segments) draw it too.
    world.state.projectiles.spawn(
        pos=Vec2(creature.pos.x, creature.pos.y),
        angle=0.0,
        type_id=ProjectileTemplateId.SPLITTER_GUN,
        owner=OwnerRef.from_creature(7),
        travel_budget=45.0,
    )

    events = world.step(
        0.016,
        inputs=[PlayerInput()],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )
    assert events.hits
    assert creature.flags & CreatureFlags.SELF_DAMAGE_TICK
    assert RngCallerStatic.PROJECTILE_UPDATE_POISON_BULLETS_GATE in {
        record.caller for record in world.state.rng.records_since()
    }
