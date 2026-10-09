from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.creatures.runtime import (
    CREATURE_LIFECYCLE_ALIVE,
    CreaturePool,
    CreatureState,
)
from crimson.creatures.spawn import (
    NATIVE_SPAWN_SLOT_COUNT,
    CreatureAiMode,
    CreatureFlags,
    SpawnId,
)
from crimson.effects import FxQueue
from crimson.game_modes import GameMode
from crimson.math_parity import f32, x87_pc24_hypot
from crimson.perks import PerkId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.sim.world_state import WorldState
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from tests.support.builders.session import make_world
from tests.support.factories import kill_creature, step_creatures, world_with_creature
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_spawner_overwrites_the_last_spawn_slot_when_all_are_owned() -> None:
    state = GameplayState(rng=Crand(0))
    pool = CreaturePool()
    for owner_index, slot in enumerate(pool.spawn_slots):
        slot.owner_creature = 100 + owner_index

    returned = pool.spawn_template(SpawnId.ZOMBIE_BOSS_SPAWNER_00, Vec2(100.0, 200.0), 0.0, state=state, detail_preset=5)

    assert pool.entries[returned].link_index == NATIVE_SPAWN_SLOT_COUNT - 1
    assert pool.spawn_slots[-1].owner_creature == returned
    assert [slot.owner_creature for slot in pool.spawn_slots[:-1]] == list(range(100, 100 + NATIVE_SPAWN_SLOT_COUNT - 1))


def test_creature_contact_damage_targets_player1_when_player0_is_dead() -> None:
    world = make_world(player_count=2)
    state = world.state
    pool = world.creatures
    rng = RecordingCrand(Crand(0x1234))

    player0 = world.players[0]
    player0.pos = Vec2(100.0, 100.0)
    player0.health = 0.0
    player0.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)
    player1 = world.players[1]
    player1.pos = Vec2(110.0, 100.0)
    player1.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.death_timer = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags(0)
    creature.ai_mode = CreatureAiMode.FLANK_PLAYER
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.contact_damage = 10.0
    creature.target_player = 0
    creature.pos = Vec2(110.0, 100.0)

    state.rng = rng
    step_creatures(world, 1.0 / 60.0)

    assert creature.target_player == 1
    assert_float_close(player0.health, 0.0)
    assert_float_close(player1.health, 90.0)
    assert [record.caller for record in rng.records_since() if record.caller is not None][:1] == [
        RngCallerStatic.CREATURE_UPDATE_ALL_CONTACT_SFX,
    ]


def test_single_player_creature_keeps_the_dormant_target_after_the_player_gets_back_up() -> None:
    world = make_world()
    state = world.state
    pool = world.creatures

    # A MediKit picked up during the death animation put the player back above 0 health.
    player = world.players[0]
    player.pos = Vec2(400.0, 400.0)
    player.health = 7.825
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.death_timer = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags(0)
    creature.ai_mode = CreatureAiMode.FLANK_PLAYER
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.contact_damage = 10.0
    creature.target_player = 1
    creature.pos = Vec2(410.0, 400.0)

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    assert creature.target_player == 1
    assert creature.attack_cooldown == 0.0
    assert_float_close(player.health, 7.825)


def test_creature_retargets_to_closer_player1_in_two_player_mode() -> None:
    world = make_world(player_count=2)
    state = world.state
    pool = world.creatures

    player0 = world.players[0]
    player0.pos = Vec2(100.0, 100.0)
    player0.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)
    player1 = world.players[1]
    player1.pos = Vec2(104.0, 100.0)
    player1.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.death_timer = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags(0)
    creature.ai_mode = CreatureAiMode.FLANK_PLAYER
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.contact_damage = 10.0
    creature.target_player = 0
    creature.pos = Vec2(104.0, 100.0)

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    assert creature.target_player == 1
    assert_float_close(player0.health, 100.0)
    assert_float_close(player1.health, 90.0)


def test_creature_retarget_keeps_current_player_when_native_distances_round_equal() -> None:
    pool = CreaturePool()
    pool._update_tick = 1
    creature = pool.entries[0]
    creature.target_player = 0
    creature.pos = Vec2(0.0, 0.0)

    players = [
        PlayerState(index=0, pos=Vec2(f32(100.00000762939453), 100.0), health=100.0),
        PlayerState(index=1, pos=Vec2(100.0, 100.0), health=100.0),
    ]

    current_exact_sq = Vec2.distance_sq(creature.pos, players[0].pos)
    alternate_exact_sq = Vec2.distance_sq(creature.pos, players[1].pos)
    assert alternate_exact_sq < current_exact_sq
    assert x87_pc24_hypot(players[0].pos.x, players[0].pos.y) == x87_pc24_hypot(
        players[1].pos.x,
        players[1].pos.y,
    )
    resolution = pool._resolve_target_player(creature, players, len(players))
    assert resolution.target_player == 0
    assert creature.target_player == 0


def test_creature_update_coop_auto_target_uses_target_player_position_by_default() -> None:
    world = make_world(player_count=2)
    state = world.state
    pool = world.creatures
    player0 = world.players[0]
    player0.pos = Vec2(0.0, 0.0)
    player0.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)
    player1 = world.players[1]
    player1.pos = Vec2(100.0, 0.0)
    player1.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    current = pool.entries[0]
    current.active = True
    current.hp = 50.0
    current.death_timer = CREATURE_LIFECYCLE_ALIVE
    current.flags = CreatureFlags(0)
    current.ai_mode = CreatureAiMode.FLANK_PLAYER
    current.move_speed = 0.0
    current.size = 45.0
    current.contact_damage = 0.0
    current.target_player = 0
    current.pos = Vec2(10.0, 0.0)

    nearer_for_player1 = pool.entries[1]
    nearer_for_player1.active = True
    nearer_for_player1.hp = 50.0
    nearer_for_player1.death_timer = CREATURE_LIFECYCLE_ALIVE
    nearer_for_player1.flags = CreatureFlags(0)
    nearer_for_player1.ai_mode = CreatureAiMode.FLANK_PLAYER
    nearer_for_player1.move_speed = 0.0
    nearer_for_player1.size = 45.0
    nearer_for_player1.contact_damage = 0.0
    nearer_for_player1.target_player = 0
    nearer_for_player1.pos = Vec2(80.0, 0.0)

    player1.auto_target = 0
    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    assert player1.auto_target == 1


def test_creature_update_coop_auto_target_preserve_bugs_keeps_player1_distance_bias() -> None:
    world = make_world(player_count=2, preserve_bugs=True)
    state = world.state
    pool = world.creatures
    player0 = world.players[0]
    player0.pos = Vec2(0.0, 0.0)
    player0.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)
    player1 = world.players[1]
    player1.pos = Vec2(100.0, 0.0)
    player1.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    current = pool.entries[0]
    current.active = True
    current.hp = 50.0
    current.death_timer = CREATURE_LIFECYCLE_ALIVE
    current.flags = CreatureFlags(0)
    current.ai_mode = CreatureAiMode.FLANK_PLAYER
    current.move_speed = 0.0
    current.size = 45.0
    current.contact_damage = 0.0
    current.target_player = 0
    current.pos = Vec2(10.0, 0.0)

    nearer_for_player1 = pool.entries[1]
    nearer_for_player1.active = True
    nearer_for_player1.hp = 50.0
    nearer_for_player1.death_timer = CREATURE_LIFECYCLE_ALIVE
    nearer_for_player1.flags = CreatureFlags(0)
    nearer_for_player1.ai_mode = CreatureAiMode.FLANK_PLAYER
    nearer_for_player1.move_speed = 0.0
    nearer_for_player1.size = 45.0
    nearer_for_player1.contact_damage = 0.0
    nearer_for_player1.target_player = 0
    nearer_for_player1.pos = Vec2(80.0, 0.0)

    player1.auto_target = 0
    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    assert player1.auto_target == 0


def test_creature_update_coop_auto_target_preserve_bugs_reuses_other_player_distance() -> None:
    world = make_world(player_count=2, preserve_bugs=True)
    state = world.state
    pool = world.creatures
    player0 = world.players[0]
    player0.pos = Vec2(0.0, 0.0)
    player0.auto_target = 0
    player1 = world.players[1]
    player1.pos = Vec2(100.0, 0.0)

    current = pool.entries[0]
    current.active = True
    current.hp = 50.0
    current.death_timer = CREATURE_LIFECYCLE_ALIVE
    current.ai_mode = CreatureAiMode.FLANK_PLAYER
    current.move_speed = 0.0
    current.size = 45.0
    current.target_player = 0
    current.pos = Vec2(50.0, 0.0)

    candidate = pool.entries[1]
    candidate.active = True
    candidate.hp = 50.0
    candidate.death_timer = CREATURE_LIFECYCLE_ALIVE
    candidate.ai_mode = CreatureAiMode.FLANK_PLAYER
    candidate.move_speed = 0.0
    candidate.size = 45.0
    candidate.target_player = 0
    candidate.pos = Vec2(10.0, 0.0)

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    # The candidate is 10 units from player 1, but native reuses its 90-unit
    # distance from player 2. It therefore does not replace the 50-unit slot.
    assert player0.auto_target == 0


def test_creature_update_preserve_bugs_updates_dead_auto_target_before_redirect() -> None:
    world = make_world(player_count=2, preserve_bugs=True)
    state = world.state
    pool = world.creatures
    player0 = world.players[0]
    player0.pos = Vec2(0.0, 0.0)
    player0.health = 0.0
    player0.auto_target = 0
    player1 = world.players[1]
    player1.pos = Vec2(100.0, 0.0)
    player1.auto_target = 0

    stale_current = pool.entries[0]
    stale_current.pos = Vec2(200.0, 0.0)

    candidate = pool.entries[1]
    candidate.active = True
    candidate.hp = 50.0
    candidate.death_timer = CREATURE_LIFECYCLE_ALIVE
    candidate.ai_mode = CreatureAiMode.FLANK_PLAYER
    candidate.move_speed = 0.0
    candidate.size = 45.0
    candidate.target_player = 0
    candidate.pos = Vec2(10.0, 0.0)

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    assert player0.auto_target == 1
    assert player1.auto_target == 0
    assert candidate.target_player == 1


def test_every_kill_credits_player_one() -> None:
    # Native `creature_handle_death` adds the XP to player one, whoever landed the hit.
    players = [PlayerState(index=0, pos=Vec2()), PlayerState(index=1, pos=Vec2())]
    world = world_with_creature(CreatureState(active=True, hp=0.0, reward_value=10.0), players=players)
    world.state.scripted_burst_active = True
    world.state.perks[int(PerkId.BLOODY_MESS_QUICK_LEARNER)] = 1

    death = kill_creature(world)

    assert death.xp_awarded == 13
    assert (players[0].experience, players[1].experience) == (13, 0)


def test_handle_death_freeze_shatters_the_creature_and_enqueues_one_random_decal() -> None:
    rng = RecordingCrand(Crand(0x1234))
    world = world_with_creature(CreatureState(active=True, hp=0.0, pos=Vec2(100.0, 100.0)), rng=rng)
    world.state.game_mode = GameMode.RUSH
    world.state.bonuses.freeze = 1.0
    fx_queue = FxQueue()

    kill_creature(world, fx_queue=fx_queue)

    assert fx_queue.count == 1
    assert not world.creatures.entries[0].active
    assert world.creatures.kill_count == 1
    tagged_callers = [
        record.caller
        for record in rng.records_since()
        if record.caller
        in {
            RngCallerStatic.CREATURE_HANDLE_DEATH_FREEZE_SHARD_ANGLE,
            RngCallerStatic.CREATURE_HANDLE_DEATH_FREEZE_SHATTER_ANGLE,
        }
    ]
    assert tagged_callers == [
        RngCallerStatic.CREATURE_HANDLE_DEATH_FREEZE_SHARD_ANGLE,
    ] * 8 + [
        RngCallerStatic.CREATURE_HANDLE_DEATH_FREEZE_SHATTER_ANGLE,
    ]


def test_handle_death_inactive_entry_skips_reentrant_side_effects() -> None:
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    world = world_with_creature(
        CreatureState(active=False, hp=-1.0, reward_value=49.0, pos=Vec2(100.0, 100.0)),
        players=[player],
    )
    world.state.game_mode = GameMode.RUSH
    world.state.bonuses.freeze = 1.0
    fx_queue = FxQueue()

    death = kill_creature(world, fx_queue=fx_queue)

    assert death.xp_awarded == 0
    assert player.experience == 0
    assert fx_queue.count == 0
    assert world.state.effects.iter_active() == []
    assert not any(entry.bonus_id != BonusId.UNUSED for entry in world.state.bonus_pool.entries)


def _inactive_bonus_carrier_world(*, preserve_bugs: bool) -> WorldState:
    world = world_with_creature(
        CreatureState(
            active=False,
            flags=CreatureFlags.BONUS_ON_DEATH,
            bonus_id=BonusId.POINTS,
            bonus_amount_override=5,
            hp=-1.0,
            pos=Vec2(100.0, 100.0),
        ),
    )
    world.state.preserve_bugs = preserve_bugs
    return world


def test_handle_death_inactive_entry_forced_bonus_on_death_is_one_shot_by_default() -> None:
    world = _inactive_bonus_carrier_world(preserve_bugs=False)

    death = kill_creature(world)
    kill_creature(world)

    assert [entry.bonus_id for entry in world.state.bonus_pool.entries].count(BonusId.POINTS) == 1
    assert death.xp_awarded == 0
    creature = world.creatures.entries[0]
    assert creature.bonus_id is None
    assert creature.bonus_amount_override is None


@pytest.mark.parametrize(
    ("hp", "death_timer"),
    [(1.0, CREATURE_LIFECYCLE_ALIVE), (-1.0, 10.0), (10.0, 10.0)],
)
def test_dead_creature_still_reevaluates_target_player(hp: float, death_timer: float) -> None:
    world = make_world(player_count=2)
    state = world.state
    player0 = world.players[0]
    player0.pos = Vec2(500.0, 100.0)
    player0.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    player1 = world.players[1]
    player1.pos = Vec2(110.0, 100.0)
    player1.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    pool = world.creatures

    creature = pool.entries[0]
    creature.active = True
    creature.hp = hp
    creature.max_hp = max(1.0, hp)
    creature.death_timer = death_timer
    creature.flags = CreatureFlags.POISONED_STRONG if hp > 0.0 else CreatureFlags(0)
    creature.target_player = 0
    creature.pos = Vec2(100.0, 100.0)
    creature.move_speed = 0.0
    creature.size = 45.0

    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    step_creatures(world, 0.1)

    assert creature.death_timer != CREATURE_LIFECYCLE_ALIVE
    assert creature.target_player == 1


def test_evil_eyes_target_still_reevaluates_target_player() -> None:
    world = make_world(player_count=2)
    state = world.state
    player0 = world.players[0]
    player0.pos = Vec2(500.0, 100.0)
    player0.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    state.perks[int(PerkId.EVIL_EYES)] = 1
    player0.evil_eyes_target_creature = 0
    player1 = world.players[1]
    player1.pos = Vec2(110.0, 100.0)
    player1.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    pool = world.creatures

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 100.0
    creature.max_hp = 100.0
    creature.death_timer = CREATURE_LIFECYCLE_ALIVE
    creature.target_player = 0
    creature.pos = Vec2(100.0, 100.0)
    creature.move_speed = 1.0
    creature.size = 50.0

    before_pos = creature.pos
    step_creatures(world, 0.2)

    assert creature.target_player == 1
    assert creature.pos == before_pos


def test_evil_eyes_default_freezes_targets_from_multiple_players() -> None:
    world = make_world(player_count=2)
    state = world.state

    player0 = world.players[0]
    player0.pos = Vec2(512.0, 512.0)
    player0.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    state.perks[int(PerkId.EVIL_EYES)] = 1
    player0.evil_eyes_target_creature = 0

    player1 = world.players[1]
    player1.pos = Vec2(520.0, 512.0)
    player1.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    state.perks[int(PerkId.EVIL_EYES)] = 1
    player1.evil_eyes_target_creature = 1

    pool = world.creatures

    creature0 = pool.entries[0]
    creature0.active = True
    creature0.hp = 50.0
    creature0.death_timer = CREATURE_LIFECYCLE_ALIVE
    creature0.flags = CreatureFlags.STOP_AND_GO
    creature0.ai_mode = CreatureAiMode.HOLD_TIMER
    creature0.link_index = 100
    creature0.target_player = 0
    creature0.pos = Vec2(640.0, 512.0)
    creature0.vel = Vec2(2.0, -3.0)
    creature0.attack_cooldown = 1.0
    creature0.move_speed = 0.0
    creature0.size = 45.0

    creature1 = pool.entries[1]
    creature1.active = True
    creature1.hp = 50.0
    creature1.death_timer = CREATURE_LIFECYCLE_ALIVE
    creature1.flags = CreatureFlags.STOP_AND_GO
    creature1.ai_mode = CreatureAiMode.HOLD_TIMER
    creature1.link_index = 100
    creature1.target_player = 0
    creature1.pos = Vec2(680.0, 512.0)
    creature1.vel = Vec2(2.0, -3.0)
    creature1.attack_cooldown = 1.0
    creature1.move_speed = 0.0
    creature1.size = 45.0

    state.rng = ScriptedCrand([0x2A, 0x2B])
    step_creatures(world, 1.0 / 60.0)

    assert_float_close(creature0.attack_cooldown, 1.0)
    assert_float_close(creature1.attack_cooldown, 1.0)
    assert creature0.vel == Vec2(2.0, -3.0)
    assert creature1.vel == Vec2(2.0, -3.0)
    assert creature0.force_target == 0
    assert creature1.force_target == 0
