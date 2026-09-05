from __future__ import annotations

from crimson.perks import PerkId
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.sim.world_reset import reset_world_players
from crimson.sim.world_state import WorldState
from crimson.weapons import WeaponId
from crimson.world.sim_world_state import SimWorldState
from grim.geom import Vec2


def test_world_children_follow_the_authoritative_world_across_load_and_reset() -> None:
    sim = SimWorldState()
    first = sim.world_state
    replacement = WorldState.build(world_size=1024.0, demo_mode_active=False, hardcore=False, quest_fail_retry_count=0)
    replacement.players.append(PlayerState(index=0, pos=Vec2(10.0, 20.0), health=17.0))
    sim.load_world_state(replacement)
    assert sim.state is replacement.state
    assert sim.players is replacement.players
    assert sim.creatures is replacement.creatures
    assert sim.spawn_env is replacement.spawn_env
    assert sim.players[0].health == 17.0

    sim.reset(seed=123, player_count=2)
    assert sim.world_state is not first and sim.world_state is not replacement
    assert sim.state is sim.world_state.state
    assert sim.players is sim.world_state.players
    assert sim.creatures is sim.world_state.creatures
    assert sim.spawn_env is sim.world_state.spawn_env
    assert sim.state.rng.state == 123
    assert len(sim.players) == 2
    assert replacement.players[0].health == 17.0


def test_reset_world_players_uses_native_alternating_layout() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        quest_fail_retry_count=0,
    )

    reset_world_players(
        world.players,
        state=world.state,
        world_size=1024.0,
        player_count=2,
    )

    assert world.players[0].pos.x == 512.0
    assert world.players[0].pos.y == 512.0
    assert world.players[1].pos.x == 432.0
    assert world.players[1].pos.y == 432.0
    assert world.players[0].spread_heat == 0.0
    assert world.players[1].spread_heat == 0.0


def test_world_reset_round_robins_native_creature_targets() -> None:
    world = SimWorldState()

    world.reset(seed=0xBEEF, player_count=2)

    assert [creature.target_player for creature in world.creatures.entries[:6]] == [0, 1, 0, 1, 0, 1]


def test_reset_world_players_preserves_native_unwritten_residue() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    player = PlayerState(
        index=0,
        pos=Vec2(20.0, 30.0),
        health=7.0,
        move_phase=4.5,
        turn_speed=3.0,
        aim=Vec2(700.0, 300.0),
        aim_heading=1.25,
        evil_eyes_target_creature=17,
        auto_target=22,
        weapon=WeaponSlot(
            weapon_id=WeaponId.ROCKET_LAUNCHER,
            clip_size=4,
            ammo=2.0,
            reload_active=True,
            reload_timer=3.0,
            reload_timer_max=4.0,
            shot_cooldown=5.0,
        ),
        weapon_reset_latch=9,
        aux_timer=2.0,
        muzzle_flash_alpha=0.75,
        low_health_timer=0.25,
        plaguebearer_active=True,
        hot_tempered_timer=1.25,
        man_bomb_timer=2.25,
        living_fortress_timer=3.25,
        fire_cough_timer=4.25,
        speed_bonus_timer=5.25,
        shield_timer=6.25,
        fire_bullets_timer=7.25,
    )
    player.perk_counts[int(PerkId.LONG_DISTANCE_RUNNER)] = 1
    world.players.append(player)

    reset_world_players(
        world.players,
        state=world.state,
        world_size=1024.0,
        player_count=1,
    )

    reset = world.players[0]
    assert reset is player
    assert reset.pos == Vec2(512.0, 512.0)
    assert reset.health == 100.0
    assert reset.move_speed == 0.0
    assert reset.heading == 0.0
    assert reset.death_timer == 16.0
    assert reset.perk_counts == [0] * len(reset.perk_counts)
    assert reset.plaguebearer_active is False
    assert reset.speed_bonus_timer == 0.0
    assert reset.shield_timer == 0.0
    assert reset.low_health_timer == 100.0
    assert reset.auto_target == 0
    assert reset.aux_timer == 0.0
    assert reset.weapon.weapon_id == WeaponId.PISTOL
    assert reset.weapon.clip_size == 10
    assert reset.weapon.ammo == 10.0
    assert reset.weapon.reload_active is True
    assert reset.weapon.reload_timer == 0.0
    assert reset.weapon.reload_timer_max == 1.0
    assert reset.weapon.shot_cooldown == 0.8

    assert reset.move_phase == 4.5
    assert reset.turn_speed == 3.0
    assert reset.aim == Vec2(700.0, 300.0)
    assert reset.aim_heading == 1.25
    assert reset.evil_eyes_target_creature == 17
    assert reset.weapon_reset_latch == 9
    assert reset.muzzle_flash_alpha == 0.75
    assert reset.hot_tempered_timer == 1.25
    assert reset.man_bomb_timer == 2.25
    assert reset.living_fortress_timer == 3.25
    assert reset.fire_cough_timer == 4.25
    assert reset.fire_bullets_timer == 7.25
