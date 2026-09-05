from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.gameplay import player_update
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.replay.driver.setup import reset_players
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime import init_default_alt_weapon, weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.factories import RecordingCreatureDamageRuntime
from tests.support.helpers import assert_float_close


def _alt(player: PlayerState) -> WeaponSlot:
    assert player.alt_weapon is not None
    return player.alt_weapon


def test_alternate_weapon_slows_movement() -> None:
    state = GameplayState()
    move_heading = Vec2(1.0, 0.0).to_heading()
    base = PlayerState(index=0, pos=Vec2(), move_speed=2.0, heading=move_heading)
    perk = PlayerState(index=0, pos=Vec2(), move_speed=2.0, heading=move_heading)
    perk.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1

    player_update(base, PlayerInput(move=Vec2(1.0, 0.0)), dt=1.0, state=state)
    player_update(perk, PlayerInput(move=Vec2(1.0, 0.0)), dt=1.0, state=state)

    assert_float_close(base.pos.x, 100.0)
    assert_float_close(perk.pos.x, 80.0)


def test_alternate_weapon_starts_with_preloaded_pistol_alt_slot() -> None:
    state = GameplayState()
    players: list[PlayerState] = []
    reset_players(players, state=state, world_size=1024.0, player_count=1)
    player = players[0]
    alt = _alt(player)

    assert player.weapon.weapon_id == 1
    assert alt.weapon_id == 1
    assert alt.clip_size == 12
    assert_float_close(alt.ammo, 12.0)
    assert alt.reload_active is False
    assert_float_close(alt.reload_timer_max, 1.2)


def test_alternate_weapon_first_weapon_pickup_keeps_preloaded_pistol_slot() -> None:
    state = GameplayState()
    players: list[PlayerState] = []
    reset_players(players, state=state, world_size=1024.0, player_count=1)
    player = players[0]
    player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1

    bonus_apply(
        state,
        player,
        BonusId.WEAPON,
        creature_damage_runtime=RecordingCreatureDamageRuntime(creatures=[]),
        amount=2,
        origin=player.pos,
        creatures=[],
        players=[player],
    )
    alt = _alt(player)

    assert player.weapon.weapon_id == 2
    assert alt.weapon_id == 1
    assert alt.clip_size == 12
    assert_float_close(alt.ammo, 12.0)


def test_alternate_weapon_reload_pressed_swaps_and_adds_cooldown() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, WeaponId.PISTOL, state=state)
    init_default_alt_weapon(player)
    player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1
    bonus_apply(
        state,
        player,
        BonusId.WEAPON,
        creature_damage_runtime=RecordingCreatureDamageRuntime(creatures=[]),
        amount=2,
        origin=player.pos,
        creatures=[],
        players=[player],
    )
    alt = _alt(player)

    assert player.weapon.weapon_id == 2
    assert alt.weapon_id == 1

    player.weapon.shot_cooldown = 0.0
    state.sfx_queue.clear()
    player_update(player, PlayerInput(reload_pressed=True), dt=0.1, state=state)
    alt = _alt(player)

    assert player.weapon.weapon_id == 1
    assert alt.weapon_id == 2
    assert player.weapon.shot_cooldown == f32(0.1)


def test_alternate_weapon_reload_pressed_still_swaps_in_move_to_cursor_mode() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, WeaponId.PISTOL, state=state)
    init_default_alt_weapon(player)
    player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1
    bonus_apply(
        state,
        player,
        BonusId.WEAPON,
        creature_damage_runtime=RecordingCreatureDamageRuntime(creatures=[]),
        amount=2,
        origin=player.pos,
        creatures=[],
        players=[player],
    )

    player.weapon.shot_cooldown = 0.0
    state.sfx_queue.clear()
    player_update(
        player,
        PlayerInput(reload_pressed=True, move_to_cursor_pressed=True),
        dt=0.1,
        state=state,
    )
    alt = _alt(player)

    assert player.weapon.weapon_id == 1
    assert alt.weapon_id == 2
    assert player.weapon.shot_cooldown == f32(0.1)


def test_alternate_weapon_swap_preserves_same_tick_fire_gate() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, WeaponId.PISTOL, state=state)
    init_default_alt_weapon(player)
    player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1
    bonus_apply(
        state,
        player,
        BonusId.WEAPON,
        creature_damage_runtime=RecordingCreatureDamageRuntime(creatures=[]),
        amount=11,
        origin=player.pos,
        creatures=[],
        players=[player],
    )
    alt = _alt(player)

    assert player.weapon.weapon_id == 11
    assert alt.weapon_id == 1
    starting_alt_ammo = float(alt.ammo)

    player.weapon.shot_cooldown = 0.05
    player_update(
        player,
        PlayerInput(aim=Vec2(700.0, 512.0), reload_pressed=True, fire_down=True),
        dt=0.06,
        state=state,
    )

    assert player.weapon.weapon_id == 1
    assert player.weapon.ammo < starting_alt_ammo


def test_alternate_weapon_swap_allows_same_tick_fire_with_swapped_reload_timer() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, WeaponId.SPLITTER_GUN, state=state)
    player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1
    player.weapon.ammo = 2.0
    player.weapon.reload_timer = 0.0
    player.weapon.reload_active = False
    player.alt_weapon = WeaponSlot(
        weapon_id=WeaponId.PLASMA_MINIGUN,
        clip_size=30,
        ammo=0.0,
        reload_active=True,
        reload_timer=0.85,
        reload_timer_max=1.3,
        shot_cooldown=0.0,
    )

    player.weapon.shot_cooldown = 0.05
    player_update(
        player,
        PlayerInput(aim=Vec2(700.0, 512.0), reload_pressed=True, fire_down=True),
        dt=0.06,
        state=state,
    )

    assert player.weapon.weapon_id == 11
    assert player.weapon.reload_timer > 0.0
    assert_float_close(player.weapon.reload_timer, player.weapon.reload_timer_max)
    assert player.weapon.ammo < 0.0
    assert player.shot_seq >= 1


def test_alternate_weapon_swap_held_reload_uses_native_cooldown_gate() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, WeaponId.PISTOL, state=state)
    init_default_alt_weapon(player)
    player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1
    bonus_apply(
        state,
        player,
        BonusId.WEAPON,
        creature_damage_runtime=RecordingCreatureDamageRuntime(creatures=[]),
        amount=2,
        origin=player.pos,
        creatures=[],
        players=[player],
    )

    assert player.weapon.weapon_id == 2
    player_update(player, PlayerInput(reload_pressed=True), dt=0.05, state=state)
    assert player.weapon.weapon_id == 1
    assert player.weapon.shot_cooldown == f32(0.1)
    assert state.player_alt_weapon_swap_cooldown_ms == 200

    for _ in range(3):
        player_update(player, PlayerInput(reload_pressed=True), dt=0.05, state=state)
        assert player.weapon.weapon_id == 1

    player_update(player, PlayerInput(reload_pressed=True), dt=0.05, state=state)
    assert player.weapon.weapon_id == 2
    assert state.player_alt_weapon_swap_cooldown_ms == 200


def test_alternate_weapon_swap_release_resets_cooldown_gate() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, WeaponId.PISTOL, state=state)
    init_default_alt_weapon(player)
    player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1
    bonus_apply(
        state,
        player,
        BonusId.WEAPON,
        creature_damage_runtime=RecordingCreatureDamageRuntime(creatures=[]),
        amount=2,
        origin=player.pos,
        creatures=[],
        players=[player],
    )

    player_update(player, PlayerInput(reload_pressed=True), dt=0.05, state=state)
    assert player.weapon.weapon_id == 1
    assert state.player_alt_weapon_swap_cooldown_ms == 200

    player_update(player, PlayerInput(reload_pressed=False), dt=0.05, state=state)
    assert state.player_alt_weapon_swap_cooldown_ms == 0

    player_update(player, PlayerInput(reload_pressed=True), dt=0.05, state=state)
    assert player.weapon.weapon_id == 2


def test_alternate_weapon_multiplayer_hold_not_cleared_by_other_player() -> None:
    state = GameplayState()
    player0 = PlayerState(index=0, pos=Vec2())
    player1 = PlayerState(index=1, pos=Vec2())
    players = [player0, player1]

    for player in players:
        weapon_assign_player(player, WeaponId.PISTOL, state=state)
        init_default_alt_weapon(player)
        player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1
        bonus_apply(
            state,
            player,
            BonusId.WEAPON,
            creature_damage_runtime=RecordingCreatureDamageRuntime(creatures=[]),
            amount=2,
            origin=player.pos,
            creatures=[],
            players=players,
        )
    player_update(
        player0,
        PlayerInput(reload_pressed=True, reload_down=True),
        dt=0.05,
        state=state,
        players=players,
        reload_active_any=True,
    )
    assert player0.weapon.weapon_id == 1
    assert state.player_alt_weapon_swap_cooldown_ms == 200

    player_update(
        player1,
        PlayerInput(reload_pressed=False),
        dt=0.05,
        state=state,
        players=players,
        reload_active_any=True,
    )
    assert state.player_alt_weapon_swap_cooldown_ms > 0

    player_update(
        player0,
        PlayerInput(reload_pressed=False, reload_down=True),
        dt=0.05,
        state=state,
        players=players,
        reload_active_any=True,
    )
    assert player0.weapon.weapon_id == 1
