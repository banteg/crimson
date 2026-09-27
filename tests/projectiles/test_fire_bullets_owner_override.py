from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.gameplay import player_update
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime.spawn import projectile_spawn
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime


def _spawn_type(
    state: GameplayState,
    *,
    players: list[PlayerState],
    owner: OwnerRef,
    owner_player_index: int | None = None,
) -> int:
    proj_id = projectile_spawn(
        state,
        players=players,
        pos=Vec2(100.0, 100.0),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner=owner,
        owner_player_index=owner_player_index,
    )
    assert proj_id >= 0
    return int(state.projectiles.entries[proj_id].type_id)


def _active_type_ids(state: GameplayState) -> list[int]:
    return [int(entry.type_id) for entry in state.projectiles.entries if bool(entry.active)]


def _nuke_type_ids(*, preserve_bugs: bool, fire_bullets_timers: tuple[float, float]) -> list[int]:
    """Player 1 picks up a nuke; return the projectile types its burst spawned."""

    world = make_world(player_count=2, preserve_bugs=preserve_bugs)
    for player, pos, timer in zip(world.players, (Vec2(100.0, 100.0), Vec2(120.0, 100.0)), fire_bullets_timers, strict=True):
        player.pos = pos
        player.fire_bullets_timer = timer
    player1 = world.players[1]

    bonus_apply(
        world.state,
        player1,
        BonusId.NUKE,
        step_runtime=make_step_runtime(world),
        origin=player1.pos,
        creatures=world.creatures.entries,
        players=world.players,
        detail_preset=5,
    )
    return _active_type_ids(world.state)


def test_projectile_spawn_fire_bullets_default_uses_owner_timer() -> None:
    state = GameplayState(preserve_bugs=False)
    player0 = PlayerState(index=0, pos=Vec2(), fire_bullets_timer=1.0)
    player1 = PlayerState(index=1, pos=Vec2(), fire_bullets_timer=0.0)
    players = [player0, player1]

    player1_type = _spawn_type(state, players=players, owner=OwnerRef.from_player(1))
    player0_type = _spawn_type(state, players=players, owner=OwnerRef.from_player(0))

    assert player1_type == int(ProjectileTemplateId.PISTOL)
    assert player0_type == int(ProjectileTemplateId.FIRE_BULLETS)


def test_projectile_spawn_fire_bullets_default_resolves_owner_index_in_player_slice() -> None:
    state = GameplayState(preserve_bugs=False)
    player1 = PlayerState(index=1, pos=Vec2(), fire_bullets_timer=1.0)

    player1_type = _spawn_type(state, players=[player1], owner=OwnerRef.from_local_player(0), owner_player_index=1)

    assert player1_type == int(ProjectileTemplateId.FIRE_BULLETS)


def test_projectile_spawn_fire_bullets_default_uses_owner_player_index_with_owner_minus_100() -> None:
    state = GameplayState(preserve_bugs=False)
    player0 = PlayerState(index=0, pos=Vec2(), fire_bullets_timer=1.0)
    player1 = PlayerState(index=1, pos=Vec2(), fire_bullets_timer=0.0)
    players = [player0, player1]

    player1_type = _spawn_type(state, players=players, owner=OwnerRef.from_local_player(0), owner_player_index=1)
    player0_type = _spawn_type(state, players=players, owner=OwnerRef.from_local_player(0), owner_player_index=0)

    assert player1_type == int(ProjectileTemplateId.PISTOL)
    assert player0_type == int(ProjectileTemplateId.FIRE_BULLETS)


def test_projectile_spawn_fire_bullets_preserve_bugs_keeps_global_gate() -> None:
    state = GameplayState(preserve_bugs=True)
    player0 = PlayerState(index=0, pos=Vec2(), fire_bullets_timer=1.0)
    player1 = PlayerState(index=1, pos=Vec2(), fire_bullets_timer=0.0)
    players = [player0, player1]

    player1_type = _spawn_type(state, players=players, owner=OwnerRef.from_player(1))

    assert player1_type == int(ProjectileTemplateId.FIRE_BULLETS)


def test_projectile_spawn_preserve_bugs_keeps_native_owner_window() -> None:
    players = [
        PlayerState(index=0, pos=Vec2(), fire_bullets_timer=1.0),
        PlayerState(index=1, pos=Vec2()),
        PlayerState(index=2, pos=Vec2()),
        PlayerState(index=3, pos=Vec2()),
    ]

    preserved_state = GameplayState(preserve_bugs=True)
    preserved_type = _spawn_type(
        preserved_state,
        players=players,
        owner=OwnerRef.from_player(3),
    )
    assert preserved_type == int(ProjectileTemplateId.PISTOL)
    assert preserved_state.shots_fired[3] == 0
    assert preserved_state.shots_fired_total == 0

    corrected_state = GameplayState(preserve_bugs=False)
    corrected_type = _spawn_type(
        corrected_state,
        players=players,
        owner=OwnerRef.from_player(3),
    )
    assert corrected_type == int(ProjectileTemplateId.PISTOL)
    assert corrected_state.shots_fired[3] == 1
    assert corrected_state.shots_fired_total == 1


def test_nuke_fire_bullets_default_is_owner_scoped_but_still_converts_for_owner() -> None:
    non_owner_types = _nuke_type_ids(preserve_bugs=False, fire_bullets_timers=(1.0, 0.0))

    assert int(ProjectileTemplateId.FIRE_BULLETS) not in non_owner_types
    assert set(non_owner_types) <= {int(ProjectileTemplateId.PISTOL), int(ProjectileTemplateId.GAUSS_GUN)}

    owner_types = _nuke_type_ids(preserve_bugs=False, fire_bullets_timers=(0.0, 1.0))

    assert owner_types
    assert set(owner_types) == {int(ProjectileTemplateId.FIRE_BULLETS)}


def test_hot_tempered_and_man_bomb_fire_bullets_default_are_owner_scoped() -> None:
    state = GameplayState(preserve_bugs=False)
    player0 = PlayerState(index=0, pos=Vec2(100.0, 100.0), fire_bullets_timer=1.0)
    player1 = PlayerState(index=1, pos=Vec2(120.0, 100.0), fire_bullets_timer=0.0, hot_tempered_timer=1.95)
    state.perks[int(PerkId.HOT_TEMPERED)] = 1
    player_update(
        state=state, player=player1, input_state=PlayerInput(aim=Vec2(121.0, 100.0)), dt=0.1, players=[player0, player1],
    )
    hot_types_non_owner = _active_type_ids(state)
    assert int(ProjectileTemplateId.FIRE_BULLETS) not in hot_types_non_owner

    state = GameplayState(preserve_bugs=False)
    player0 = PlayerState(index=0, pos=Vec2(100.0, 100.0), fire_bullets_timer=0.0)
    player1 = PlayerState(index=1, pos=Vec2(120.0, 100.0), fire_bullets_timer=1.0, hot_tempered_timer=1.95)
    state.perks[int(PerkId.HOT_TEMPERED)] = 1
    player_update(
        state=state, player=player1, input_state=PlayerInput(aim=Vec2(121.0, 100.0)), dt=0.1, players=[player0, player1],
    )
    hot_types_owner = _active_type_ids(state)
    assert hot_types_owner
    assert set(hot_types_owner) == {int(ProjectileTemplateId.FIRE_BULLETS)}

    state = GameplayState(preserve_bugs=False)
    player0 = PlayerState(index=0, pos=Vec2(100.0, 100.0), fire_bullets_timer=1.0)
    player1 = PlayerState(index=1, pos=Vec2(120.0, 100.0), fire_bullets_timer=0.0, man_bomb_timer=3.9)
    state.perks[int(PerkId.MAN_BOMB)] = 1
    player_update(
        state=state, player=player1, input_state=PlayerInput(aim=Vec2(121.0, 100.0)), dt=0.2, players=[player0, player1],
    )
    man_bomb_types_non_owner = _active_type_ids(state)
    assert int(ProjectileTemplateId.FIRE_BULLETS) not in man_bomb_types_non_owner

    state = GameplayState(preserve_bugs=False)
    player0 = PlayerState(index=0, pos=Vec2(100.0, 100.0), fire_bullets_timer=0.0)
    player1 = PlayerState(index=1, pos=Vec2(120.0, 100.0), fire_bullets_timer=1.0, man_bomb_timer=3.9)
    state.perks[int(PerkId.MAN_BOMB)] = 1
    player_update(
        state=state, player=player1, input_state=PlayerInput(aim=Vec2(121.0, 100.0)), dt=0.2, players=[player0, player1],
    )
    man_bomb_types_owner = _active_type_ids(state)
    assert man_bomb_types_owner
    assert set(man_bomb_types_owner) == {int(ProjectileTemplateId.FIRE_BULLETS)}


def test_nuke_and_perk_fire_bullets_preserve_bugs_keeps_global_conversion() -> None:
    nuke_types = _nuke_type_ids(preserve_bugs=True, fire_bullets_timers=(1.0, 0.0))
    assert nuke_types
    assert set(nuke_types) == {int(ProjectileTemplateId.FIRE_BULLETS)}

    state = GameplayState(preserve_bugs=True)
    player0 = PlayerState(index=0, pos=Vec2(100.0, 100.0), fire_bullets_timer=1.0)
    player1 = PlayerState(index=1, pos=Vec2(120.0, 100.0), fire_bullets_timer=0.0, hot_tempered_timer=1.95)
    state.perks[int(PerkId.HOT_TEMPERED)] = 1
    player_update(
        state=state, player=player1, input_state=PlayerInput(aim=Vec2(121.0, 100.0)), dt=0.1, players=[player0, player1],
    )
    hot_types = _active_type_ids(state)
    assert hot_types
    assert set(hot_types) == {int(ProjectileTemplateId.FIRE_BULLETS)}

    state = GameplayState(preserve_bugs=True)
    player0 = PlayerState(index=0, pos=Vec2(100.0, 100.0), fire_bullets_timer=1.0)
    player1 = PlayerState(index=1, pos=Vec2(120.0, 100.0), fire_bullets_timer=0.0, man_bomb_timer=3.9)
    state.perks[int(PerkId.MAN_BOMB)] = 1
    player_update(
        state=state, player=player1, input_state=PlayerInput(aim=Vec2(121.0, 100.0)), dt=0.2, players=[player0, player1],
    )
    man_bomb_types = _active_type_ids(state)
    assert man_bomb_types
    assert set(man_bomb_types) == {int(ProjectileTemplateId.FIRE_BULLETS)}
