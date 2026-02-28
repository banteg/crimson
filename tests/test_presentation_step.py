from __future__ import annotations

from itertools import count

from crimson.creatures.runtime import CreatureDeath
from crimson.creatures.spawn import CreatureTypeId
from crimson.effects import FxQueue
from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState
from crimson.projectiles import ProjectileHit, ProjectileTypeId
from crimson.sim.presentation_step import (
    apply_world_presentation_step,
    plan_death_sfx_keys,
    plan_hit_sfx_keys,
    queue_projectile_decals,
)
from crimson.sim.state_types import BonusPickupEvent, PlayerState
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.helpers import MockCrand, assert_float_close, assert_rng_progression


def _death(
    *,
    type_id: int,
    suppress_death_sfx: bool = False,
) -> CreatureDeath:
    return CreatureDeath(
        index=0,
        pos=Vec2(),
        type_id=int(type_id),
        reward_value=0.0,
        xp_awarded=0,
        owner_id=-1,
        suppress_death_sfx=bool(suppress_death_sfx),
    )


def _hits(count: int, *, type_id: int = int(ProjectileTypeId.PISTOL)) -> list[ProjectileHit]:
    hits: list[ProjectileHit] = []
    for _ in range(int(count)):
        hits.append(
            ProjectileHit(
                type_id=int(type_id),
                origin=Vec2(0.0, 0.0),
                hit=Vec2(1.0, 1.0),
                target=Vec2(1.0, 1.0),
            ),
        )
    return hits


def test_plan_hit_sfx_skips_first_hit_when_tune_not_started() -> None:
    draws = 0

    def _rand() -> int:
        nonlocal draws
        draws += 1
        return 0

    trigger_game_tune, keys = plan_hit_sfx_keys(
        _hits(2),
        game_mode=int(GameMode.SURVIVAL),
        demo_mode_active=False,
        game_tune_started=False,
        rand=_rand,
    )

    assert trigger_game_tune is True
    assert keys == ["sfx_bullet_hit_01"]
    assert draws == 2


def test_plan_hit_sfx_no_skip_when_tune_started() -> None:
    draws = 0

    def _rand() -> int:
        nonlocal draws
        draws += 1
        return 0

    trigger_game_tune, keys = plan_hit_sfx_keys(
        _hits(2),
        game_mode=int(GameMode.SURVIVAL),
        demo_mode_active=False,
        game_tune_started=True,
        rand=_rand,
    )

    assert trigger_game_tune is False
    assert keys == ["sfx_bullet_hit_01", "sfx_bullet_hit_01"]
    assert draws == 2


def test_plan_death_sfx_allows_five_randomized_deaths() -> None:
    rng = MockCrand(0, fallback="repeat_last")
    before_calls = rng.calls
    before_state = rng.state

    deaths = tuple(_death(type_id=int(CreatureTypeId.ZOMBIE)) for _ in range(5))
    keys = plan_death_sfx_keys(deaths, rand=rng)

    assert len(keys) == 5
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=5,
        expected_after_state=0,
    )


def test_plan_death_sfx_skips_suppressed_deaths() -> None:
    rng = MockCrand(0, fallback="repeat_last")
    before_calls = rng.calls
    before_state = rng.state

    deaths = (
        _death(type_id=int(CreatureTypeId.ZOMBIE), suppress_death_sfx=True),
        _death(type_id=int(CreatureTypeId.ZOMBIE), suppress_death_sfx=False),
    )
    keys = plan_death_sfx_keys(deaths, rand=rng)

    assert len(keys) == 1
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=1,
        expected_after_state=0,
    )


def test_apply_world_presentation_step_orders_sfx() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.weapon.weapon_id = WeaponId.PISTOL
    player.shot_seq = 1

    state.perk_selection.pending_count = 1

    commands = apply_world_presentation_step(
        state=state,
        players=[player],
        fx_queue=FxQueue(),
        hits=[],
        deaths=(),
        pickups=[
            BonusPickupEvent(
                player_index=0,
                bonus_id=1,
                amount=100,
                pos=Vec2(),
            ),
        ],
        event_sfx=["sfx_custom_1", "sfx_custom_2", "sfx_custom_3", "sfx_custom_4", "sfx_custom_5"],
        prev_audio=[(0, False, 0.0)],
        prev_perk_pending=0,
        game_mode=int(GameMode.SURVIVAL),
        demo_mode_active=False,
        perk_progression_enabled=True,
        rand=lambda: 0,
        detail_preset=5,
        fx_toggle=0,
        game_tune_started=False,
    )

    assert commands.trigger_game_tune is False
    assert commands.sfx_keys == [
        "sfx_ui_levelup",
        "sfx_pistol_fire",
        "sfx_ui_bonus",
        "sfx_custom_1",
        "sfx_custom_2",
        "sfx_custom_3",
        "sfx_custom_4",
    ]


def test_queue_projectile_decals_consumes_rand() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    rng = MockCrand(0, fallback="repeat_last")
    before_calls = rng.calls
    before_state = rng.state

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1),
        rand=rng,
        detail_preset=5,
        fx_toggle=0,
    )

    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=74,
        expected_after_state=0,
        expected_hash="c4a960b5d558f47f",
    )
    assert fx_queue.count > 0


def test_queue_projectile_decals_native_default_draw_count() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    rng = MockCrand(0, fallback="repeat_last")
    before_calls = rng.calls
    before_state = rng.state

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1),
        rand=rng,
        detail_preset=5,
        fx_toggle=0,
    )

    # Native `projectile_update` default creature-hit path consumes:
    # - 2x blood splatter calls + 2 branch rolls,
    # - 1 extra throwaway rand,
    # - 3x decal spread rolls + 12x `fx_queue_add_random` draws.
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=74,
        expected_after_state=0,
        expected_hash="c4a960b5d558f47f",
    )
    assert fx_queue.count == 12


def test_queue_projectile_decals_blade_gun_spawns_native_pre_branch_splatter(mocker) -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    splatter_angles: list[float] = []

    def _record_blood_splatter(
        *,
        pos: Vec2,
        angle: float,
        age: float,
        rand,
        detail_preset: int,
        fx_toggle: int,
    ) -> None:
        _ = pos, age, rand, detail_preset, fx_toggle
        splatter_angles.append(float(angle))

    mocker.patch.object(
        state.effects,
        "spawn_blood_splatter",
        side_effect=_record_blood_splatter,
    )
    rng_values = count(0)

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1, type_id=int(ProjectileTypeId.BLADE_GUN)),
        rand=lambda: int(next(rng_values)),
        detail_preset=5,
        fx_toggle=0,
    )

    assert len(splatter_angles) >= 8
    for idx in range(8):
        assert_float_close(splatter_angles[idx], float(idx) * 0.024543693)


def test_queue_projectile_decals_fire_bullets_freeze_runs_six_shard_iterations(mocker) -> None:
    state = GameplayState()
    state.bonuses.freeze = 1.0
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    spawn_freeze_shard = mocker.patch.object(
        state.effects,
        "spawn_freeze_shard",
        wraps=state.effects.spawn_freeze_shard,
    )
    rng = MockCrand(0, fallback="repeat_last")
    before_calls = rng.calls
    before_state = rng.state

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1, type_id=int(ProjectileTypeId.FIRE_BULLETS)),
        rand=rng,
        detail_preset=5,
        fx_toggle=0,
    )

    assert spawn_freeze_shard.call_count == 6
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=79,
        expected_after_state=0,
        expected_hash="56444bb167a4637e",
    )
    assert fx_queue.count == 6


def test_queue_projectile_decals_fire_bullets_freeze_runs_hooks_with_fx_toggle_set(mocker) -> None:
    state = GameplayState()
    state.bonuses.freeze = 1.0
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    spawn_freeze_shard = mocker.patch.object(
        state.effects,
        "spawn_freeze_shard",
        wraps=state.effects.spawn_freeze_shard,
    )
    rng = MockCrand(0, fallback="repeat_last")
    before_calls = rng.calls
    before_state = rng.state

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1, type_id=int(ProjectileTypeId.FIRE_BULLETS)),
        rand=rng,
        detail_preset=5,
        fx_toggle=1,
    )

    assert spawn_freeze_shard.call_count == 6
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=79,
        expected_after_state=0,
        expected_hash="56444bb167a4637e",
    )
    assert fx_queue.count == 6


def test_queue_projectile_decals_orders_blood_before_decals() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    rng = MockCrand(0, fallback="repeat_last")
    before_calls = rng.calls
    before_state = rng.state

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1),
        rand=rng,
        detail_preset=5,
        fx_toggle=0,
    )

    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=74,
        expected_after_state=0,
        expected_hash="c4a960b5d558f47f",
    )
    assert fx_queue.count == 12


def test_apply_world_presentation_step_prefers_preplanned_hit_outputs() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    rng = MockCrand(0, fallback="repeat_last")
    before_calls = rng.calls
    before_state = rng.state

    commands = apply_world_presentation_step(
        state=state,
        players=[player],
        fx_queue=FxQueue(),
        hits=_hits(1),
        deaths=(),
        pickups=[],
        event_sfx=[],
        prev_audio=[(0, False, 0.0)],
        prev_perk_pending=0,
        game_mode=int(GameMode.SURVIVAL),
        demo_mode_active=False,
        perk_progression_enabled=True,
        rand=rng,
        detail_preset=5,
        fx_toggle=0,
        game_tune_started=False,
        trigger_game_tune=True,
        hit_sfx=["sfx_bullet_hit_01"],
    )

    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=0,
        expected_after_state=0,
        expected_hash="da39a3ee5e6b4b0d",
    )
    assert commands.trigger_game_tune is True
    assert commands.sfx_keys == ["sfx_bullet_hit_01"]
