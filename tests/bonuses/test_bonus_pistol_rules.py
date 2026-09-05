from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusPool
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime.availability import prepare_weapon_availability
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_rng_progression


def _init_bonus_state(state: GameplayState) -> GameplayState:
    state.bonus_pool = BonusPool()
    prepare_weapon_availability(state)
    return state


def test_pistol_safety_net_forces_weapon_drop() -> None:
    state = _init_bonus_state(GameplayState())
    state.rng = ScriptedCrand([0, 0, 0, 1], fallback=ScriptedCrand.Fallback.ZERO)

    player = PlayerState(index=0, pos=Vec2(256.0, 256.0))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player])
    assert entry is not None
    assert entry.bonus_id == BonusId.WEAPON
    assert entry.amount == WeaponId.ASSAULT_RIFLE


def test_pistol_safety_net_preserve_bugs_requires_exact_two_player_slice() -> None:
    state = _init_bonus_state(GameplayState(preserve_bugs=True))
    rng = ScriptedCrand([0], fallback=ScriptedCrand.Fallback.RAISE)
    state.rng = rng

    players = [
        PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)),
        PlayerState(index=1, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL)),
        PlayerState(index=2, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)),
    ]

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=players)

    assert entry is None
    assert rng.calls == 1


def test_pistol_safety_net_preserve_bugs_admits_player_two_in_two_player_slice() -> None:
    state = _init_bonus_state(GameplayState(preserve_bugs=True))
    state.rng = ScriptedCrand([0, 0, 0, 1], fallback=ScriptedCrand.Fallback.ZERO)

    players = [
        PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)),
        PlayerState(index=1, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL)),
    ]

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=players)

    assert entry is not None
    assert entry.bonus_id == BonusId.WEAPON


def test_pistol_extra_gate_allows_spawn_without_bonus_magnet() -> None:
    state = _init_bonus_state(GameplayState())
    state.rng = ScriptedCrand([3, 0, 1, 0, 0], fallback=ScriptedCrand.Fallback.ZERO)

    player = PlayerState(index=0, pos=Vec2())

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(100.0, 100.0), state=state, players=[player])
    assert entry is not None


def test_pistol_extra_gate_uses_any_player_by_default() -> None:
    state = _init_bonus_state(GameplayState())
    state.rng = ScriptedCrand([3, 0, 1, 0], fallback=ScriptedCrand.Fallback.ZERO)

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(300.0, 300.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(100.0, 100.0), state=state, players=[player1, player2])
    assert entry is not None


def test_pistol_extra_gate_preserve_bugs_uses_player1_only() -> None:
    state = _init_bonus_state(GameplayState(preserve_bugs=True))
    state.rng = ScriptedCrand([3, 0, 1, 0], fallback=ScriptedCrand.Fallback.ZERO)

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(300.0, 300.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(100.0, 100.0), state=state, players=[player1, player2])
    assert entry is None


def test_weapon_drop_near_player2_converts_to_points_by_default() -> None:
    state = _init_bonus_state(GameplayState())
    state.rng = ScriptedCrand([1, 13, 1, 4], fallback=ScriptedCrand.Fallback.ZERO)

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(500.0, 500.0), weapon=WeaponSlot(weapon_id=WeaponId.SUBMACHINE_GUN))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(500.0, 500.0), state=state, players=[player1, player2])
    assert entry is not None
    assert entry.bonus_id == BonusId.POINTS
    assert entry.amount == 100


def test_weapon_drop_near_player2_stays_player1_only_with_preserve_bugs() -> None:
    state = _init_bonus_state(GameplayState(preserve_bugs=True))
    state.rng = ScriptedCrand([1, 13, 1, 4], fallback=ScriptedCrand.Fallback.ZERO)

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(500.0, 500.0), weapon=WeaponSlot(weapon_id=WeaponId.SUBMACHINE_GUN))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(500.0, 500.0), state=state, players=[player1, player2])
    assert entry is not None
    assert entry.bonus_id == BonusId.WEAPON
    assert entry.amount == WeaponId.SUBMACHINE_GUN


def test_weapon_drop_near_check_uses_native_pc24_hypotenuse_boundary() -> None:
    state = _init_bonus_state(GameplayState(preserve_bugs=True))
    state.rng = ScriptedCrand([1, 13, 1, 4], fallback=ScriptedCrand.Fallback.ZERO)

    player = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    entry = state.bonus_pool.try_spawn_on_kill(
        pos=Vec2(43.35334777832031, 35.44696044921875),
        state=state,
        players=[player],
    )

    # Double-precision dx²+dy² is below 56², but native PC=24 math rounds the
    # hypotenuse to exactly 56 and does not convert the weapon drop to points.
    assert entry is not None
    assert entry.bonus_id == BonusId.WEAPON
    assert entry.amount == WeaponId.SUBMACHINE_GUN


def test_pistol_safety_net_consumes_weapon_rng_when_spawn_pos_is_blocked() -> None:
    state = _init_bonus_state(GameplayState())
    rng = ScriptedCrand([0, 0, 2], fallback=ScriptedCrand.Fallback.ZERO)
    state.rng = rng

    player = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    before_calls = rng.calls
    before_state = rng.state

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(16.0, 100.0), state=state, players=[player])
    assert entry is None
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=3,
        expected_after_state=2,
    )
    assert not any(slot.bonus_id != BonusId.UNUSED for slot in state.bonus_pool.entries)


def test_spawn_gate_consumes_pick_rng_when_spacing_rejects_slot() -> None:
    state = _init_bonus_state(GameplayState())
    rng = ScriptedCrand([1, 0, 0], fallback=ScriptedCrand.Fallback.ZERO)
    state.rng = rng

    player = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    seeded = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.POINTS, state=state, emit_burst=False)
    assert seeded is not None
    before_calls = rng.calls
    before_state = rng.state

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(110.0, 100.0), state=state, players=[player])
    assert entry is None
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=3,
        expected_after_state=0,
    )
    active = [slot for slot in state.bonus_pool.entries if slot.bonus_id != BonusId.UNUSED]
    assert len(active) == 1


def test_weapon_drop_suppression_checks_all_carried_weapons_by_default() -> None:
    state = _init_bonus_state(GameplayState())
    state.rng = ScriptedCrand([1, 13, 1, 2], fallback=ScriptedCrand.Fallback.ZERO)

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(500.0, 500.0), weapon=WeaponSlot(weapon_id=WeaponId.SHOTGUN))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player1, player2])
    assert entry is None


def test_weapon_drop_suppression_preserve_bugs_checks_player1_weapon_only() -> None:
    state = _init_bonus_state(GameplayState(preserve_bugs=True))
    state.rng = ScriptedCrand([1, 13, 1, 2], fallback=ScriptedCrand.Fallback.ZERO)

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(500.0, 500.0), weapon=WeaponSlot(weapon_id=WeaponId.SHOTGUN))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player1, player2])
    assert entry is not None
    assert entry.bonus_id == BonusId.WEAPON
    assert entry.amount == WeaponId.SHOTGUN


def test_try_spawn_on_kill_owns_success_burst_rng() -> None:
    rng = ScriptedCrand([1, 0, 0] + [0] * 64, fallback=ScriptedCrand.Fallback.RAISE)
    state = _init_bonus_state(GameplayState(rng=rng))
    player = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))

    before_calls = rng.calls
    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player])

    assert entry is not None
    assert len(state.effects.iter_active()) == 16
    assert all(effect.pos == entry.pos for effect in state.effects.iter_active())
    assert [record.caller for record in rng.records_since(before_calls) if record.caller is not None] == [
        RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BASE_GATE,
        RngCallerStatic.BONUS_PICK_RANDOM_TYPE_ROLL,
        RngCallerStatic.BONUS_SPAWN_AT_POS_POINTS_AMOUNT,
        *(
            [
                RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BURST_ROTATION,
                RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BURST_VEL_X,
                RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BURST_VEL_Y,
                RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BURST_SCALE_STEP,
            ]
            * 16
        ),
    ]
