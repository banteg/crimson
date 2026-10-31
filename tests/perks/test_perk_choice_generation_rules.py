from __future__ import annotations

from pathlib import Path

import pytest

from crimson.cl_build import ClBuild
from crimson.game_modes import GameMode
from crimson.perks import PerkId
from crimson.perks.availability import perk_id_max, prepare_perk_availability
from crimson.perks.selection import perk_generate_choices
from crimson.persistence import save_status
from crimson.quests.level import QuestLevel
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.run_init import initialize_run
from crimson.sim.run_spec import RunSpec, RunStatus
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from tests.support.helpers import ScriptedCrand, assert_rng_progression


def _status_default() -> save_status.GameStatus:
    return save_status.GameStatus.from_data(
        path=Path("game.cfg"),
        data=save_status.default_status_data(),
        dirty=False,
    )


def test_perk_generate_choices_monster_vision_forced_slot_preserves_native_order() -> None:
    # Capture quest_3_4 focus tick 25380 draws:
    #   7x perk_select_random (0x0042fbdc), 2x rarity gate (0x004046d4).
    # Native force-inserts Monster Vision first for this quest, so the later
    # random Monster Vision candidate is skipped as a duplicate and the visible
    # first three remain [30, 18, 36].
    rng = ScriptedCrand(
        [7142, 17282, 1460, 25337, 13003, 21224, 12422, 22458, 29730],
        fallback=ScriptedCrand.Fallback.REPEAT_LAST,
    )
    state = GameplayState(rng=rng)
    status = _status_default()
    status.quest_unlock_index = 49
    status.quest_unlock_index_hardcore = 49
    state.status = status
    state.quest_level = QuestLevel(3, 4)
    prepare_perk_availability(state)
    player = PlayerState(index=0, pos=Vec2())

    choices = perk_generate_choices(state, [player], game_mode=GameMode.QUESTS)
    assert choices == [
        PerkId.MONSTER_VISION,
        PerkId.ANXIOUS_LOADER,
        PerkId.VEINS_OF_POISON,
        PerkId.PERK_EXPERT,
        PerkId.FIRE_CAUGH,
        PerkId.BLOODY_MESS_QUICK_LEARNER,
        PerkId.BARREL_GREASER,
    ]
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PERK_SELECT_RANDOM,
        RngCallerStatic.PERKS_GENERATE_CHOICES_RARITY_GATE,
        RngCallerStatic.PERK_SELECT_RANDOM,
        RngCallerStatic.PERK_SELECT_RANDOM,
        RngCallerStatic.PERKS_GENERATE_CHOICES_RARITY_GATE,
        RngCallerStatic.PERK_SELECT_RANDOM,
        RngCallerStatic.PERK_SELECT_RANDOM,
        RngCallerStatic.PERK_SELECT_RANDOM,
        RngCallerStatic.PERK_SELECT_RANDOM,
    ]


def _pyromaniac_offer_choices(*weapon_ids: WeaponId, preserve_bugs: bool = False) -> list[PerkId]:
    # Seed 1 rolls Pyromaniac among these eight perks whenever it is offerable.
    state = GameplayState(rng=Crand(1), preserve_bugs=preserve_bugs)
    for perk_id in (
        PerkId.PYROMANIAC,
        PerkId.SHARPSHOOTER,
        PerkId.FASTLOADER,
        PerkId.LEAN_MEAN_EXP_MACHINE,
        PerkId.LONG_DISTANCE_RUNNER,
        PerkId.PYROKINETIC,
        PerkId.INSTANT_WINNER,
        PerkId.GRIM_DEAL,
    ):
        state.perk_available[int(perk_id)] = True

    players = [
        PlayerState(index=index, pos=Vec2(), weapon=WeaponSlot(weapon_id=weapon_id))
        for index, weapon_id in enumerate(weapon_ids)
    ]
    return perk_generate_choices(state, players, game_mode=GameMode.SURVIVAL)


def test_perk_generate_choices_rejects_pyromaniac_without_flamethrower() -> None:
    assert PerkId.PYROMANIAC not in _pyromaniac_offer_choices(WeaponId.PISTOL)


def test_perk_generate_choices_default_allows_pyromaniac_when_any_alive_player_has_flamethrower() -> None:
    assert PerkId.PYROMANIAC in _pyromaniac_offer_choices(WeaponId.PISTOL, WeaponId.FLAMETHROWER)


def test_perk_generate_choices_preserve_bugs_keeps_player1_pyromaniac_gate() -> None:
    choices = _pyromaniac_offer_choices(WeaponId.PISTOL, WeaponId.FLAMETHROWER, preserve_bugs=True)
    assert PerkId.PYROMANIAC not in choices


def test_perk_generate_choices_degenerate_all_owned_matches_reference_stream() -> None:
    status = _status_default()
    status.quest_unlock_index = 40
    rng = RecordingCrand(Crand(123))
    state = GameplayState(rng=rng)
    state.status = status
    state.quest_level = QuestLevel(4, 10)
    prepare_perk_availability(state)

    player = PlayerState(index=0, pos=Vec2())
    for idx in range(len(state.perks.counts)):
        state.perks[idx] = 1

    before_calls = rng.calls
    before_state = rng.state
    choices = perk_generate_choices(state, [player], game_mode=GameMode.QUESTS)
    assert choices == [
        PerkId.RANDOM_WEAPON,
        PerkId.INSTANT_WINNER,
        PerkId.INSTANT_WINNER,
        PerkId.INSTANT_WINNER,
        PerkId.RANDOM_WEAPON,
        PerkId.RANDOM_WEAPON,
        PerkId.INSTANT_WINNER,
    ]
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=65708,
        expected_after_state=1991494647,
    )


def test_perk_generate_choices_caches_offerability_checks(mocker) -> None:
    import crimson.perks.selection as selection_mod

    status = _status_default()
    status.quest_unlock_index = 40
    state = GameplayState(rng=Crand(123))
    state.status = status
    state.quest_level = QuestLevel(4, 10)
    prepare_perk_availability(state)

    player = PlayerState(index=0, pos=Vec2())
    for idx in range(len(state.perks.counts)):
        state.perks[idx] = 1

    original = selection_mod.perk_can_offer
    calls = 0

    def _counting_perk_can_offer(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    mocker.patch.object(selection_mod, "perk_can_offer", side_effect=_counting_perk_can_offer)
    choices = selection_mod.perk_generate_choices(state, [player], game_mode=GameMode.QUESTS)
    assert choices == [
        PerkId.RANDOM_WEAPON,
        PerkId.INSTANT_WINNER,
        PerkId.INSTANT_WINNER,
        PerkId.INSTANT_WINNER,
        PerkId.RANDOM_WEAPON,
        PerkId.RANDOM_WEAPON,
        PerkId.INSTANT_WINNER,
    ]
    assert calls <= perk_id_max(state.cl_build)


_TWO_PLAYER_EXCLUDED = {
    PerkId.GRIM_DEAL,
    PerkId.ALTERNATE_WEAPON,
    PerkId.FATAL_LOTTERY,
    PerkId.RANDOM_WEAPON,
    PerkId.FINAL_REVENGE,
    PerkId.HIGHLANDER,
}


def _offered_over_seeds(player_count: int) -> set[PerkId]:
    offered: set[PerkId] = set()
    for seed in range(64):
        state = GameplayState(rng=Crand(seed))
        status = _status_default()
        status.quest_unlock_index = 49
        state.status = status
        prepare_perk_availability(state)
        players = [PlayerState(index=index, pos=Vec2()) for index in range(player_count)]
        offered.update(perk_generate_choices(state, players, game_mode=GameMode.SURVIVAL))
    return offered


def test_perk_generate_choices_excludes_two_player_perks_for_every_coop_count() -> None:
    assert _offered_over_seeds(1) >= _TWO_PLAYER_EXCLUDED
    for player_count in (2, 3, 4):
        assert not _TWO_PLAYER_EXCLUDED & _offered_over_seeds(player_count)


@pytest.mark.parametrize(
    ("cl_build", "first"),
    [(ClBuild.V1_9_93, PerkId.MAN_BOMB), (ClBuild.V1_9_8, PerkId.LEAN_MEAN_EXP_MACHINE)],
)
def test_perk_roll_spans_the_builds_perk_ids(cl_build: ClBuild, first: PerkId) -> None:
    # 1.9.93 rolls `% 57 + 1`: 52 is Man Bomb and 56 the never-available Lifeline 50-50. 1.9.8 rolls
    # `% 53 + 1`: 52 lands on the 53 it has no perk for and 56 on Lean Mean Exp Machine.
    rng = ScriptedCrand([52, 56, 0, 1, 2, 4, 5, 6])
    state = GameplayState(rng=rng, cl_build=cl_build)
    prepare_perk_availability(state)

    choices = perk_generate_choices(state, [PlayerState(index=0, pos=Vec2())], game_mode=GameMode.SURVIVAL)

    assert choices == [
        first,
        PerkId.BLOODY_MESS_QUICK_LEARNER,
        PerkId.SHARPSHOOTER,
        PerkId.FASTLOADER,
        PerkId.LONG_DISTANCE_RUNNER,
        PerkId.PYROKINETIC,
        PerkId.INSTANT_WINNER,
    ]
    assert_rng_progression(rng, before_calls=0, before_state=0, expected_draws=8)


_PERKS_AFTER_1_9_8 = {PerkId.MAN_BOMB, PerkId.FIRE_CAUGH, PerkId.LIVING_FORTRESS, PerkId.TOUGH_RELOADER}


def _run_offers(cl_build: ClBuild) -> set[PerkId]:
    offered: set[PerkId] = set()
    for seed in range(32):
        spec = RunSpec(game_mode_id=GameMode.SURVIVAL, seed=seed, status=RunStatus(quest_unlock_index=49), cl_build=cl_build)
        world = initialize_run(spec).session.world
        offered.update(perk_generate_choices(world.state, world.players, game_mode=GameMode.SURVIVAL))
    return offered


def test_a_1_9_8_run_never_offers_the_perks_it_predates() -> None:
    assert _run_offers(ClBuild.V1_9_93) >= _PERKS_AFTER_1_9_8
    assert not _run_offers(ClBuild.V1_9_8) & _PERKS_AFTER_1_9_8
