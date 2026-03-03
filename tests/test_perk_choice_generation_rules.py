from __future__ import annotations

from pathlib import Path
from typing import Any

from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.perks.availability import perks_rebuild_available
from crimson.perks.selection import PERK_ID_MAX, perk_generate_choices
from crimson.persistence import save_status
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.helpers import assert_rng_progression


class _SeqRng:
    def __init__(self, values: list[int]) -> None:
        self._values = [int(v) for v in values] or [0]
        self._idx = 0

    def rand(self) -> int:
        value = int(self._values[self._idx % len(self._values)])
        self._idx += 1
        return value


def _as_rng(value: object) -> Any:
    return value


def _status_default() -> save_status.GameStatus:
    return save_status.GameStatus(path=Path("game.cfg"), data=save_status.default_status_data(), dirty=False)


def test_perks_rebuild_available_unlocks_base_and_quest_perks() -> None:
    status = _status_default()
    status.quest_unlock_index = 0
    state = GameplayState()
    state.status = status
    perks_rebuild_available(state)

    assert state.perk_available[int(PerkId.BONUS_MAGNET)]
    assert not state.perk_available[int(PerkId.URANIUM_FILLED_BULLETS)]

    status.quest_unlock_index = 3  # includes quest 1.3 unlock_perk_id=URANIUM_FILLED_BULLETS
    perks_rebuild_available(state)
    assert state.perk_available[int(PerkId.URANIUM_FILLED_BULLETS)]


def test_perk_generate_choices_inserts_monster_vision_on_quest_3_4() -> None:
    # `perk_generate_choices` always fills a 7-entry list; provide enough entropy to avoid
    # degenerately selecting from a tiny, repeatedly invalid subset.
    state = GameplayState(rng=_as_rng(_SeqRng(list(range(2048)))))
    state.quest_stage_major = 3
    state.quest_stage_minor = 4
    player = PlayerState(index=0, pos=Vec2())

    choices = perk_generate_choices(state, player, game_mode=GameMode.QUESTS, player_count=1)
    assert choices and choices[0] == PerkId.MONSTER_VISION


def test_perk_generate_choices_inserts_monster_vision_when_capture_counts_unknown() -> None:
    state = GameplayState(rng=_as_rng(_SeqRng(list(range(2048)))))
    state.quest_stage_major = 3
    state.quest_stage_minor = 4
    state.perk_selection.capture_player_perk_counts_known = False
    player = PlayerState(index=0, pos=Vec2())

    choices = perk_generate_choices(state, player, game_mode=GameMode.QUESTS, player_count=1)
    assert choices and choices[0] == PerkId.MONSTER_VISION


def test_perk_generate_choices_monster_vision_forced_slot_preserves_native_order() -> None:
    # Capture quest_3_4 focus tick 25380 draws:
    #   7x perk_select_random (0x0042fbdc), 2x rarity gate (0x004046d4).
    # Native force-inserts Monster Vision first for this quest, so the later
    # random Monster Vision candidate is skipped as a duplicate and the visible
    # first three remain [30, 18, 36].
    state = GameplayState(
        rng=_as_rng(_SeqRng([7142, 17282, 1460, 25337, 13003, 21224, 12422, 22458, 29730])),
    )
    status = _status_default()
    status.quest_unlock_index = 49
    status.quest_unlock_index_full = 49
    state.status = status
    state.quest_stage_major = 3
    state.quest_stage_minor = 4
    player = PlayerState(index=0, pos=Vec2())

    choices = perk_generate_choices(
        state,
        player,
        game_mode=GameMode.QUESTS,
        player_count=1,
        count=7,
    )
    assert choices == [
        PerkId.MONSTER_VISION,
        PerkId.ANXIOUS_LOADER,
        PerkId.VEINS_OF_POISON,
        PerkId.PERK_EXPERT,
        PerkId.FIRE_CAUGH,
        PerkId.BLOODY_MESS_QUICK_LEARNER,
        PerkId.BARREL_GREASER,
    ]


def test_perk_generate_choices_rejects_pyromaniac_without_flamethrower() -> None:
    state = GameplayState(rng=_as_rng(_SeqRng([38, 1, 2, 3, 4, 5, 6, 7])))
    state._perk_available_unlock_index = 0
    for perk_id in (PerkId.PYROMANIAC, PerkId.SHARPSHOOTER, PerkId.FASTLOADER, PerkId.LEAN_MEAN_EXP_MACHINE, PerkId.LONG_DISTANCE_RUNNER, PerkId.PYROKINETIC, PerkId.INSTANT_WINNER, PerkId.GRIM_DEAL):
        state.perk_available[int(perk_id)] = True

    player = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    choices = perk_generate_choices(state, player, game_mode=GameMode.SURVIVAL, player_count=1)
    assert PerkId.PYROMANIAC not in choices


def test_perk_generate_choices_default_allows_pyromaniac_when_any_alive_player_has_flamethrower() -> None:
    state = GameplayState(rng=_as_rng(_SeqRng([38, 1, 2, 3, 4, 5, 6, 7])), preserve_bugs=False)
    state._perk_available_unlock_index = 0
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

    player0 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    player1 = PlayerState(index=1, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.FLAMETHROWER))
    choices = perk_generate_choices(
        state,
        player0,
        players=[player0, player1],
        game_mode=GameMode.SURVIVAL,
        player_count=2,
    )
    assert PerkId.PYROMANIAC in choices


def test_perk_generate_choices_preserve_bugs_keeps_player1_pyromaniac_gate() -> None:
    state = GameplayState(rng=_as_rng(_SeqRng([38, 1, 2, 3, 4, 5, 6, 7])), preserve_bugs=True)
    state._perk_available_unlock_index = 0
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

    player0 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    player1 = PlayerState(index=1, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.FLAMETHROWER))
    choices = perk_generate_choices(
        state,
        player0,
        players=[player0, player1],
        game_mode=GameMode.SURVIVAL,
        player_count=2,
    )
    assert PerkId.PYROMANIAC not in choices


def test_perk_generate_choices_blocks_perks_when_death_clock_active() -> None:
    state = GameplayState(rng=_as_rng(_SeqRng([41, 1, 2, 3, 4, 5, 6, 9])))
    perks_rebuild_available(state)
    state.perk_available[int(PerkId.JINXED)] = True

    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.DEATH_CLOCK)] = 1

    choices = perk_generate_choices(state, player, game_mode=GameMode.SURVIVAL, player_count=1)
    assert PerkId.JINXED not in choices


def test_perk_generate_choices_applies_rarity_gate() -> None:
    # Anxious Loader is in the global rarity gate; when (rand & 3) == 1 it is rejected.
    state = GameplayState(rng=_as_rng(_SeqRng([17, 1, 1, 2, 3, 4, 5, 6, 7])))
    state._perk_available_unlock_index = 0
    for perk_id in (PerkId.ANXIOUS_LOADER, PerkId.SHARPSHOOTER, PerkId.FASTLOADER, PerkId.LEAN_MEAN_EXP_MACHINE, PerkId.LONG_DISTANCE_RUNNER, PerkId.PYROKINETIC, PerkId.INSTANT_WINNER, PerkId.GRIM_DEAL):
        state.perk_available[int(perk_id)] = True

    player = PlayerState(index=0, pos=Vec2())
    choices = perk_generate_choices(state, player, game_mode=GameMode.SURVIVAL, player_count=1)
    assert PerkId.ANXIOUS_LOADER not in choices


def test_perk_generate_choices_degenerate_all_owned_matches_reference_stream() -> None:
    class _LcgRng:
        def __init__(self, seed: int) -> None:
            self._state = int(seed) & 0x7FFFFFFF
            self.calls = 0

        @property
        def state(self) -> int:
            return int(self._state)

        def rand(self) -> int:
            self.calls += 1
            self._state = (1103515245 * self._state + 12345) & 0x7FFFFFFF
            return self._state

    status = _status_default()
    status.quest_unlock_index = 40
    rng = _LcgRng(123)
    state = GameplayState(rng=_as_rng(rng))
    state.status = status
    state.quest_stage_major = 4
    state.quest_stage_minor = 10
    perks_rebuild_available(state)

    player = PlayerState(index=0, pos=Vec2())
    for idx in range(len(player.perk_counts)):
        player.perk_counts[idx] = 1

    before_calls = rng.calls
    before_state = rng.state
    choices = perk_generate_choices(state, player, game_mode=GameMode.QUESTS, player_count=1, count=7)
    assert choices == [
        PerkId.RANDOM_WEAPON,
        PerkId.INSTANT_WINNER,
        PerkId.RANDOM_WEAPON,
        PerkId.RANDOM_WEAPON,
        PerkId.RANDOM_WEAPON,
        PerkId.RANDOM_WEAPON,
        PerkId.RANDOM_WEAPON,
    ]
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=65860,
        expected_after_state=790131735,
    )


def test_perk_generate_choices_caches_offerability_checks(mocker) -> None:
    import crimson.perks.selection as selection_mod

    status = _status_default()
    status.quest_unlock_index = 40
    state = GameplayState(rng=_as_rng(_SeqRng(list(range(2048)))))
    state.status = status
    state.quest_stage_major = 4
    state.quest_stage_minor = 10
    perks_rebuild_available(state)

    player = PlayerState(index=0, pos=Vec2())
    for idx in range(len(player.perk_counts)):
        player.perk_counts[idx] = 1

    original = selection_mod.perk_can_offer
    calls = 0

    def _counting_perk_can_offer(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    mocker.patch.object(selection_mod, "perk_can_offer", side_effect=_counting_perk_can_offer)
    choices = selection_mod.perk_generate_choices(state, player, game_mode=GameMode.QUESTS, player_count=1, count=7)
    assert choices == [
        PerkId.INSTANT_WINNER,
        PerkId.RANDOM_WEAPON,
        PerkId.INSTANT_WINNER,
        PerkId.INSTANT_WINNER,
        PerkId.INSTANT_WINNER,
        PerkId.INSTANT_WINNER,
        PerkId.INSTANT_WINNER,
    ]
    assert calls <= PERK_ID_MAX
