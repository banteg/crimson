from __future__ import annotations

from grim.geom import Vec2
import pytest

from pathlib import Path

from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState, PlayerState
from crimson.persistence import save_status
from crimson.perks import PerkId
from crimson.perks.availability import perks_rebuild_available
from crimson.perks.selection import PERK_ID_MAX, perk_generate_choices


class _SeqRng:
    def __init__(self, values: list[int]) -> None:
        self._values = [int(v) for v in values] or [0]
        self._idx = 0

    def rand(self) -> int:
        value = int(self._values[self._idx % len(self._values)])
        self._idx += 1
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


def test_perk_generate_choices_inserts_monster_vision_on_quest_1_7() -> None:
    # `perk_generate_choices` always fills a 7-entry list; provide enough entropy to avoid
    # degenerately selecting from a tiny, repeatedly invalid subset.
    state = GameplayState(rng=_SeqRng(list(range(2048))))
    state.quest_stage_major = 1
    state.quest_stage_minor = 7
    player = PlayerState(index=0, pos=Vec2())

    choices = perk_generate_choices(state, player, game_mode=int(GameMode.QUESTS), player_count=1)
    assert choices and choices[0] == PerkId.MONSTER_VISION


def test_perk_generate_choices_rejects_pyromaniac_without_flamethrower() -> None:
    state = GameplayState(rng=_SeqRng([38, 1, 2, 3, 4, 5, 6, 7]))
    state._perk_available_unlock_index = 0
    for perk_id in (PerkId.PYROMANIAC, PerkId.SHARPSHOOTER, PerkId.FASTLOADER, PerkId.LEAN_MEAN_EXP_MACHINE, PerkId.LONG_DISTANCE_RUNNER, PerkId.PYROKINETIC, PerkId.INSTANT_WINNER, PerkId.GRIM_DEAL):
        state.perk_available[int(perk_id)] = True

    player = PlayerState(index=0, pos=Vec2(), weapon_id=1)
    choices = perk_generate_choices(state, player, game_mode=int(GameMode.SURVIVAL), player_count=1)
    assert PerkId.PYROMANIAC not in choices


def test_perk_generate_choices_blocks_perks_when_death_clock_active() -> None:
    state = GameplayState(rng=_SeqRng([41, 1, 2, 3, 4, 5, 6, 9]))
    perks_rebuild_available(state)
    state.perk_available[int(PerkId.JINXED)] = True

    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.DEATH_CLOCK)] = 1

    choices = perk_generate_choices(state, player, game_mode=int(GameMode.SURVIVAL), player_count=1)
    assert PerkId.JINXED not in choices


def test_perk_generate_choices_applies_rarity_gate() -> None:
    # Anxious Loader is in the global rarity gate; when (rand & 3) == 1 it is rejected.
    state = GameplayState(rng=_SeqRng([17, 1, 1, 2, 3, 4, 5, 6, 7]))
    state._perk_available_unlock_index = 0
    for perk_id in (PerkId.ANXIOUS_LOADER, PerkId.SHARPSHOOTER, PerkId.FASTLOADER, PerkId.LEAN_MEAN_EXP_MACHINE, PerkId.LONG_DISTANCE_RUNNER, PerkId.PYROKINETIC, PerkId.INSTANT_WINNER, PerkId.GRIM_DEAL):
        state.perk_available[int(perk_id)] = True

    player = PlayerState(index=0, pos=Vec2())
    choices = perk_generate_choices(state, player, game_mode=int(GameMode.SURVIVAL), player_count=1)
    assert PerkId.ANXIOUS_LOADER not in choices


def test_perk_generate_choices_degenerate_all_owned_matches_reference_stream() -> None:
    class _LcgRng:
        def __init__(self, seed: int) -> None:
            self._state = int(seed) & 0x7FFFFFFF
            self.calls = 0

        def rand(self) -> int:
            self.calls += 1
            self._state = (1103515245 * self._state + 12345) & 0x7FFFFFFF
            return self._state

    status = _status_default()
    status.quest_unlock_index = 40
    rng = _LcgRng(123)
    state = GameplayState(rng=rng)
    state.status = status
    state.quest_stage_major = 4
    state.quest_stage_minor = 10
    perks_rebuild_available(state)

    player = PlayerState(index=0, pos=Vec2())
    for idx in range(len(player.perk_counts)):
        player.perk_counts[idx] = 1

    choices = perk_generate_choices(state, player, game_mode=int(GameMode.QUESTS), player_count=1, count=7)
    assert choices == [
        PerkId.RANDOM_WEAPON,
        PerkId.INSTANT_WINNER,
        PerkId.RANDOM_WEAPON,
        PerkId.RANDOM_WEAPON,
        PerkId.RANDOM_WEAPON,
        PerkId.RANDOM_WEAPON,
        PerkId.RANDOM_WEAPON,
    ]
    assert rng.calls == 65860


def test_perk_generate_choices_caches_offerability_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    import crimson.perks.selection as selection_mod

    status = _status_default()
    status.quest_unlock_index = 40
    state = GameplayState(rng=_SeqRng(list(range(2048))))
    state.status = status
    state.quest_stage_major = 4
    state.quest_stage_minor = 10
    perks_rebuild_available(state)

    player = PlayerState(index=0, pos=Vec2())
    for idx in range(len(player.perk_counts)):
        player.perk_counts[idx] = 1

    original = selection_mod.perk_can_offer
    calls = 0

    def _counting_perk_can_offer(*args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(selection_mod, "perk_can_offer", _counting_perk_can_offer)
    choices = selection_mod.perk_generate_choices(state, player, game_mode=int(GameMode.QUESTS), player_count=1, count=7)
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
