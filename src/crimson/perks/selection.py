from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from ..game_modes import GameMode
from ..quests.level import QuestLevel
from ..rng_caller_static import RngCallerStatic
from ..sim.state_types import PlayerState
from ..weapons import WeaponId
from .availability import perk_can_offer
from .helpers import perk_active
from .ids import PERK_BY_ID, PerkFlags, PerkId
from .runtime.apply import perk_apply
from .state import PerkSelectionState

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ..creatures.runtime import CreatureState

PERK_ID_MAX = max(int(perk_id) for perk_id in PERK_BY_ID)

_DEATH_CLOCK_BLOCKED: frozenset[PerkId] = frozenset(
    (
        PerkId.JINXED,
        PerkId.BREATHING_ROOM,
        PerkId.GRIM_DEAL,
        PerkId.HIGHLANDER,
        PerkId.FATAL_LOTTERY,
        PerkId.AMMUNITION_WITHIN,
        PerkId.INFERNAL_CONTRACT,
        PerkId.REGENERATION,
        PerkId.GREATER_REGENERATION,
        PerkId.THICK_SKINNED,
        PerkId.BANDAGE,
    ),
)

_PERK_RARITY_GATE: frozenset[PerkId] = frozenset(
    (
        PerkId.JINXED,
        PerkId.AMMUNITION_WITHIN,
        PerkId.ANXIOUS_LOADER,
        PerkId.MONSTER_VISION,
    ),
)


def perk_choice_count(player: PlayerState) -> int:
    if perk_active(player, PerkId.PERK_MASTER):
        return 7
    if perk_active(player, PerkId.PERK_EXPERT):
        return 6
    return 5


def perk_select_random(state: GameplayState, player: PlayerState, *, game_mode: GameMode, player_count: int) -> PerkId:
    """Randomly select an eligible perk id.

    Port of `perk_select_random` (0x0042fbd0).
    """

    for _ in range(1000):
        perk_id = PerkId(
            state.rng.rand_tagged(RngCallerStatic.PERK_SELECT_RANDOM) % PERK_ID_MAX + 1,
        )
        if not (0 <= int(perk_id) < len(state.perk_available)):
            continue
        if not state.perk_available[int(perk_id)]:
            continue
        if perk_can_offer(state, player, perk_id, game_mode=game_mode, player_count=player_count):
            return perk_id

    return PerkId.INSTANT_WINNER


def _perk_offerable_mask(
    state: GameplayState,
    player: PlayerState,
    *,
    game_mode: GameMode,
    player_count: int,
) -> list[bool]:
    """Build a cached `perk_select_random` eligibility mask for `1..PERK_ID_MAX`."""
    offerable: list[bool] = [False] * (PERK_ID_MAX + 1)
    max_perk_index = min(PERK_ID_MAX, len(state.perk_available) - 1)
    for perk_index in range(1, max_perk_index + 1):
        if not state.perk_available[perk_index]:
            continue
        perk_id = PerkId(perk_index)
        if perk_can_offer(state, player, perk_id, game_mode=game_mode, player_count=player_count):
            offerable[perk_index] = True
    return offerable


def perk_generate_choices(
    state: GameplayState,
    player: PlayerState,
    *,
    players: list[PlayerState] | None = None,
    game_mode: GameMode,
    player_count: int,
    count: int | None = None,
) -> list[PerkId]:
    """Generate a unique list of perk choices for the current selection."""

    if count is None:
        count = perk_choice_count(player)

    offerable_mask = _perk_offerable_mask(
        state,
        player,
        game_mode=game_mode,
        player_count=player_count,
    )
    player_perk_counts = player.perk_counts
    player_weapon_id = player.weapon.weapon_id
    death_clock_active = int(player_perk_counts[int(PerkId.DEATH_CLOCK)]) > 0
    flamethrower_id = WeaponId.FLAMETHROWER

    pyromaniac_allowed = player_weapon_id == flamethrower_id
    if not state.preserve_bugs and int(player_count) > 1:
        pyromaniac_allowed = False
        source_players = players if players is not None else [player]
        for source_player in source_players:
            if float(source_player.health) <= 0.0:
                continue
            if source_player.weapon.weapon_id == flamethrower_id:
                pyromaniac_allowed = True
                break

    def _select_random_offer() -> PerkId:
        for _ in range(1000):
            perk_index = state.rng.rand_tagged(RngCallerStatic.PERK_SELECT_RANDOM) % PERK_ID_MAX + 1
            if offerable_mask[perk_index]:
                return PerkId(perk_index)
        return PerkId.INSTANT_WINNER

    # `perks_generate_choices` always fills a fixed array of 7 entries, even if the UI
    # only shows 5/6 (Perk Expert/Master). Preserve RNG consumption by generating the
    # full list, then slicing.
    choices: list[PerkId] = [PerkId.ANTIPERK] * 7
    choice_index = 0

    # Native `quest_monster_vision_meta` points to quest 3-4 (Hidden Evil):
    # force Monster Vision as the first choice if not owned.
    if state.quest_level == QuestLevel(3, 4) and int(player_perk_counts[int(PerkId.MONSTER_VISION)]) == 0:
        choices[0] = PerkId.MONSTER_VISION
        choice_index = 1

    while choice_index < 7:
        attempts = 0
        while True:
            attempts += 1
            perk_id = _select_random_offer()

            # Native gates this on player-1 weapon only. In default mode, allow
            # it in co-op when any alive player has Flamethrower equipped.
            if perk_id == PerkId.PYROMANIAC and not pyromaniac_allowed:
                continue

            if death_clock_active and perk_id in _DEATH_CLOCK_BLOCKED:
                continue

            # Global rarity gate: certain perks have a 25% chance to be rejected.
            if (
                perk_id in _PERK_RARITY_GATE
                and (state.rng.rand_tagged(RngCallerStatic.PERKS_GENERATE_CHOICES_RARITY_GATE) & 3) == 1
            ):
                continue

            meta = PERK_BY_ID.get(perk_id)
            flags = meta.flags if meta is not None else PerkFlags(0)
            stackable = (flags & PerkFlags.STACKABLE) != 0

            if attempts > 10_000 and stackable:
                break

            if perk_id in choices[:choice_index]:
                continue

            if stackable or int(player_perk_counts[int(perk_id)]) < 1 or attempts > 29_999:
                break

        choices[choice_index] = perk_id
        choice_index += 1

    if game_mode == GameMode.TUTORIAL:
        choices = [
            PerkId.SHARPSHOOTER,
            PerkId.LONG_DISTANCE_RUNNER,
            PerkId.EVIL_EYES,
            PerkId.RADIOACTIVE,
            PerkId.FASTSHOT,
            PerkId.FASTSHOT,
            PerkId.FASTSHOT,
        ]

    return choices[:count]


def _perk_selection_prepare_if_needed(
    state: GameplayState,
    players: list[PlayerState],
    perk_state: PerkSelectionState,
    *,
    game_mode: GameMode,
    player_count: int | None = None,
) -> list[PerkId]:
    if not players:
        return []
    if player_count is None:
        player_count = len(players)
    if perk_state.choices_dirty or not perk_state.choices:
        perk_state.choices = perk_generate_choices(
            state,
            players[0],
            players=players,
            game_mode=game_mode,
            player_count=player_count,
            count=7,
        )
        perk_state.choices_dirty = False
    return perk_state.choices


def perk_selection_prepared_choices(
    players: list[PlayerState],
    perk_state: PerkSelectionState,
) -> list[PerkId]:
    """Return already-prepared visible choices without mutating state."""

    if not players:
        return []
    if perk_state.choices_dirty or not perk_state.choices:
        return []
    visible_count = max(1, int(perk_choice_count(players[0])))
    return perk_state.choices[:visible_count]


def perk_selection_open_choices(
    state: GameplayState,
    players: list[PlayerState],
    perk_state: PerkSelectionState,
    *,
    game_mode: GameMode,
    player_count: int | None = None,
) -> list[PerkId]:
    """Prepare current perk choices for the selection UI and return the visible list.

    Mirrors `perk_choices_dirty` + `perks_generate_choices` before entering the
    perk selection screen (state 6).
    """

    _perk_selection_prepare_if_needed(
        state,
        players,
        perk_state,
        game_mode=game_mode,
        player_count=player_count,
    )
    return perk_selection_prepared_choices(players, perk_state)


def perk_selection_pick(
    state: GameplayState,
    players: list[PlayerState],
    perk_state: PerkSelectionState,
    choice_index: int,
    *,
    game_mode: GameMode,
    player_count: int | None = None,
    dt: float | None = None,
    creatures: Sequence[CreatureState] | None = None,
    refresh_choices: bool = False,
) -> PerkId | None:
    """Pick a perk from the current choice list and apply it.

    On success, decrements `pending_count` (one perk resolved) and marks the
    choice list dirty, matching `perk_selection_screen_update`.
    """

    if perk_state.pending_count <= 0:
        return None
    _perk_selection_prepare_if_needed(
        state,
        players,
        perk_state,
        game_mode=game_mode,
        player_count=player_count,
    )
    choices = perk_selection_prepared_choices(players, perk_state)
    if not choices:
        return None
    idx = int(choice_index)
    if idx < 0 or idx >= len(choices):
        return None
    perk_id = choices[idx]
    perk_apply(state, players, perk_id, perk_state=perk_state, dt=dt, creatures=creatures)
    assert int(perk_state.pending_count) > 0, "picked perk must leave a pending perk to resolve"
    perk_state.pending_count -= 1
    perk_state.choices_dirty = True
    if refresh_choices:
        _perk_selection_prepare_if_needed(
            state,
            players,
            perk_state,
            game_mode=game_mode,
            player_count=player_count,
        )
    return perk_id
