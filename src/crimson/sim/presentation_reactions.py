from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from grim.sfx_map import SfxId

from .hooks import TickResult
from .sessions import QuestSpawnState


@dataclass(frozen=True, slots=True)
class QuestPresentationReaction:
    play_hit_sfx: bool = False
    play_completion_music: bool = False


@dataclass(frozen=True, slots=True)
class PostApplyReaction:
    sfx: tuple[SfxId, ...] = ()
    quest: QuestPresentationReaction | None = None


def build_post_apply_reaction(
    *,
    tick_result: TickResult,
    quest_state: QuestSpawnState | None = None,
) -> PostApplyReaction:
    if quest_state is None:
        return PostApplyReaction(
            sfx=tuple(tick_result.payload.step.presentation.post_apply_sfx),
        )
    return PostApplyReaction(
        sfx=tuple(tick_result.payload.step.presentation.post_apply_sfx),
        quest=QuestPresentationReaction(
            play_hit_sfx=bool(quest_state.play_hit_sfx),
            play_completion_music=bool(quest_state.play_completion_music),
        ),
    )


def apply_post_apply_reaction(
    *,
    reaction: PostApplyReaction,
    play_sfx: Callable[[SfxId], None] | None,
    play_completion_music: Callable[[], None] | None = None,
) -> None:
    quest = reaction.quest
    if play_sfx is not None:
        for sfx in reaction.sfx:
            play_sfx(sfx)
        if quest is not None and bool(quest.play_hit_sfx):
            play_sfx(SfxId.QUESTHIT)

    if quest is not None and bool(quest.play_completion_music) and play_completion_music is not None:
        play_completion_music()
