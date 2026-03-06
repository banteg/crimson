from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .hooks import TickResult
from .sessions import QuestSpawnState


@dataclass(frozen=True, slots=True)
class QuestPresentationReaction:
    play_hit_sfx: bool = False
    play_completion_music: bool = False


@dataclass(frozen=True, slots=True)
class PostApplyReaction:
    sfx_keys: tuple[str, ...] = ()
    quest: QuestPresentationReaction | None = None


def build_post_apply_reaction(
    *,
    tick_result: TickResult,
    quest_state: QuestSpawnState | None = None,
) -> PostApplyReaction:
    if quest_state is None:
        return PostApplyReaction(
            sfx_keys=tuple(str(key) for key in tick_result.payload.step.post_apply_sfx_keys),
        )
    return PostApplyReaction(
        sfx_keys=tuple(str(key) for key in tick_result.payload.step.post_apply_sfx_keys),
        quest=QuestPresentationReaction(
            play_hit_sfx=bool(quest_state.play_hit_sfx),
            play_completion_music=bool(quest_state.play_completion_music),
        ),
    )


def apply_post_apply_reaction(
    *,
    reaction: PostApplyReaction,
    play_sfx: Callable[[str], None] | None,
    play_completion_music: Callable[[], None] | None = None,
) -> None:
    quest = reaction.quest
    if play_sfx is not None:
        for key in reaction.sfx_keys:
            play_sfx(str(key))
        if quest is not None and bool(quest.play_hit_sfx):
            play_sfx("sfx_questhit")

    if quest is not None and bool(quest.play_completion_music) and play_completion_music is not None:
        play_completion_music()
