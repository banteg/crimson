from __future__ import annotations

import msgspec

from grim.sfx_map import SfxId

from .hooks import TickResult
from .sessions import QuestSpawnState


class QuestPresentationReaction(msgspec.Struct, frozen=True):
    play_hit_sfx: bool = False
    play_completion_music: bool = False


class PostApplyReaction(msgspec.Struct, frozen=True):
    sfx: tuple[SfxId, ...] = ()
    quest: QuestPresentationReaction | None = None


class PostApplyReactionRuntime(msgspec.Struct):
    def play_sfx(self, sfx: SfxId) -> None:
        _ = sfx

    def play_completion_music(self) -> None:
        pass


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
    runtime: PostApplyReactionRuntime | None = None,
) -> None:
    if runtime is None:
        return
    quest = reaction.quest
    for sfx in reaction.sfx:
        runtime.play_sfx(sfx)
    if quest is not None and bool(quest.play_hit_sfx):
        runtime.play_sfx(SfxId.QUESTHIT)

    if quest is not None and bool(quest.play_completion_music):
        runtime.play_completion_music()
