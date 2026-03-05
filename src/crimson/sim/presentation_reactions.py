from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .sessions import QuestSpawnState


@dataclass(frozen=True, slots=True)
class QuestPresentationReaction:
    spawn_timeline_ms: float
    completion_transition_ms: float
    name_timer_ms: float
    play_hit_sfx: bool = False
    play_completion_music: bool = False


@dataclass(frozen=True, slots=True)
class PostApplyReaction:
    sfx_keys: tuple[str, ...] = ()
    quest: QuestPresentationReaction | None = None


def resolve_quest_presentation_reaction(
    quest_state: QuestSpawnState,
    *,
    dt_seconds: float,
    current_name_timer_ms: float,
) -> QuestPresentationReaction:
    return QuestPresentationReaction(
        spawn_timeline_ms=float(quest_state.spawn_timeline_ms),
        completion_transition_ms=float(quest_state.completion_transition_ms),
        name_timer_ms=float(current_name_timer_ms) + float(dt_seconds) * 1000.0,
        play_hit_sfx=bool(quest_state.play_hit_sfx),
        play_completion_music=bool(quest_state.play_completion_music),
    )


def merge_post_apply_reactions(*reactions: PostApplyReaction | None) -> PostApplyReaction:
    sfx_keys: list[str] = []
    quest: QuestPresentationReaction | None = None
    for reaction in reactions:
        if reaction is None:
            continue
        sfx_keys.extend(str(key) for key in reaction.sfx_keys)
        if reaction.quest is not None:
            quest = reaction.quest
    return PostApplyReaction(
        sfx_keys=tuple(sfx_keys),
        quest=quest,
    )


def apply_post_apply_reaction(
    *,
    reaction: PostApplyReaction,
    play_sfx: Callable[[str], None] | None,
    play_completion_music: Callable[[], None] | None = None,
    on_quest_reaction: Callable[[QuestPresentationReaction], None] | None = None,
) -> None:
    quest = reaction.quest
    if quest is not None and on_quest_reaction is not None:
        on_quest_reaction(quest)

    if play_sfx is not None:
        for key in reaction.sfx_keys:
            play_sfx(str(key))
        if quest is not None and bool(quest.play_hit_sfx):
            play_sfx("sfx_questhit")

    if quest is not None and bool(quest.play_completion_music) and play_completion_music is not None:
        play_completion_music()
