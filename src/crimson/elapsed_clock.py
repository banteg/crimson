from __future__ import annotations

from typing import Literal, cast

from .game_modes import GameMode

ElapsedFieldName = Literal[
    "sim_elapsed_ms",
    "raw_frame_elapsed_ms",
    "quest_spawn_timeline_ms",
    "presentation_elapsed_ms",
]
SessionElapsedSource = Literal["sim_elapsed_ms", "raw_frame_elapsed_ms"]

SESSION_ELAPSED_FIELDS: tuple[SessionElapsedSource, ...] = (
    "sim_elapsed_ms",
    "raw_frame_elapsed_ms",
)
AUTHORITATIVE_ELAPSED_FIELDS: tuple[ElapsedFieldName, ...] = (
    "sim_elapsed_ms",
    "raw_frame_elapsed_ms",
    "quest_spawn_timeline_ms",
    "presentation_elapsed_ms",
)


def elapsed_field_name(
    value: object,
    *,
    allowed: tuple[ElapsedFieldName, ...] = AUTHORITATIVE_ELAPSED_FIELDS,
) -> ElapsedFieldName:
    for field in allowed:
        if hasattr(value, field):
            return field
    allowed_text = ", ".join(allowed)
    raise TypeError(f"value does not expose an elapsed field from {{{allowed_text}}}: {type(value).__name__}")


def elapsed_ms_value(
    value: object,
    *,
    allowed: tuple[ElapsedFieldName, ...] = AUTHORITATIVE_ELAPSED_FIELDS,
) -> int:
    field = elapsed_field_name(value, allowed=allowed)
    raw = getattr(value, field)
    return int(raw)


def session_elapsed_source_for_mode(mode_id: GameMode | int) -> SessionElapsedSource:
    mode = GameMode(int(mode_id))
    if mode == GameMode.RUSH:
        return "raw_frame_elapsed_ms"
    return "sim_elapsed_ms"


def authoritative_elapsed_field_for_mode(mode_id: GameMode | int) -> ElapsedFieldName:
    mode = GameMode(int(mode_id))
    if mode == GameMode.RUSH:
        return "raw_frame_elapsed_ms"
    if mode == GameMode.QUESTS:
        return "quest_spawn_timeline_ms"
    return cast(ElapsedFieldName, "sim_elapsed_ms")
