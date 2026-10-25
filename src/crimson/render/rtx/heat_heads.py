"""Baked OpenCV head tracks, shared with the native game's heat tint."""

from importlib.resources import files

import msgspec

from ...creatures.spawn import CreatureTypeId

_TRACKS = msgspec.json.decode(
    files(__package__).joinpath("heat_heads.json").read_bytes(), type=dict[str, tuple[tuple[int, int], ...]],
)
_HEADS = {CreatureTypeId.ZOMBIE: _TRACKS["zombie"], CreatureTypeId.LIZARD: _TRACKS["lizard"]}


def heat_head_color(type_id: CreatureTypeId, frame_index: int) -> tuple[int, int]:
    """Green/blue carry a cell-local head center; zero selects the fixed heat lobes.

    Only tracked walking cells have entries. Death, spawner and other species'
    frames retain the approved fixed positions rather than guessing anatomy.
    """
    frames = _HEADS.get(type_id, ())
    return frames[frame_index] if 0 <= frame_index < len(frames) else (0, 0)
