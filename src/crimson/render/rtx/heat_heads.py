"""Baked OpenCV head tracks, shared with the native game's heat tint."""

from importlib.resources import files

import msgspec

from ...creatures.spawn import CreatureTypeId

_TRACKS = msgspec.json.decode(
    files(__package__).joinpath("heat_heads.json").read_bytes(), type=dict[str, tuple[tuple[int, int], ...]],
)
_HEADS = _TRACKS["zombie"]


def heat_head_color(type_id: CreatureTypeId, frame_index: int) -> tuple[int, int]:
    """Green/blue carry a cell-local head center; zero selects the fixed heat lobes.

    Only tracked walking cells have entries. Death, spawner and other species'
    frames retain the approved fixed positions rather than guessing anatomy.
    """
    if type_id == CreatureTypeId.ZOMBIE and 0 <= frame_index < len(_HEADS):
        return _HEADS[frame_index]
    return (0, 0)
