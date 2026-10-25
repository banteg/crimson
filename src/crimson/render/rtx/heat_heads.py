"""Zombie walking frames' head centers, baked once with OpenCV optical flow; the native game reads the same table."""

from importlib.resources import files

import msgspec

from ...creatures.spawn import CreatureTypeId

# Cell-local byte coordinates, one per walking frame (atlas cells 0-31).
ZOMBIE_HEADS = msgspec.json.decode(
    files(__package__).joinpath("zombie_heat_heads.json").read_bytes(), type=tuple[tuple[int, int], ...],
)


def heat_head_color(type_id: CreatureTypeId, frame_index: int) -> tuple[int, int]:
    """Green/blue for heat_body.frag: a zombie walking frame's head, or zero for the fixed lobe."""
    if type_id == CreatureTypeId.ZOMBIE and frame_index < len(ZOMBIE_HEADS):
        return ZOMBIE_HEADS[frame_index]
    return (0, 0)
