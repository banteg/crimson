from __future__ import annotations

from collections.abc import Sequence

from .input import PlayerInput


def normalize_input_frame(inputs: Sequence[PlayerInput] | None, *, player_count: int) -> tuple[PlayerInput, ...]:
    """Pad or truncate slot-ordered input at the world boundary.

    PlayerInput is immutable; its values need no reconstruction or coercion.
    Wire validation and legacy control inference belong to their source adapters.
    """
    count = max(0, player_count)
    supplied = () if inputs is None else tuple(inputs[:count])
    return supplied + (PlayerInput(),) * (count - len(supplied))
