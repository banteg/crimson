from __future__ import annotations

"""Deterministic per-tick player input frame normalization."""

from collections.abc import Sequence

import msgspec

from .input import PlayerInput


class InputFrame(msgspec.Struct, frozen=True):
    players: tuple[PlayerInput, ...]

    def as_list(self) -> list[PlayerInput]:
        return list(self.players)


def normalize_input_frame(inputs: Sequence[PlayerInput] | None, *, player_count: int) -> InputFrame:
    """Return a fixed-size, player-index-ordered input frame."""
    count = max(0, int(player_count))
    frame = [PlayerInput() for _ in range(count)]
    if inputs is not None:
        limit = min(len(inputs), count)
        for idx in range(limit):
            inp = inputs[idx]
            frame[idx] = PlayerInput(
                move=inp.move,
                aim=inp.aim,
                move_mode=inp.move_mode,
                aim_scheme=inp.aim_scheme,
                fire_down=inp.fire_down,
                fire_pressed=inp.fire_pressed,
                reload_pressed=inp.reload_pressed,
                reload_down=inp.reload_down,
                move_to_cursor_pressed=inp.move_to_cursor_pressed,
                move_forward_pressed=inp.move_forward_pressed,
                move_backward_pressed=inp.move_backward_pressed,
                turn_left_pressed=inp.turn_left_pressed,
                turn_right_pressed=inp.turn_right_pressed,
            )
    return InputFrame(players=tuple(frame))
