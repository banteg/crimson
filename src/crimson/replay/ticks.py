"""The single way a session advances through recorded play.

Live play and verification both step `ReplayTick`s. Live input is packed into
the tick the replay records before the simulation sees it, so no precision or
field that the file cannot hold ever reaches the session.
"""

from __future__ import annotations

from collections.abc import Sequence

import msgspec

from grim.sfx_map import SfxId

from ..sim.commands import GameCommand
from ..sim.input import PlayerInput
from ..sim.sessions import DeterministicSession, DeterministicSessionTick
from .input_codec import pack_tick, unpack_tick_inputs
from .types import REPLAY_TICK_DT, ReplayTick


def step_replay_tick(
    session: DeterministicSession,
    tick: ReplayTick,
    *,
    prelude_post_apply_sfx: list[SfxId] | None = None,
) -> DeterministicSessionTick:
    return session.step_tick(
        dt=REPLAY_TICK_DT,
        inputs=unpack_tick_inputs(tick.inputs),
        commands=tick.commands,
        prelude_post_apply_sfx=prelude_post_apply_sfx,
    )


class LiveTickSource:
    """Turns polled local input and queued commands into replay ticks.

    Input is polled once per rendered frame, which can run zero or several
    ticks. Held controls and aim follow the latest poll; a press edge waits for
    the next tick even across frames that run none, then fires once.
    """

    def __init__(self) -> None:
        self._inputs: list[PlayerInput] = []
        self._commands: list[GameCommand] = []

    def poll(self, inputs: Sequence[PlayerInput]) -> None:
        previous = self._inputs
        self._inputs = [
            msgspec.structs.replace(
                inp,
                fire_pressed=inp.fire_pressed or (index < len(previous) and previous[index].fire_pressed),
                reload_pressed=inp.reload_pressed or (index < len(previous) and previous[index].reload_pressed),
            )
            for index, inp in enumerate(inputs)
        ]

    def submit(self, command: GameCommand) -> None:
        self._commands.append(command)

    @property
    def queued_commands(self) -> tuple[GameCommand, ...]:
        return tuple(self._commands)

    def clear_edges(self) -> None:
        """Drop undelivered presses (pausing); held controls and commands stay."""

        self._inputs = [msgspec.structs.replace(inp, fire_pressed=False, reload_pressed=False) for inp in self._inputs]

    def next_tick(self) -> ReplayTick:
        # A press fires for one tick even if released before a tick ran (the
        # mouse wheel has no held state); catch-up ticks in the same frame keep
        # the held state without repeating the pulse.
        tick = pack_tick(
            [
                msgspec.structs.replace(inp, fire_down=True) if inp.fire_pressed and not inp.fire_down else inp
                for inp in self._inputs
            ],
            self._commands,
        )
        self._commands = []
        self.clear_edges()
        return tick
