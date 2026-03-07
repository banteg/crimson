from __future__ import annotations

import pytest

from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import TypoCharCommand, TypoSubmitCommand
from crimson.sim.sessions import DeterministicSession
from crimson.typo.runtime import apply_typo_command, typo_input_transform
from crimson.typo.state import reset_typo_state
from crimson.typo.typing import TYPING_MAX_CHARS, TypingBuffer
from grim.geom import Vec2


def test_typing_buffer_backspace_and_max_len() -> None:
    buf = TypingBuffer()
    buf.backspace()
    assert buf.text == ""

    for _ in range(TYPING_MAX_CHARS + 10):
        buf.push_char("a")
    assert buf.text == "a" * TYPING_MAX_CHARS

    buf.backspace()
    assert buf.text == "a" * (TYPING_MAX_CHARS - 1)


def test_typing_buffer_submit_noop_on_empty() -> None:
    buf = TypingBuffer()
    result = buf.submit(matched=False)
    assert result is None
    assert buf.submit_count == 0
    assert buf.match_count == 0


def test_typing_buffer_submit_counts_match_and_clears_text() -> None:
    buf = TypingBuffer(text="alpha")
    result = buf.submit(matched=True)
    assert result == "alpha"
    assert buf.text == ""
    assert buf.submit_count == 1
    assert buf.match_count == 1


def test_typing_buffer_submit_counts_reload_as_submit_only() -> None:
    buf = TypingBuffer(text="reload")
    result = buf.submit(matched=False)
    assert result == "reload"
    assert buf.text == ""
    assert buf.submit_count == 1
    assert buf.match_count == 0


def test_typo_commands_apply_before_input_transform(make_world_state) -> None:
    world = make_world_state()
    reset_typo_state(
        world.state.typo,
        creature_capacity=len(world.creatures.entries),
    )
    seen_typing_text: list[str] = []

    class _StopAfterTransform(RuntimeError):
        pass

    def _transform(inputs: list[PlayerInput]) -> list[PlayerInput]:
        seen_typing_text.append(str(world.state.typo.typing.text))
        raise _StopAfterTransform

    session = DeterministicSession(
        world=world,
        world_size=1024.0,
        damage_scale_by_type={},
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.TYPO,
        perk_progression_enabled=False,
        input_transform=_transform,
    )

    with pytest.raises(_StopAfterTransform):
        session.step_tick(
            timing=session.timing_for_dt(1.0 / 60.0),
            inputs=[PlayerInput()],
            commands=[TypoCharCommand(player_index=0, ch="a")],
        )

    assert seen_typing_text == ["a"]


def test_typo_submit_match_overrides_only_one_tick(make_world_state) -> None:
    world = make_world_state()
    reset_typo_state(
        world.state.typo,
        creature_capacity=len(world.creatures.entries),
    )
    creature = world.creatures.entries[7]
    creature.active = True
    creature.pos = Vec2(321.0, 654.0)
    world.state.typo.names.names[7] = "alpha"
    world.state.typo.typing.text = "alpha"

    apply_typo_command(world, TypoSubmitCommand(player_index=0))

    baseline = [PlayerInput(aim=Vec2(10.0, 20.0))]
    transformed0 = typo_input_transform(world, baseline)
    transformed1 = typo_input_transform(world, baseline)

    assert transformed0[0].aim == Vec2(321.0, 654.0)
    assert transformed0[0].fire_down is True
    assert transformed0[0].fire_pressed is True
    assert transformed1[0].aim == Vec2(10.0, 20.0)
    assert transformed1[0].fire_down is False
    assert transformed1[0].fire_pressed is False
