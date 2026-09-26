from __future__ import annotations

import msgspec
import pytest

from crimson.aim_schemes import AimScheme
from crimson.math_parity import f32
from crimson.movement_controls import MovementControlType
from crimson.replay.input_codec import unpack_tick_inputs
from crimson.replay.ticks import LiveTickSource
from crimson.sim.commands import PerkMenuOpenCommand
from crimson.sim.input import PlayerInput
from grim.geom import Vec2


def _next_inputs(source: LiveTickSource) -> list[PlayerInput]:
    return unpack_tick_inputs(source.next_tick().inputs)


def test_ticks_carry_input_exactly_as_stored() -> None:
    # Stick and mouse aim math produces f64 points; the tick holds their f32 form.
    source = LiveTickSource()
    source.poll([PlayerInput(move=Vec2(0.3, -0.7), aim=Vec2(600.1, 512.3))])
    [inp] = _next_inputs(source)
    assert inp.move == Vec2(float(f32(0.3)), float(f32(-0.7)))
    assert inp.aim == Vec2(float(f32(600.1)), float(f32(512.3)))


def test_a_press_fires_once_even_when_released_before_the_tick() -> None:
    source = LiveTickSource()
    source.poll([PlayerInput(fire_pressed=True)])
    first, second = _next_inputs(source), _next_inputs(source)
    assert (first[0].fire_down, first[0].fire_pressed) == (True, True)
    assert (second[0].fire_down, second[0].fire_pressed) == (False, False)


@pytest.mark.parametrize("move_mode", list(MovementControlType))
@pytest.mark.parametrize("aim_scheme", list(AimScheme))
def test_catch_up_ticks_keep_control_modes_and_held_buttons(
    move_mode: MovementControlType,
    aim_scheme: AimScheme,
) -> None:
    held = PlayerInput(
        move_mode=move_mode,
        aim_scheme=aim_scheme,
        fire_down=True,
        fire_pressed=True,
        reload_down=True,
        reload_pressed=True,
        move_forward_pressed=True,
        move_backward_pressed=False,
        turn_left_pressed=True,
        turn_right_pressed=False,
    )
    source = LiveTickSource()
    source.poll([held])
    assert _next_inputs(source) == [held]
    assert _next_inputs(source) == [msgspec.structs.replace(held, fire_pressed=False, reload_pressed=False)]


@pytest.mark.parametrize("zero_tick_frames", [1, 3, 10])
def test_presses_wait_for_a_tick_and_use_the_latest_held_state(zero_tick_frames: int) -> None:
    source = LiveTickSource()
    source.submit(PerkMenuOpenCommand(player_index=0))
    source.poll([PlayerInput(fire_pressed=True, fire_down=True)])
    for _ in range(zero_tick_frames):
        source.poll([PlayerInput(reload_pressed=True, aim=Vec2(123, 456))])
    first = source.next_tick()
    second = source.next_tick()
    assert unpack_tick_inputs(first.inputs) == [
        PlayerInput(fire_down=True, fire_pressed=True, reload_pressed=True, aim=Vec2(123, 456)),
    ]
    assert first.commands == [PerkMenuOpenCommand(player_index=0)]
    assert unpack_tick_inputs(second.inputs) == [PlayerInput(aim=Vec2(123, 456))]
    assert second.commands == []
    assert source.queued_commands == ()


def test_pause_discards_presses_but_keeps_commands_and_held_controls() -> None:
    source = LiveTickSource()
    command = PerkMenuOpenCommand(player_index=0)
    source.submit(command)
    source.poll(
        [PlayerInput(fire_pressed=True, fire_down=True, reload_pressed=True, reload_down=True, fire_bullets_key_down=True)],
    )
    source.clear_edges()
    tick = source.next_tick()
    assert unpack_tick_inputs(tick.inputs) == [PlayerInput(fire_down=True, reload_down=True, fire_bullets_key_down=True)]
    assert tick.commands == [command]
