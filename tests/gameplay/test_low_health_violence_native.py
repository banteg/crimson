from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from crimson.aim_schemes import AimScheme
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.gameplay import player_update
from crimson.math_parity import f32
from crimson.movement_controls import MovementControlType
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from grim.sfx_map import SfxId

_FIXTURE = Path(__file__).resolve().parents[2] / "crimson-zig/src/runtime/testdata/violence-disabled-low-health.json"


def _bits(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0]


def test_low_health_gore_gate_matches_native_effects_sound_timer_and_rng() -> None:
    fixture = json.loads(_FIXTURE.read_text())
    assert fixture["fpcw"] == 0x7F
    assert len(fixture["cases"]) == 192
    for case in fixture["cases"]:
        frame = case["input"]["frame"]
        expected = case["expected"]
        rng = RecordingCrand(Crand(frame["seed"]))
        state = GameplayState(rng=rng, preserve_bugs=True)
        player = PlayerState(
            index=frame["index"],
            pos=Vec2(frame["pos_x"], frame["pos_y"]),
            health=f32(frame["health"]),
            low_health_timer=f32(frame["low_health_timer"]),
            aim_heading=f32(frame["aim_heading"]),
        )
        player_update(
            player,
            PlayerInput(aim=Vec2(300.0, 400.0), aim_scheme=AimScheme.MOUSE, move_mode=MovementControlType.STATIC),
            frame["dt"], state, violence_disabled=frame["violence_disabled"],
        )
        assert _bits(player.low_health_timer) == expected["timer_bits"], case["input"]["name"]
        assert [record.value for record in rng.records_since()] == expected["rng_draws"], case["input"]["name"]
        assert rng.state == expected["rng_state"]
        effects = state.effects.iter_active()
        assert len(effects) == len(expected["effects"])
        for effect, native in zip(effects, expected["effects"], strict=True):
            template = tuple(native["template_bits"])
            assert effect.effect_id == native["effect_id"]
            assert [_bits(effect.pos.x), _bits(effect.pos.y)] == native["position_bits"]
            assert tuple(map(_bits, (effect.vel.x, effect.vel.y, effect.rotation))) == template[:3]
            # The helper preserves template.scale; it does not initialize it.
            assert tuple(map(_bits, (effect.half_width, effect.half_height, effect.age, effect.lifetime))) == template[4:8]
            assert effect.flags == template[8]
            assert tuple(map(_bits, (effect.color.r, effect.color.g, effect.color.b, effect.color.a))) == template[9:13]
            assert (_bits(effect.rotation_step), _bits(effect.scale_step)) == template[13:15]
        assert len(state.sfx_queue) == len(expected["sounds"])
        for sound, native in zip(state.sfx_queue, expected["sounds"], strict=True):
            assert sound.sfx_id == (SfxId.BLOODSPILL_01 if native["sample_offset"] == 0 else SfxId.BLOODSPILL_02)
            assert sound.position is not None
            assert [_bits(sound.position.x), _bits(sound.position.y)] == native["position_bits"]
            assert native["gain_bits"] == _bits(sound.gain)


@pytest.mark.parametrize("violence_disabled", [0, 1, 255])
def test_world_step_passes_gore_setting_to_low_health_players(violence_disabled) -> None:
    world = WorldState.build(world_size=1024.0, demo_mode_active=False, hardcore=False, quest_fail_retry_count=0)
    world.players = [
        PlayerState(index=index, pos=Vec2(400.0 + index * 100, 400.0), health=19.0, low_health_timer=0.0)
        for index in range(2)
    ]
    world.step(
        0.016,
        inputs=[PlayerInput(), PlayerInput()], world_size=1024.0,
        damage_scale_by_type={}, detail_preset=5, violence_disabled=violence_disabled,
        fx_queue=FxQueue(), fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL, perk_progression_enabled=False,
    )
    assert len(world.state.effects.iter_active()) == (0 if violence_disabled else 12)
    assert [player.low_health_timer for player in world.players] == [1.0, 1.0]
