"""Read-only audio review reproductions; backend substitutions never play audio.

Run from the repository root with `PYTHONPATH=. uv run --no-sync python <this-file>`.
The malformed OGG probe uses the installed raylib decoder without opening a device.
All generated assets and logs live in temporary directories.
"""

from __future__ import annotations

import json
from contextlib import ExitStack, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from crimson.effects import FxQueue
from crimson.game_modes import GameMode
from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.presentation_step import (
    DeterministicPresentationPlan,
    plan_hit_sfx,
    plan_world_presentation_step,
)
from crimson.world.audio_bridge import AudioBridge
from grim import audio, music, paq, sfx
from grim.config import default_crimson_cfg
from grim.console import ConsoleLog, ConsoleState
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from grim.sfx_map import SFX_SPECS, SfxId
from tests.support.helpers import ScriptedCrand


@contextmanager
def music_backend():
    playing = set()
    with ExitStack() as stack:
        calls = {}
        functions = {
            "set_music_volume": lambda *_: None,
            "play_music_stream": playing.add,
            "stop_music_stream": playing.discard,
            "update_music_stream": lambda *_: None,
            "is_music_stream_playing": lambda track: track in playing,
        }
        for name, implementation in functions.items():
            calls[name] = stack.enter_context(patch.object(rl, name, side_effect=implementation))
        yield playing, calls


def zero_volume():
    state = music.init_music_state(ready=True, enabled=True, volume=0.8)
    track = object()
    state.tracks["gt1_ingame"] = track
    state.queue.append("gt1_ingame")
    with music_backend() as (playing, calls):
        music.trigger_game_tune(state, rng=Crand(1))
        music.set_music_volume(state, 0.0)
        music.update_music(state, 1 / 60)
        music.set_music_volume(state, 0.8)
        for _ in range(120):
            music.update_music(state, 1 / 60)
        retrigger = music.trigger_game_tune(state, rng=Crand(1))
        result = {
            "active_track": state.active_track,
            "game_tune_started": state.game_tune_started,
            "playback_count_after_restore": len(state.playbacks),
            "backend_playing_after_restore": track in playing,
            "play_calls_including_initial_start": calls["play_music_stream"].call_count,
            "retrigger_result": retrigger,
        }
    assert not result["backend_playing_after_restore"]
    assert result["game_tune_started"] and result["playback_count_after_restore"] == 0
    return result


def sound_planning():
    def hit(x):
        return ProjectileHit(
            type_id=ProjectileTemplateId.PISTOL,
            origin=Vec2(),
            hit=Vec2(x, 100),
            target=Vec2(x, 100),
        )

    def hit_plan(hits, *, demo=False):
        rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
        trigger, ids = plan_hit_sfx(
            hits,
            game_mode=GameMode.RUSH,
            demo_mode_active=demo,
            game_tune_started=True,
            rng=rng,
        )
        return DeterministicPresentationPlan(trigger_game_tune=trigger, sfx=tuple(ids)), rng.calls

    state = audio.AudioState(
        ready=True,
        music=music.init_music_state(ready=False, enabled=False, volume=1.0),
        sfx=sfx.init_sfx_state(ready=True, enabled=True, volume=1.0),
    )
    state.sfx.samples[SfxId.BULLET_HIT_01] = sfx.SfxSample(
        entry_name="bullet_hit_01.ogg",
        source=object(),
        aliases=[object() for _ in range(3)],
    )
    bridge = AudioBridge(audio=state, audio_rng=Crand(1))
    duplicate_plan, rng_calls = hit_plan([hit(256)] * 6)
    with (
        patch.object(rl, "is_sound_playing", return_value=False),
        patch.object(rl, "set_sound_pitch"),
        patch.object(rl, "play_sound") as play,
        patch.object(rl, "set_sound_pan") as pan,
    ):
        bridge.apply_plan(plan=duplicate_plan)
        starts = play.call_count
        pan_calls = pan.call_count

    event_ids = [
        SfxId.ZOMBIE_DIE_01,
        SfxId.ALIEN_DIE_01,
        SfxId.LIZARD_DIE_01,
        SfxId.SPIDER_DIE_01,
        SfxId.TROOPER_DIE_01,
    ]
    planned = plan_world_presentation_step(
        state=GameplayState(),
        players=[],
        fx_queue=FxQueue(),
        hits=[],
        pickups=[],
        event_sfx=event_ids,
        prev_audio=[],
        prev_perk_pending=0,
        game_mode=GameMode.RUSH,
        demo_mode_active=False,
        perk_progression_enabled=False,
        rng=Crand(1),
        detail_preset=5,
        violence_disabled=0,
        game_tune_started=True,
    )
    left, _ = hit_plan([hit(256)])
    right, _ = hit_plan([hit(768)])
    demo, _ = hit_plan([hit(256)], demo=True)
    result = {
        "six_same_tick_hits": {"rng_calls": rng_calls, "backend_starts": starts, "native_starts": 1},
        "five_distinct_event_ids": {
            "input": [value.value for value in event_ids],
            "output": [value.value for value in planned.sfx],
        },
        "left_right_plans_identical": left == right,
        "demo_and_normal_plans_identical": left == demo,
        "backend_pan_calls": pan_calls,
        "native_pan_at_width_1024_camera_x_0": {"x_256": -425, "x_768": 425},
    }
    assert starts == 6 and rng_calls == 6
    assert len(planned.sfx) == 4 and SfxId.TROOPER_DIE_01 not in planned.sfx
    assert left == right == demo
    return result


def invalid_music():
    # Real decoding, no backend mocks and no InitAudioDevice call. Invalid data
    # fails before an audio buffer is needed; this does not exercise valid playback.
    with TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "corrupt.ogg").write_bytes(b"OggS")
        console = ConsoleState(base_dir=root, log=ConsoleLog(base_dir=root))
        state = music.init_music_state(ready=True, enabled=True, volume=0.5)
        loaded = music.load_music_track(state, root, "corrupt.ogg", console=console)
        stream = state.tracks["corrupt"]
        music.queue_track(state, "corrupt")
        triggered = music.trigger_game_tune(state, rng=Crand(1))
        music.update_music(state, 1 / 60)
        result = {
            "load_result": loaded,
            "raylib_is_music_valid": rl.is_music_valid(stream),
            "null_audio_buffer": stream.stream.buffer == rl.ffi.NULL,
            "console_messages": list(console.log.lines),
            "trigger_result": triggered,
            "game_tune_started": state.game_tune_started,
            "backend_playing": rl.is_music_stream_playing(stream),
        }
        music.shutdown_music(state)
    assert loaded == ("corrupt", 0) and not result["raylib_is_music_valid"]
    assert result["game_tune_started"] and not result["backend_playing"]
    return result


def failed_audio_initialization():
    # Exercise real init_audio_state and both archive loaders. Only native handle
    # allocation is substituted. The second music entry is genuinely absent.
    with TemporaryDirectory() as temp, ExitStack() as stack:
        root = Path(temp)
        entries = sorted({spec.entry_name for spec in SFX_SPECS.values()})
        paq.write_paq(root / sfx.SFX_PAK_NAME, [(name, b"fake PCM") for name in entries])
        paq.write_paq(root / music.MUSIC_PAK_NAME, [("music/intro.ogg", b"fake Vorbis")])
        console = ConsoleState(base_dir=root, log=ConsoleLog(base_dir=root))
        config = default_crimson_cfg()
        calls = {}
        for name in (
            "init_audio_device",
            "close_audio_device",
            "unload_wave",
            "unload_sound",
            "unload_sound_alias",
            "unload_music_stream",
            "set_sound_volume",
            "set_music_volume",
        ):
            calls[name] = stack.enter_context(patch.object(rl, name))
        stack.enter_context(patch.object(rl, "is_audio_device_ready", side_effect=[False, True]))
        for name in (
            "load_wave_from_memory",
            "load_sound_from_wave",
            "load_sound_alias",
            "load_music_stream_from_memory",
        ):
            calls[name] = stack.enter_context(patch.object(rl, name, side_effect=lambda *_: object()))
        try:
            audio.init_audio_state(config, root, console)
        except FileNotFoundError as exc:
            failure = str(exc)
        else:
            raise AssertionError("missing shortie_monk entry must fail")
        result = {
            "exception": failure,
            "device_initializations": calls["init_audio_device"].call_count,
            "device_closes": calls["close_audio_device"].call_count,
            "sound_sources_created": calls["load_sound_from_wave"].call_count,
            "sound_sources_unloaded": calls["unload_sound"].call_count,
            "aliases_created": calls["load_sound_alias"].call_count,
            "aliases_unloaded": calls["unload_sound_alias"].call_count,
            "music_streams_created": calls["load_music_stream_from_memory"].call_count,
            "music_streams_unloaded": calls["unload_music_stream"].call_count,
        }
    assert result["sound_sources_created"] > 0 and result["music_streams_created"] == 1
    assert result["sound_sources_unloaded"] == result["music_streams_unloaded"] == result["device_closes"] == 0
    return result


def failed_voice_acquisition():
    state = sfx.init_sfx_state(ready=True, enabled=True, volume=1.0)
    with (
        patch.object(rl, "load_wave_from_memory", return_value=object()),
        patch.object(rl, "load_sound_from_wave", return_value=object()),
        patch.object(rl, "unload_wave"),
        patch.object(rl, "load_sound_alias", side_effect=[object(), RuntimeError("second alias failed")]),
        patch.object(rl, "unload_sound") as unload_source,
        patch.object(rl, "unload_sound_alias") as unload_alias,
    ):
        try:
            sfx._load_sample_from_data(state, entry_name="pistol_fire.ogg", data=b"fake PCM")
        except RuntimeError as exc:
            failure = str(exc)
        else:
            raise AssertionError("injected alias allocation failure must escape")
        result = {
            "exception": failure,
            "source_unloads": unload_source.call_count,
            "alias_unloads": unload_alias.call_count,
            "published_samples": len(state.samples),
        }
    assert result["source_unloads"] == result["alias_unloads"] == result["published_samples"] == 0
    return result


if __name__ == "__main__":
    results = {
        "zero_volume": zero_volume(),
        "sound_planning": sound_planning(),
        "invalid_music": invalid_music(),
        "failed_audio_initialization": failed_audio_initialization(),
        "failed_voice_acquisition": failed_voice_acquisition(),
    }
    output = Path(__file__).with_name("probe-results.json")
    output.write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))
