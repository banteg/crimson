from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from crimson import audio_router
from crimson.camera import camera_shake_update
from crimson.dbg.checkpoint_diff import compare_checkpoints
from crimson.game_modes import GameMode
from crimson.math_parity import f32
from crimson.modes import base_gameplay_mode
from crimson.modes.tutorial_mode import TutorialMode
from crimson.perks import PerkId
from crimson.persistence.highscores import HighScoreRecord, read_highscore_records, write_highscore_records
from crimson.replay import ReplayHeader, ReplayRecorder
from crimson.replay.checkpoints import build_checkpoint
from crimson.replay.driver.playback_driver import PlaybackDriver
from crimson.sim.batch_apply import PresentationTickOutput, apply_presentation_outputs
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import PerkPickCommand
from crimson.sim.sessions import DeterministicSession
from crimson.world.runtime import WorldRuntime
from grim.audio import AudioState
from grim.config import default_crimson_cfg
from grim.geom import Vec2
from grim.music import init_music_state
from grim.rand import Crand, RecordingCrand
from grim.sfx import init_sfx_state


def tutorial_startup():
    from grim.view import ViewContext

    cfg = default_crimson_cfg(Path("/private/tmp/crimson-system-review.cfg"))
    cfg.gameplay.mode = GameMode.TUTORIAL
    mode = TutorialMode(ViewContext(assets_dir=Path("/private/tmp/assets")), config=cfg, audio_rng=Crand(0xBEEF))
    with (
        patch.object(base_gameplay_mode, "load_small_font", return_value=None),
        patch.object(mode.world_runtime, "open_runtime"),
        patch.object(mode, "apply_terrain_setup"),
    ):
        mode.open()
    live = mode._sim_session
    recorder = mode._replay_recorder
    assert live is not None and recorder is not None
    inp = PlayerInput(aim=Vec2(600, 512), fire_down=True, fire_pressed=True)
    recorder.record_tick([inp], dt=1 / 60)
    replay = PlaybackDriver(recorder.finish(), version_mismatch_action=None)

    def weapon(world):
        p = world.players[0]
        return {
            "ammo": p.weapon.ammo, "clip_size": p.weapon.clip_size, "cooldown": p.weapon.shot_cooldown, "shot_seq": p.shot_seq,
        }

    before = {"live": weapon(live.world), "replay": weapon(replay.world)}
    a = live.step_tick(dt=1 / 60, inputs=(inp,))
    b = replay.step_tick(0)
    return {
        "before": before,
        "after": {"live": weapon(live.world), "replay": weapon(replay.world)},
        "rng": {"live": live.world.state.rng.state, "replay": replay.world.state.rng.state},
        "sfx": {"live": [str(v) for v in a.presentation.sfx], "replay": [str(v) for v in b.payload.presentation.sfx]},
    }


def audio_partition(batch: bool):
    audio = AudioState(
        ready=False,
        music=init_music_state(ready=False, enabled=True, volume=1.0),
        sfx=init_sfx_state(ready=False, enabled=True, volume=1.0),
    )
    runtime = WorldRuntime(assets_dir=Path("/private/tmp/assets"), audio_rng=Crand(1), audio=audio)
    world = runtime.sim_world.world_state
    world.state.bonuses.reflex_boost = f32(0.025)
    world.players[0].weapon.shot_cooldown = 0
    session = DeterministicSession(
        world=world,
        world_size=1024,
        damage_scale_by_type=runtime.sim_world.damage_scale_by_type,
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )
    outputs = []
    timers = []
    with patch.object(audio_router, "play_sfx") as play:
        for tick in range(2):
            step = session.step_tick(dt=1 / 60, inputs=(PlayerInput(aim=Vec2(600, 512), fire_down=tick == 0),))
            timers.append(world.state.bonuses.reflex_boost)
            output = PresentationTickOutput(tick_index=tick, dt_sim=step.dt_sim, presentation=step.presentation)
            if batch:
                outputs.append(output)
            else:
                apply_presentation_outputs(outputs=[output], runtime=runtime, apply_audio=True, update_camera=False)
        if batch:
            apply_presentation_outputs(outputs=outputs, runtime=runtime, apply_audio=True, update_camera=False)
        return {
            "timers": timers,
            "sound_timers": [call.kwargs["reflex_boost_timer"] for call in play.call_args_list],
            "rng": world.state.rng.state,
        }


def camera_latch():
    state = GameplayState(rng=RecordingCrand(Crand(0xBEEF)))
    state.time_scale_active = True
    state.bonuses.reflex_boost = 0
    state.camera_shake_timer = f32(0.01)
    state.camera_shake_pulses = 5
    camera_shake_update(state, f32(0.01))
    return {
        "time_scale_active": state.time_scale_active,
        "bonus_timer": state.bonuses.reflex_boost,
        "python_interval": state.camera_shake_timer,
        "recovered_native_interval": f32(0.06),
    }


def camera_latch_reachable():
    runtime = WorldRuntime(assets_dir=Path("/private/tmp/assets"), audio_rng=Crand(1))
    world = runtime.sim_world.world_state
    world.state.time_scale_active = True
    world.state.bonuses.reflex_boost = f32(0.01)
    world.state.camera_shake_timer = f32(0.06)
    world.state.camera_shake_pulses = 5
    session = DeterministicSession(
        world=world,
        world_size=1024,
        damage_scale_by_type=runtime.sim_world.damage_scale_by_type,
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )
    rows = []
    for tick in range(2):
        before = {
            "latch": world.state.time_scale_active,
            "bonus": world.state.bonuses.reflex_boost,
            "shake_timer": world.state.camera_shake_timer,
        }
        session.step_tick(dt=1 / 60, inputs=(PlayerInput(),))
        rows.append(
            {
                "tick": tick,
                "before": before,
                "shake_timer_after": world.state.camera_shake_timer,
                "pulses_after": world.state.camera_shake_pulses,
            },
        )
    return rows


def checkpoint_blind_spot():
    runtime = WorldRuntime(assets_dir=Path("/private/tmp/assets"), audio_rng=Crand(1))
    world = runtime.sim_world.world_state
    before = build_checkpoint(tick_index=0, world=world, elapsed_ms=0)
    world.players[0].weapon.shot_cooldown = 10.0
    world.state.camera_shake_timer = 0.06
    world.state.camera_shake_pulses = 20
    world.creatures.entries[0].hp = 17
    after = build_checkpoint(tick_index=0, world=world, elapsed_ms=0)
    return {
        "changed": ["shot_cooldown", "camera_shake_timer", "camera_shake_pulses", "inactive_creature_hp"],
        "checkpoints_equal": before == after,
        "verifier_ok": compare_checkpoints([before], [after]).ok,
    }


def interrupted_score_save():
    with tempfile.TemporaryDirectory(prefix="crimson-review-") as directory:
        path = Path(directory) / "scores.bin"
        record = HighScoreRecord.blank(rand_value=123)
        write_highscore_records(path, [record])
        before = len(read_highscore_records(path))
        size = path.stat().st_size
        # A serializer failure demonstrates that the previous valid file has
        # already been destroyed, even before the first write is attempted.
        with patch(
            "crimson.persistence.highscores.encode_record_payload", side_effect=ValueError("injected encoding failure"),
        ):
            try:
                write_highscore_records(path, [record])
            except ValueError:
                pass
        return {
            "records_before": before,
            "bytes_before": size,
            "records_after": len(read_highscore_records(path)),
            "bytes_after": path.stat().st_size,
        }


def perk_command_timing():
    recorder = ReplayRecorder(ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=0xBEEF))
    command = PerkPickCommand(player_index=0, choice_index=0)
    inp = PlayerInput(move=Vec2(1, 0), aim=Vec2(600, 512))
    recorder.record_tick((inp,), commands=(command,), dt=1 / 60)
    replay = recorder.finish()
    live = PlaybackDriver(replay, version_mismatch_action=None)
    playback = PlaybackDriver(replay, version_mismatch_action=None)
    for driver in (live, playback):
        selection = driver.world.state.perk_selection
        selection.pending_count = 1
        selection.choices_dirty = False
        selection.choices = [PerkId.REFLEX_BOOSTED] * 7
    live_tick = live.session.step_tick(dt=1 / 60, inputs=(inp,), commands=(command,))
    replay_tick = playback.step_tick(0).payload
    return {
        "live_dt_sim": live_tick.dt_sim,
        "replay_dt_sim": replay_tick.dt_sim,
        "live_x": live.world.players[0].pos.x,
        "replay_x": playback.world.players[0].pos.x,
        "live_elapsed_ms": live.session.elapsed_ms,
        "replay_elapsed_ms": playback.session.elapsed_ms,
    }


if __name__ == "__main__":
    payload = json.dumps(
        {
            "tutorial_startup": tutorial_startup(),
            "audio_serial": audio_partition(False),
            "audio_batch": audio_partition(True),
            "camera_latch": camera_latch(),
            "camera_latch_reachable": camera_latch_reachable(),
            "checkpoint_blind_spot": checkpoint_blind_spot(),
            "interrupted_score_save": interrupted_score_save(),
            "perk_command_timing": perk_command_timing(),
        },
        indent=2,
    )
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(payload + "\n")
    else:
        print(payload)
