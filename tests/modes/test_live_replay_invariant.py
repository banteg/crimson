"""Live play must simulate exactly what its replay records.

The live loop runs real controller interpretation (stick math produces f64 aim
points), ragged frame times (zero to six ticks per frame), press edges between
ticks and perk commands. Verification of the saved replay must then reproduce
the complete session state the live run had.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from crimson import local_input
from crimson.game_modes import GameMode
from crimson.gamepad_profile import apply_pad_profile
from crimson.input_codes import PadCode
from crimson.math_parity import f32
from crimson.modes.survival_mode import SurvivalMode
from crimson.replay import load_replay
from crimson.replay.driver.playback_driver import PlaybackWalkObserver, build_verify_playback_driver
from crimson_re.dbg.state_digest import session_digest
from grim.geom import Vec2
from grim.rand import Crand
from grim.view import ViewContext

# Frame times in seconds: high refresh rates, a 0.1 s lag spike (six ticks) and odd rates.
_FRAME_DTS = (1 / 144, 1 / 144, 1 / 120, 0.1, 1 / 60, 0.033, 1 / 240, 0.05, 1 / 75)
_TICKS = 3600
# Complete-state digests are costly; a split never heals, so sampling still finds it.
_DIGEST_EVERY = 8


def _axis(value: float) -> float:
    # raylib reports f32 axes; the interpreter's normalisation then yields f64 aim points.
    return float(f32(max(-1.0, min(1.0, value))))


@pytest.mark.usefixtures("headless_resources")
def test_live_run_replays_to_identical_session_state(mocker, make_mode_config, assets_dir: Path, tmp_path: Path) -> None:
    config = make_mode_config(game_mode=GameMode.SURVIVAL)
    apply_pad_profile(config.controls, 0)
    mode = SurvivalMode(ViewContext(assets_dir=assets_dir), config=config, audio_rng=Crand(1))
    mode.open()

    frame = [0]

    def axis_value(code: int, player_index: int = 0) -> float:
        # Circle-strafe on the left stick; right stick tracks the nearest creature with a wobble.
        t = frame[0] * 0.021
        match int(code):
            case PadCode.LEFT_STICK_X:
                return _axis(math.cos(t) * 0.8)
            case PadCode.LEFT_STICK_Y:
                return _axis(math.sin(t) * 0.8)
        player = mode.player
        living = [c for c in mode.creatures.entries if c.active and c.hp > 0.0]
        target = min(living, key=lambda c: (c.pos - player.pos).length_sq(), default=None)
        direction = (target.pos - player.pos).normalized() if target is not None else Vec2(1.0, 0.0)
        wobble = math.sin(frame[0] * 0.3) * 0.07
        match int(code):
            case PadCode.RIGHT_STICK_X:
                return _axis((direction.x - direction.y * wobble) * 0.95)
            case PadCode.RIGHT_STICK_Y:
                return _axis((direction.y + direction.x * wobble) * 0.95)
        return 0.0

    mocker.patch.object(local_input, "input_axis_value", side_effect=axis_value)
    fire = int(PadCode.R2)
    reload = int(PadCode.L1)
    mocker.patch.object(
        local_input,
        "input_code_is_down",
        side_effect=lambda code, player_index=0: int(code) == fire and frame[0] % 2 == 0,
    )
    mocker.patch.object(
        local_input,
        "input_code_is_pressed",
        side_effect=lambda code, player_index=0: (int(code) == fire and frame[0] % 2 == 0)
        or (int(code) == reload and frame[0] % 97 == 0),
    )

    session = mode._sim_session
    assert session is not None
    live_digests: list[str] = []
    live_ticks = [0]
    on_tick_applied = mode._on_tick_applied

    def record_digest(tick):
        if live_ticks[0] % _DIGEST_EVERY == 0:
            live_digests.append(session_digest(session))
        live_ticks[0] += 1
        return on_tick_applied(tick)

    mocker.patch.object(mode, "_on_tick_applied", side_effect=record_digest)

    while mode._replay_recorder is not None and live_ticks[0] < _TICKS and not mode._game_over_active:
        if mode.state.perk_selection.pending_count > 0 and not mode._perk_menu.active and frame[0] % 3 == 0:
            mode._request_perk_menu()
            mode.record_perk_pick_command(frame[0] // 3 % 3)
            mode._perk_menu.close()
        mode._run_deterministic_session_ticks(
            dt_frame=_FRAME_DTS[frame[0] % len(_FRAME_DTS)],
            session=session,
            recorder=mode._replay_recorder,
        )
        frame[0] += 1
    if mode._replay_recorder is not None:
        mode._save_replay()

    [path] = sorted((tmp_path / "replays").glob("*.crd"))
    replay = load_replay(path.read_bytes())
    assert len(replay.ticks) == live_ticks[0] > 1000
    assert any(command for tick in replay.ticks for command in tick.commands)

    driver = build_verify_playback_driver(replay, warn_on_version_mismatch=False)
    replayed_digests: list[str] = []

    class Digests(PlaybackWalkObserver):
        def after_tick(self, tick_result, world) -> None:
            if len(replayed_digests) * _DIGEST_EVERY == int(tick_result.tick_index):
                replayed_digests.append(session_digest(driver.session))

    assert driver.run(observer=Digests()) == replay.result
    first_split = next((i for i, (a, b) in enumerate(zip(live_digests, replayed_digests, strict=True)) if a != b), None)
    assert first_split is None, f"live and replay state split by tick {first_split * _DIGEST_EVERY}"
