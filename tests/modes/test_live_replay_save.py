from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.modes import base_gameplay_mode, rush_mode, survival_mode
from crimson.modes.base_gameplay_mode import BaseGameplayMode
from crimson.modes.rush_mode import RushMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.perks import PerkId
from crimson.replay import load_replay
from crimson.replay.driver.playback_driver import build_verify_playback_driver
from crimson.screens.results.game_over import GameOverUi
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import PerkPickCommand
from crimson.sim.run_result import RunOutcome
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext
from tests.support.replay_runner_helpers import unverified_replay


def _open_mode[ModeT: BaseGameplayMode](
    mode_cls: Callable[..., ModeT],
    game_mode: GameMode,
    *,
    mocker,
    make_mode_config,
    assets_dir: Path,
    replay_checkpoints: bool = False,
) -> ModeT:
    mode = mode_cls(
        ViewContext(assets_dir=assets_dir, replay_checkpoints=replay_checkpoints),
        config=make_mode_config(game_mode=game_mode),
        audio_rng=Crand(1),
    )
    mocker.patch.object(mode, "apply_terrain_setup")
    mocker.patch.object(mode.world_runtime, "open_runtime")
    mocker.patch.object(base_gameplay_mode, "load_small_font", return_value=None)
    mode.open()
    mocker.patch.object(mode, "_sync_audio_and_ground")
    mocker.patch.object(mode, "_build_local_inputs", return_value=[PlayerInput(aim=Vec2(600.0, 512.0))])
    mocker.patch.object(base_gameplay_mode, "apply_presentation_outputs")
    return mode


def _run_ticks(mode: BaseGameplayMode, *, ticks: int) -> None:
    session = mode._sim_session
    assert session is not None
    mode._run_deterministic_session_ticks(dt_frame=ticks / 60, session=session, recorder=mode._replay_recorder)


def _saved_files(base_dir: Path) -> list[Path]:
    replays_dir = base_dir / "replays"
    return sorted(replays_dir.iterdir()) if replays_dir.is_dir() else []


def test_game_over_replay_result_is_taken_before_the_highscore_rng_draw(
    mocker,
    make_mode_config,
    assets_dir,
    tmp_path,
) -> None:
    mode = _open_mode(RushMode, GameMode.RUSH, mocker=mocker, make_mode_config=make_mode_config, assets_dir=assets_dir)
    mocker.patch.object(GameOverUi, "open")
    rng_before_record: list[int] = []
    build_record = rush_mode.build_highscore_record_for_game_over

    def _record_rng_then_build(**kwargs):
        rng_before_record.append(int(mode.state.rng.state))
        return build_record(**kwargs)

    mocker.patch.object(rush_mode, "build_highscore_record_for_game_over", side_effect=_record_rng_then_build)
    mode.player.health = 1.0
    attacker = mode.creatures.entries[0]
    attacker.active = True
    attacker.hp = 100.0
    attacker.size = 50.0
    attacker.pos = mode.player.pos
    attacker.contact_damage = 100.0

    _run_ticks(mode, ticks=3)

    assert mode._game_over_active
    assert mode._tick_runner_next_tick_index == 1
    [replay_path] = _saved_files(tmp_path)
    replay = load_replay(replay_path.read_bytes())
    assert len(replay.ticks) == 1
    assert replay.result.outcome == RunOutcome.DEATH
    assert replay.result.rng_state == rng_before_record[0]
    assert int(mode.state.rng.state) != rng_before_record[0]


@pytest.mark.parametrize("replay_checkpoints", [False, True])
def test_saved_live_replay_round_trips_and_verifies(
    mocker,
    make_mode_config,
    assets_dir,
    tmp_path,
    replay_checkpoints,
) -> None:
    mode = _open_mode(
        SurvivalMode,
        GameMode.SURVIVAL,
        mocker=mocker,
        make_mode_config=make_mode_config,
        assets_dir=assets_dir,
        replay_checkpoints=replay_checkpoints,
    )
    _run_ticks(mode, ticks=5)

    mode._save_replay()

    saved = _saved_files(tmp_path)
    assert [path.suffix for path in saved] == ([".crd", ".chk"] if replay_checkpoints else [".crd"])
    replay = load_replay(saved[0].read_bytes())
    assert len(replay.ticks) == 5
    assert replay.result.outcome == RunOutcome.INCOMPLETE
    assert build_verify_playback_driver(replay).run() == replay.result


def test_run_left_before_first_tick_saves_no_replay(mocker, make_mode_config, assets_dir, tmp_path) -> None:
    mode = _open_mode(
        SurvivalMode,
        GameMode.SURVIVAL,
        mocker=mocker,
        make_mode_config=make_mode_config,
        assets_dir=assets_dir,
    )

    mode._save_replay()

    assert _saved_files(tmp_path) == []
    assert mode._replay_recorder is None


def test_debug_cheat_stops_recording(mocker, make_mode_config, assets_dir, tmp_path) -> None:
    mode = _open_mode(
        SurvivalMode,
        GameMode.SURVIVAL,
        mocker=mocker,
        make_mode_config=make_mode_config,
        assets_dir=assets_dir,
    )
    _run_ticks(mode, ticks=2)
    mocker.patch.object(survival_mode, "debug_enabled", return_value=True)
    mocker.patch.object(survival_mode.rl, "is_key_pressed", side_effect=lambda key: key == rl.KeyboardKey.KEY_F2)

    mode._handle_input()

    assert mode.state.debug_god_mode
    assert mode._replay_recorder is None
    _run_ticks(mode, ticks=2)
    mode._save_replay()
    assert _saved_files(tmp_path) == []


def test_perk_prompt_stays_closed_while_a_pick_is_queued(mocker, make_mode_config, assets_dir) -> None:
    mode = _open_mode(
        SurvivalMode,
        GameMode.SURVIVAL,
        mocker=mocker,
        make_mode_config=make_mode_config,
        assets_dir=assets_dir,
    )
    selection = mode.state.perk_selection
    selection.pending_count = 1
    selection.choices_dirty = False
    selection.choices = [PerkId.BANDAGE] * 7
    assert mode._ui_pending_perk_count() == 1

    mode.record_perk_pick_command(0)
    assert mode._ui_pending_perk_count() == 0

    session = mode._sim_session
    assert session is not None
    # A frame that runs no tick moves the pick into the tick provider's queue.
    mode._run_deterministic_session_ticks(dt_frame=1 / 240, session=session, recorder=mode._replay_recorder)
    assert selection.pending_count == 1
    assert mode._ui_pending_perk_count() == 0

    _run_ticks(mode, ticks=1)

    assert selection.pending_count == 0
    recorder = mode._replay_recorder
    assert recorder is not None
    assert unverified_replay(recorder).ticks[0].commands == [PerkPickCommand(player_index=0, choice_index=0)]
    # With the pick applied, the prompt follows the pending count again.
    selection.pending_count = 1
    assert mode._ui_pending_perk_count() == 1
